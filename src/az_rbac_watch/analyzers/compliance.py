"""Analysis engine — drift detection (scan) and guardrail violations (audit).

Two analysis modes:
- Drift (scan)      : compare actual assignments to the desired state (baseline rules)
                      -> DRIFT finding for each undeclared assignment
- Violations (audit): evaluate guardrails (governance rules)
                      -> finding named after the rule for each match
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from az_rbac_watch.config.policy_model import PolicyModel, Rule, RuleMatch
from az_rbac_watch.scanner.rbac_scanner import (
    PrincipalType,
    RbacScanResult,
    ScannedRoleAssignment,
)

__all__ = [
    "DRIFT",
    "ORPHANED_ASSIGNMENT",
    "SEVERITY_ORDER",
    "ComplianceFinding",
    "ComplianceReport",
    "ComplianceSummary",
    "Severity",
    "_check_aggregation_rules",
    "_check_orphans",
    "check_compliance",
    "check_drift",
    "check_violations",
]

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────

DRIFT = "DRIFT"

# Backward-compatible aliases
OUT_OF_BASELINE = DRIFT
GOVERNANCE_VIOLATION = "GOVERNANCE_VIOLATION"
ORPHANED_ASSIGNMENT = "ORPHANED_ASSIGNMENT"


# ── Enums & Models ───────────────────────────────────────────


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class ComplianceFinding(BaseModel):
    """An anomaly detected by the analysis engine."""

    rule_id: str
    severity: Severity
    message: str
    assignment_id: str = ""
    scope: str = ""
    principal_id: str = ""
    principal_display_name: str = ""
    principal_type: str = ""
    role_name: str = ""
    details: dict[str, str] = Field(default_factory=dict)


class ComplianceSummary(BaseModel):
    """Statistical summary of the report."""

    total_assignments_checked: int = 0
    total_findings: int = 0
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    drift_count: int = 0
    violation_count: int = 0
    orphan_count: int = 0


class ComplianceReport(BaseModel):
    """Complete analysis report."""

    policy_version: str
    tenant_id: str
    scan_timestamp: datetime
    findings: list[ComplianceFinding] = Field(default_factory=list)
    summary: ComplianceSummary = ComplianceSummary()
    scan_errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


# ── Generic rules engine ──────────────────────────────────────


class _PrecomputedMatch:
    """Pre-computed lowered sets for a RuleMatch to avoid repeated allocations."""

    __slots__ = ("match", "principal_type_in_set", "role_in_set", "role_not_in_set", "rule")

    def __init__(self, rule: Rule) -> None:
        self.rule = rule
        self.match = rule.match
        m = rule.match
        self.role_in_set: frozenset[str] | None = frozenset(r.lower() for r in m.role_in) if m.role_in else None
        self.role_not_in_set: frozenset[str] | None = (
            frozenset(r.lower() for r in m.role_not_in) if m.role_not_in else None
        )
        self.principal_type_in_set: frozenset[str] | None = (
            frozenset(t.lower() for t in m.principal_type_in) if m.principal_type_in else None
        )


def _evaluate_match(match: RuleMatch, a: ScannedRoleAssignment, pc: _PrecomputedMatch | None = None) -> bool:
    """Evaluate all non-None conditions in a RuleMatch against an assignment.

    Returns True if ALL conditions are satisfied (AND logic).
    An empty match (all None) matches everything.
    When pc is provided, uses pre-computed sets for role_in/role_not_in/principal_type_in.
    """
    role_lower = a.role_name.lower() if a.role_name else ""
    scope_lower = a.scope.lower().rstrip("/")
    principal_type_lower = str(a.principal_type).lower() if a.principal_type else ""
    role_type_lower = str(a.role_type).lower() if a.role_type else ""

    if match.scope is not None and scope_lower != match.scope.lower().rstrip("/"):
        return False

    if match.scope_prefix is not None:
        prefix = match.scope_prefix.lower().rstrip("/")
        if scope_lower != prefix and not scope_lower.startswith(prefix + "/"):
            return False

    if match.role is not None and role_lower != match.role.lower():
        return False

    if match.role_in is not None:
        role_in_set = pc.role_in_set if pc else {r.lower() for r in match.role_in}
        if role_lower not in role_in_set:  # type: ignore[operator]
            return False

    if match.role_not_in is not None:
        role_not_in_set = pc.role_not_in_set if pc else {r.lower() for r in match.role_not_in}
        if role_lower in role_not_in_set:  # type: ignore[operator]
            return False

    if match.role_type is not None and role_type_lower != match.role_type.lower():
        return False

    if match.principal_type is not None and principal_type_lower != match.principal_type.lower():
        return False

    if match.principal_type_in is not None:
        pt_in_set = pc.principal_type_in_set if pc else {t.lower() for t in match.principal_type_in}
        if principal_type_lower not in pt_in_set:  # type: ignore[operator]
            return False

    if match.principal_id is not None and a.principal_id.lower() != match.principal_id.lower():
        return False

    # Name-based operators — False when display name is not resolved (no false positives)
    dn = a.principal_display_name.lower() if a.principal_display_name else ""

    if match.principal_name_prefix is not None and (not dn or not dn.startswith(match.principal_name_prefix.lower())):
        return False

    not_prefix = match.principal_name_not_prefix
    if not_prefix is not None and (not dn or dn.startswith(not_prefix.lower())):
        return False

    if match.principal_name_contains is not None and (not dn or match.principal_name_contains.lower() not in dn):
        return False

    if match.principal_name_not_contains is None:
        return True
    return not (not dn or match.principal_name_not_contains.lower() in dn)


def _check_governance_rules(
    rules: list[Rule],
    assignments: list[ScannedRoleAssignment],
) -> list[ComplianceFinding]:
    """Evaluate governance rules against scanned assignments → violation findings."""
    if not rules:
        return []

    # Separate aggregation rules (max_assignments) from per-assignment rules
    aggregation_rules = [r for r in rules if r.match.max_assignments is not None]
    per_assignment_rules = [r for r in rules if r.match.max_assignments is None]

    # Pre-compute lowered sets once per rule
    precomputed = [_PrecomputedMatch(rule) for rule in per_assignment_rules]

    findings: list[ComplianceFinding] = []

    for a in assignments:
        if a.role_name is None:
            continue
        name_part = f" ({a.principal_display_name})" if a.principal_display_name else ""
        for pc in precomputed:
            if _evaluate_match(pc.match, a, pc):
                details: dict[str, str] = {}
                if pc.rule.remediation:
                    details["remediation"] = pc.rule.remediation
                findings.append(
                    ComplianceFinding(
                        rule_id=pc.rule.name,
                        severity=Severity(pc.rule.severity),
                        message=(
                            f"{pc.rule.description or pc.rule.name}: "
                            f"{a.principal_id}{name_part} with role {a.role_name} at {a.scope}"
                        ),
                        assignment_id=a.id,
                        scope=a.scope,
                        principal_id=a.principal_id,
                        principal_display_name=a.principal_display_name or "",
                        principal_type=str(a.principal_type),
                        role_name=a.role_name,
                        details=details,
                    )
                )

    # Process aggregation rules (max_assignments per scope)
    findings.extend(_check_aggregation_rules(aggregation_rules, assignments))

    return findings


def _check_aggregation_rules(
    rules: list[Rule],
    assignments: list[ScannedRoleAssignment],
) -> list[ComplianceFinding]:
    """Evaluate aggregation rules — fire when matching assignment count exceeds threshold per scope."""
    if not rules:
        return []

    findings: list[ComplianceFinding] = []

    for rule in rules:
        threshold = rule.match.max_assignments
        if threshold is None:
            continue

        pc = _PrecomputedMatch(rule)

        # Collect matching assignments grouped by scope
        scope_groups: dict[str, list[ScannedRoleAssignment]] = {}
        for a in assignments:
            if a.role_name is None:
                continue
            if _evaluate_match(pc.match, a, pc):
                scope_key = a.scope.lower().rstrip("/")
                scope_groups.setdefault(scope_key, []).append(a)

        # Only fire for scopes where count exceeds threshold
        for _scope_key, matched in scope_groups.items():
            if len(matched) <= threshold:
                continue

            details: dict[str, str] = {
                "count": str(len(matched)),
                "threshold": str(threshold),
            }
            if rule.remediation:
                details["remediation"] = rule.remediation

            # Use the original scope casing from the first match
            scope_display = matched[0].scope
            principals = ", ".join(
                a.principal_display_name or a.principal_id for a in matched
            )

            findings.append(
                ComplianceFinding(
                    rule_id=rule.name,
                    severity=Severity(rule.severity),
                    message=(
                        f"{rule.description or rule.name}: "
                        f"{len(matched)} assignments at {scope_display} "
                        f"(max {threshold}): {principals}"
                    ),
                    assignment_id=matched[0].id,
                    scope=scope_display,
                    principal_id="",
                    principal_display_name="",
                    principal_type="",
                    role_name=matched[0].role_name or "",
                    details=details,
                )
            )

    return findings


def _check_drift(
    baseline_rules: list[Rule],
    assignments: list[ScannedRoleAssignment],
) -> list[ComplianceFinding]:
    """Check assignments against baseline rules → DRIFT findings for undeclared assignments."""
    if not baseline_rules:
        return []

    baseline_precomputed = [_PrecomputedMatch(rule) for rule in baseline_rules]
    findings: list[ComplianceFinding] = []

    for a in assignments:
        if a.role_name is None:
            continue
        if any(_evaluate_match(pc.match, a, pc) for pc in baseline_precomputed):
            continue
        # No baseline rule matched → DRIFT
        name_part = f" ({a.principal_display_name})" if a.principal_display_name else ""
        findings.append(
            ComplianceFinding(
                rule_id=DRIFT,
                severity=Severity.HIGH,
                message=(f"Undeclared assignment: {a.principal_id}{name_part} with role {a.role_name} at {a.scope}"),
                assignment_id=a.id,
                scope=a.scope,
                principal_id=a.principal_id,
                principal_display_name=a.principal_display_name or "",
                principal_type=str(a.principal_type),
                role_name=a.role_name,
                details={
                    "remediation": "Add a baseline rule for this assignment or remove it from the tenant",
                },
            )
        )

    return findings


def _check_orphans(
    assignments: list[ScannedRoleAssignment],
) -> list[ComplianceFinding]:
    """Detect orphaned assignments — principal deleted from Entra ID."""
    findings: list[ComplianceFinding] = []
    for a in assignments:
        if a.principal_type != PrincipalType.UNKNOWN:
            continue
        role_display = a.role_name or "(unknown role)"
        findings.append(
            ComplianceFinding(
                rule_id=ORPHANED_ASSIGNMENT,
                severity=Severity.HIGH,
                message=(
                    f"Orphaned assignment: principal {a.principal_id} "
                    f"no longer exists in Entra ID — "
                    f"role {role_display} at {a.scope}"
                ),
                assignment_id=a.id,
                scope=a.scope,
                principal_id=a.principal_id,
                principal_display_name="",
                principal_type=str(a.principal_type),
                role_name=a.role_name or "",
                details={
                    "remediation": "Remove this role assignment — the principal no longer exists",
                },
            )
        )
    return findings


def _build_report(
    policy: PolicyModel,
    scan_result: RbacScanResult,
    findings: list[ComplianceFinding],
) -> ComplianceReport:
    """Build a ComplianceReport from findings."""
    drift_count = sum(1 for f in findings if f.rule_id == DRIFT)
    orphan_count = sum(1 for f in findings if f.rule_id == ORPHANED_ASSIGNMENT)
    violation_count = sum(1 for f in findings if f.rule_id not in (DRIFT, ORPHANED_ASSIGNMENT))

    severity_counts = Counter(f.severity for f in findings)
    summary = ComplianceSummary(
        total_assignments_checked=len(scan_result.all_assignments),
        total_findings=len(findings),
        findings_by_severity={str(k): v for k, v in severity_counts.items()},
        drift_count=drift_count,
        violation_count=violation_count,
        orphan_count=orphan_count,
    )

    return ComplianceReport(
        policy_version=policy.version,
        tenant_id=str(policy.tenant_id),
        scan_timestamp=datetime.now(tz=UTC),
        findings=findings,
        summary=summary,
        scan_errors=scan_result.all_errors,
        warnings=scan_result.warnings,
    )


# ── Entry points ─────────────────────────────────────────────


def check_drift(
    policy: PolicyModel,
    scan_result: RbacScanResult,
) -> ComplianceReport:
    """Drift detection — compare reality to the desired state (baseline rules).

    Each assignment not covered by a baseline rule = DRIFT finding.
    If no baseline rules exist, the report is empty (no drift to detect).
    """
    assignments = scan_result.all_assignments
    baseline_rules = [r for r in policy.rules if r.type == "baseline"]
    findings = _check_drift(baseline_rules, assignments)
    findings.extend(_check_orphans(assignments))
    return _build_report(policy, scan_result, findings)


def check_violations(
    policy: PolicyModel,
    scan_result: RbacScanResult,
) -> ComplianceReport:
    """Guardrail audit — evaluate governance rules.

    Each assignment matching a governance rule = violation finding.
    If no governance rules exist, the report is empty.
    """
    assignments = scan_result.all_assignments
    governance_rules = [r for r in policy.rules if r.type == "governance"]
    findings = _check_governance_rules(governance_rules, assignments)
    findings.extend(_check_orphans(assignments))
    return _build_report(policy, scan_result, findings)


def check_compliance(
    policy: PolicyModel,
    scan_result: RbacScanResult,
) -> ComplianceReport:
    """Combined entry point: drift + violations (both passes).

    Useful when evaluating all rules in a single pass.
    """
    assignments = scan_result.all_assignments

    governance_rules = [r for r in policy.rules if r.type == "governance"]
    baseline_rules = [r for r in policy.rules if r.type == "baseline"]

    findings: list[ComplianceFinding] = []
    findings.extend(_check_governance_rules(governance_rules, assignments))
    findings.extend(_check_drift(baseline_rules, assignments))
    findings.extend(_check_orphans(assignments))

    return _build_report(policy, scan_result, findings)
