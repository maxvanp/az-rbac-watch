"""rbac_scan MCP tool — flagship security scanner.

Scans Azure RBAC assignments, evaluates governance rules,
detects orphaned assignments, computes a risk score, and
returns prioritized remediation actions.
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from uuid import UUID

from az_rbac_watch.analyzers.compliance import (
    ORPHANED_ASSIGNMENT,
    ComplianceFinding,
    Severity,
    check_violations,
)
from az_rbac_watch.config.default_rules import DEFAULT_GOVERNANCE_RULES
from az_rbac_watch.config.policy_model import PolicyModel, load_policy_model
from az_rbac_watch.mcp.azure_scan import scan_subscription_async
from az_rbac_watch.scanner.rbac_scanner import (
    PrincipalType,
    ScannedRoleAssignment,
)

__all__ = ["SCAN_TOOL_DEF", "handle_scan"]

logger = logging.getLogger(__name__)

# ── Severity weights for risk scoring ────────────────────────────

_SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 10,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

# ── Tool definition ──────────────────────────────────────────────

SCAN_TOOL_DEF = {
    "name": "rbac_scan",
    "description": (
        "Scan Azure RBAC for security issues. Returns a risk score (0-100), "
        "findings ranked by severity, orphaned assignments, and prioritized "
        "remediation actions. Without a policy file, uses Azure best-practice "
        "defaults. With a cloudsight.yaml policy, scores against your "
        "organization's rules."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "subscriptionId": {
                "type": "string",
                "description": (
                    "Azure subscription ID to scan. Omit to scan all accessible subscriptions."
                ),
            },
            "policyPath": {
                "type": "string",
                "description": "Path to cloudsight.yaml policy file. Omit for default rules.",
            },
        },
    },
}

# ── Internal helpers ─────────────────────────────────────────────


def _detect_orphans(
    assignments: list[ScannedRoleAssignment],
) -> list[dict[str, str]]:
    """Detect orphaned assignments — principal can't be resolved."""
    orphans: list[dict[str, str]] = []
    for a in assignments:
        if a.principal_display_name is None and a.principal_type in (
            PrincipalType.UNKNOWN,
            None,
        ):
            orphans.append({
                "principalId": a.principal_id,
                "role": a.role_name or "(unknown)",
                "scope": a.scope,
            })
    return orphans


def _compute_risk_score(
    findings: list[ComplianceFinding],
    orphan_count: int,
    total_assignments: int,
) -> int:
    """Weighted risk score normalized to 0-100."""
    if total_assignments == 0:
        return 0

    raw = sum(_SEVERITY_WEIGHT.get(f.severity, 0) for f in findings)
    # Orphans contribute as high severity each
    raw += orphan_count * _SEVERITY_WEIGHT[Severity.HIGH]

    # Normalize: max possible is if every assignment were critical
    max_possible = total_assignments * _SEVERITY_WEIGHT[Severity.CRITICAL]
    if max_possible == 0:
        return 0

    return min(100, round(raw / max_possible * 100))


def _build_top_actions(
    findings: list[ComplianceFinding],
    orphan_count: int,
    *,
    max_actions: int = 5,
) -> list[str]:
    """Derive top prioritized actions from findings and orphans."""
    actions: list[str] = []

    # Group findings by severity
    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    for sev in severity_order:
        sev_findings = [f for f in findings if f.severity == sev and f.rule_id != ORPHANED_ASSIGNMENT]
        if not sev_findings:
            continue
        # Group by rule_id
        by_rule: dict[str, list[ComplianceFinding]] = {}
        for f in sev_findings:
            by_rule.setdefault(f.rule_id, []).append(f)
        for rule_id, group in by_rule.items():
            desc = group[0].message.split(":")[0] if group[0].message else rule_id
            actions.append(f"Fix {len(group)} {sev.value} finding(s): {desc}")
            if len(actions) >= max_actions:
                return actions

    if orphan_count > 0 and len(actions) < max_actions:
        actions.append(
            f"Remove {orphan_count} orphaned assignment(s) pointing to deleted principals"
        )

    return actions[:max_actions]


def _finding_to_dict(f: ComplianceFinding) -> dict[str, str]:
    """Convert a ComplianceFinding to the output JSON shape."""
    result: dict[str, str] = {
        "severity": str(f.severity),
        "rule": f.rule_id,
        "description": f.message,
        "principal": f.principal_display_name or f.principal_id,
        "principalType": f.principal_type,
        "role": f.role_name,
        "scope": f.scope,
    }
    if "remediation" in f.details:
        result["remediation"] = f.details["remediation"]
    return result


# ── Public handler ───────────────────────────────────────────────


async def handle_scan(
    subscription_id: str | None = None,
    policy_path: str | None = None,
) -> str:
    """Scan Azure RBAC and return structured JSON with risk score, findings, orphans, and actions."""

    # 1. Scan Azure
    scan_result = await scan_subscription_async(subscription_id)
    all_assignments = scan_result.all_assignments

    # 2. Build or load policy for rule evaluation
    if policy_path:
        policy = load_policy_model(policy_path)
    else:
        # Ad-hoc mode: build a minimal PolicyModel with default governance rules
        # Use a dummy tenant_id — the compliance engine only looks at rules
        policy = PolicyModel(
            version="2.0",
            tenant_id=UUID("00000000-0000-0000-0000-000000000000"),
            rules=list(DEFAULT_GOVERNANCE_RULES),
        )

    # 3. Evaluate governance rules via the existing compliance engine
    report = check_violations(policy, scan_result)

    # Filter out orphan findings from the compliance report (we handle them separately)
    rule_findings = [f for f in report.findings if f.rule_id != ORPHANED_ASSIGNMENT]

    # 4. Detect orphans
    orphans = _detect_orphans(all_assignments)

    # 5. Compute risk score
    risk_score = _compute_risk_score(rule_findings, len(orphans), len(all_assignments))

    # 6. Build summary
    principal_types: Counter[str] = Counter()
    role_distribution: Counter[str] = Counter()
    for a in all_assignments:
        principal_types[str(a.principal_type)] += 1
        role_distribution[a.role_name or "(unknown)"] += 1

    summary = {
        "totalAssignments": len(all_assignments),
        "principalTypes": dict(principal_types),
        "roleDistribution": dict(role_distribution),
        "subscriptionsScanned": len(scan_result.subscription_results),
    }

    # 7. Build top actions
    top_actions = _build_top_actions(rule_findings, len(orphans))

    # 8. Assemble output
    output = {
        "riskScore": risk_score,
        "summary": summary,
        "findings": [_finding_to_dict(f) for f in rule_findings],
        "orphans": orphans,
        "topActions": top_actions,
    }

    return json.dumps(output, indent=2)
