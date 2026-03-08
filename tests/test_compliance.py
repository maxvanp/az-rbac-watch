"""Tests unitaires pour le moteur de conformité (baseline/governance rules).

Tous les tests utilisent des données mockées — aucun credential Azure requis.
"""

from __future__ import annotations

from datetime import UTC

from az_rbac_watch.analyzers.compliance import (
    OUT_OF_BASELINE,
    ComplianceFinding,
    ComplianceReport,
    ComplianceSummary,
    Severity,
    check_compliance,
)
from az_rbac_watch.scanner.rbac_scanner import PrincipalType, RoleType

from .conftest import (
    VALID_PRINCIPAL_GROUP,
    VALID_PRINCIPAL_SP,
    VALID_PRINCIPAL_USER,
    VALID_SUB_ID,
    VALID_TENANT_ID,
)
from .factories import make_assignment, make_policy, make_scan_result

# ── TestSeverity ──────────────────────────────────────────────


class TestSeverity:
    def test_values(self):
        assert Severity.CRITICAL == "critical"
        assert Severity.HIGH == "high"
        assert Severity.MEDIUM == "medium"
        assert Severity.LOW == "low"
        assert Severity.INFO == "info"

    def test_serialization(self):
        finding = ComplianceFinding(
            rule_id="TEST",
            severity=Severity.HIGH,
            message="test",
        )
        data = finding.model_dump()
        assert data["severity"] == "high"


# ── TestComplianceFinding ─────────────────────────────────────


class TestComplianceFinding:
    def test_minimal_creation(self):
        finding = ComplianceFinding(
            rule_id="TEST_RULE",
            severity=Severity.MEDIUM,
            message="Un problème détecté",
        )
        assert finding.rule_id == "TEST_RULE"
        assert finding.severity == Severity.MEDIUM
        assert finding.message == "Un problème détecté"

    def test_defaults(self):
        finding = ComplianceFinding(
            rule_id="TEST",
            severity=Severity.LOW,
            message="test",
        )
        assert finding.assignment_id == ""
        assert finding.scope == ""
        assert finding.principal_id == ""
        assert finding.principal_display_name == ""
        assert finding.principal_type == ""
        assert finding.role_name == ""
        assert finding.details == {}


# ── TestComplianceReport ──────────────────────────────────────


class TestComplianceReport:
    def test_empty_report(self):
        report = ComplianceReport(
            policy_version="2.0",
            tenant_id=VALID_TENANT_ID,
            scan_timestamp="2025-01-01T00:00:00Z",
        )
        assert report.findings == []
        assert report.summary.total_findings == 0
        assert report.scan_errors == []

    def test_report_with_findings(self):
        findings = [
            ComplianceFinding(rule_id="R1", severity=Severity.HIGH, message="m1"),
            ComplianceFinding(rule_id="R2", severity=Severity.LOW, message="m2"),
        ]
        report = ComplianceReport(
            policy_version="2.0",
            tenant_id=VALID_TENANT_ID,
            scan_timestamp="2025-01-01T00:00:00Z",
            findings=findings,
        )
        assert len(report.findings) == 2

    def test_report_with_scan_errors(self):
        report = ComplianceReport(
            policy_version="2.0",
            tenant_id=VALID_TENANT_ID,
            scan_timestamp="2025-01-01T00:00:00Z",
            scan_errors=["Erreur API 403"],
        )
        assert len(report.scan_errors) == 1


# ── TestComplianceSummary ─────────────────────────────────────


class TestComplianceSummary:
    def test_defaults(self):
        summary = ComplianceSummary()
        assert summary.drift_count == 0
        assert summary.violation_count == 0
        assert summary.total_findings == 0


# ── TestCheckCompliance ──────────────────────────────────────


class TestCheckCompliance:
    def test_baseline_matches_no_findings(self):
        """Assignment matched by baseline rule → 0 findings."""
        policy = make_policy(
            rules=[
                {
                    "name": "allow-reader",
                    "type": "baseline",
                    "match": {
                        "principal_id": VALID_PRINCIPAL_GROUP,
                        "role": "Reader",
                        "scope": f"/subscriptions/{VALID_SUB_ID}",
                    },
                }
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(
                    principal_type=PrincipalType.GROUP,
                    principal_id=VALID_PRINCIPAL_GROUP,
                    role_name="Reader",
                    scope=f"/subscriptions/{VALID_SUB_ID}",
                )
            ]
        )
        report = check_compliance(policy, scan)
        assert len(report.findings) == 0
        assert report.summary.drift_count == 0

    def test_out_of_baseline_detected(self):
        """Assignment not matching any baseline rule → DRIFT HIGH."""
        policy = make_policy(
            rules=[
                {
                    "name": "allow-reader",
                    "type": "baseline",
                    "match": {
                        "principal_id": VALID_PRINCIPAL_GROUP,
                        "role": "Reader",
                        "scope": f"/subscriptions/{VALID_SUB_ID}",
                    },
                }
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(
                    principal_type=PrincipalType.USER,
                    role_name="Owner",
                    scope=f"/subscriptions/{VALID_SUB_ID}",
                )
            ]
        )
        report = check_compliance(policy, scan)
        assert len(report.findings) == 1
        assert report.findings[0].rule_id == OUT_OF_BASELINE
        assert report.findings[0].severity == Severity.HIGH
        assert report.summary.drift_count == 1

    def test_governance_only_no_out_of_baseline(self):
        """No baseline rules → governance-only mode, no OUT_OF_BASELINE findings."""
        policy = make_policy(
            rules=[
                {"name": "no-owner", "type": "governance", "severity": "critical", "match": {"role": "Owner"}},
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="Reader"),
            ]
        )
        report = check_compliance(policy, scan)
        out_of_baseline = [f for f in report.findings if f.rule_id == OUT_OF_BASELINE]
        assert len(out_of_baseline) == 0

    def test_governance_rule_violation(self):
        """Assignment matching governance rule → GOVERNANCE_VIOLATION finding."""
        policy = make_policy(
            rules=[
                {"name": "no-owner", "type": "governance", "severity": "critical", "match": {"role": "Owner"}},
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="Owner"),
            ]
        )
        report = check_compliance(policy, scan)
        assert len(report.findings) == 1
        assert report.findings[0].rule_id == "no-owner"
        assert report.findings[0].severity == Severity.CRITICAL
        assert report.summary.violation_count == 1

    def test_governance_overrides_baseline(self):
        """Governance + baseline on same assignment → GOVERNANCE_VIOLATION produced (governance wins)."""
        policy = make_policy(
            rules=[
                {
                    "name": "allow-all-reader",
                    "type": "baseline",
                    "match": {"role": "Reader"},
                },
                {
                    "name": "no-direct-users",
                    "type": "governance",
                    "severity": "high",
                    "match": {"principal_type": "User"},
                },
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(
                    principal_type=PrincipalType.USER,
                    role_name="Reader",
                ),
            ]
        )
        report = check_compliance(policy, scan)
        rule_ids = {f.rule_id for f in report.findings}
        assert "no-direct-users" in rule_ids
        # Also no OUT_OF_BASELINE since the baseline rule matches
        assert OUT_OF_BASELINE not in rule_ids

    def test_mixed_baseline_governance_and_out_of_baseline(self):
        """Baseline + governance + out-of-baseline assignment in one report."""
        policy = make_policy(
            rules=[
                {
                    "name": "allow-reader-group",
                    "type": "baseline",
                    "match": {
                        "principal_id": VALID_PRINCIPAL_GROUP,
                        "role": "Reader",
                        "scope": f"/subscriptions/{VALID_SUB_ID}",
                    },
                },
                {
                    "name": "no-direct-users",
                    "type": "governance",
                    "severity": "high",
                    "match": {"principal_type": "User"},
                },
            ],
        )
        scan = make_scan_result(
            [
                # Allowed
                make_assignment(
                    principal_type=PrincipalType.GROUP,
                    principal_id=VALID_PRINCIPAL_GROUP,
                    role_name="Reader",
                    scope=f"/subscriptions/{VALID_SUB_ID}",
                ),
                # Governance match + out-of-baseline
                make_assignment(
                    principal_type=PrincipalType.USER,
                    role_name="Owner",
                    scope=f"/subscriptions/{VALID_SUB_ID}",
                    assignment_id="a2",
                ),
                # Out-of-baseline only (SP, no governance rule)
                make_assignment(
                    principal_type=PrincipalType.SERVICE_PRINCIPAL,
                    principal_id=VALID_PRINCIPAL_SP,
                    role_name="Contributor",
                    scope=f"/subscriptions/{VALID_SUB_ID}",
                    assignment_id="a3",
                ),
            ]
        )
        report = check_compliance(policy, scan)
        rule_ids = [f.rule_id for f in report.findings]
        assert "no-direct-users" in rule_ids
        assert OUT_OF_BASELINE in rule_ids
        assert report.summary.violation_count >= 1
        assert report.summary.drift_count >= 1

    def test_no_rules_no_findings(self):
        """Empty rules → no findings at all (governance-only mode, no governance rules)."""
        policy = make_policy()
        scan = make_scan_result(
            [
                make_assignment(role_name="Reader"),
            ]
        )
        report = check_compliance(policy, scan)
        assert report.summary.total_findings == 0

    def test_role_name_none_ignored(self):
        """Assignments with role_name=None are ignored."""
        policy = make_policy(
            rules=[
                {"name": "allow-all", "type": "baseline", "match": {}},
            ],
        )
        scan = make_scan_result([make_assignment(role_name=None)])
        report = check_compliance(policy, scan)
        assert report.summary.drift_count == 0
        assert report.summary.total_assignments_checked == 1

    def test_scan_errors_passed_to_report(self):
        """Scan errors are propagated to the report."""
        policy = make_policy()
        scan = make_scan_result([], errors=["Erreur API 403"])
        report = check_compliance(policy, scan)
        assert report.scan_errors == ["Erreur API 403"]

    def test_metadata(self):
        """Report contains policy model metadata."""
        policy = make_policy()
        scan = make_scan_result([])
        report = check_compliance(policy, scan)
        assert report.policy_version == "2.0"
        assert report.tenant_id == VALID_TENANT_ID
        assert report.scan_timestamp.tzinfo == UTC

    def test_finding_contains_assignment_details(self):
        """OUT_OF_BASELINE finding contains scanned assignment details."""
        policy = make_policy(
            rules=[
                {"name": "allow-nothing", "type": "baseline", "match": {"role": "NonExistent"}},
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(
                    principal_id=VALID_PRINCIPAL_USER,
                    principal_type=PrincipalType.USER,
                    role_name="Owner",
                    scope=f"/subscriptions/{VALID_SUB_ID}/resourceGroups/rg-1",
                    assignment_id="test-assignment-id",
                )
            ]
        )
        report = check_compliance(policy, scan)
        assert len(report.findings) == 1
        f = report.findings[0]
        assert f.assignment_id == "test-assignment-id"
        assert f.principal_id == VALID_PRINCIPAL_USER
        assert f.principal_type == "User"
        assert f.role_name == "Owner"
        assert f.scope == f"/subscriptions/{VALID_SUB_ID}/resourceGroups/rg-1"

    def test_summary_severity_breakdown(self):
        """Summary contains severity breakdown."""
        policy = make_policy(
            rules=[
                {"name": "no-owner", "type": "governance", "severity": "critical", "match": {"role": "Owner"}},
                {
                    "name": "allow-reader",
                    "type": "baseline",
                    "match": {"principal_id": "missing-principal", "role": "Reader", "scope": "/subscriptions/xxx"},
                },
            ],
        )
        scan = make_scan_result([make_assignment(role_name="Owner")])
        report = check_compliance(policy, scan)
        # no-owner → critical, OUT_OF_BASELINE → high
        assert Severity.CRITICAL in report.summary.findings_by_severity
        assert Severity.HIGH in report.summary.findings_by_severity


# ── TestRulesEngine ──────────────────────────────────────────


class TestRulesEngine:
    """Tests for the generic declarative rules engine (governance rules)."""

    # ── principal_type match ─────────────────────────────────

    def test_match_principal_type_positive(self):
        policy = make_policy(
            rules=[
                {"name": "no-direct-users", "severity": "high", "match": {"principal_type": "User"}},
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(principal_type=PrincipalType.USER, role_name="Reader"),
            ]
        )
        report = check_compliance(policy, scan)
        rule_ids = [f.rule_id for f in report.findings]
        assert "no-direct-users" in rule_ids

    def test_match_principal_type_negative(self):
        """Group assignments don't match principal_type: User."""
        policy = make_policy(
            rules=[
                {"name": "no-direct-users", "severity": "high", "match": {"principal_type": "User"}},
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(
                    principal_type=PrincipalType.GROUP,
                    principal_id=VALID_PRINCIPAL_GROUP,
                    role_name="Reader",
                ),
            ]
        )
        report = check_compliance(policy, scan)
        rule_ids = [f.rule_id for f in report.findings]
        assert "no-direct-users" not in rule_ids

    # ── role match ───────────────────────────────────────────

    def test_match_role_positive(self):
        policy = make_policy(
            rules=[
                {"name": "no-owner", "severity": "critical", "match": {"role": "Owner"}},
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="Owner"),
            ]
        )
        report = check_compliance(policy, scan)
        rule_ids = [f.rule_id for f in report.findings]
        assert "no-owner" in rule_ids
        finding = next(f for f in report.findings if f.rule_id == "no-owner")
        assert finding.severity == Severity.CRITICAL

    def test_match_role_negative(self):
        policy = make_policy(
            rules=[
                {"name": "no-owner", "severity": "critical", "match": {"role": "Owner"}},
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="Reader"),
            ]
        )
        report = check_compliance(policy, scan)
        rule_ids = [f.rule_id for f in report.findings]
        assert "no-owner" not in rule_ids

    # ── role_not_in match ────────────────────────────────────

    def test_match_role_not_in_positive(self):
        """Role NOT in the allowed list → match."""
        policy = make_policy(
            rules=[
                {"name": "allowed-roles-prod", "severity": "high", "match": {"role_not_in": ["Reader", "Contributor"]}},
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="Owner"),
            ]
        )
        report = check_compliance(policy, scan)
        rule_ids = [f.rule_id for f in report.findings]
        assert "allowed-roles-prod" in rule_ids

    def test_match_role_not_in_negative(self):
        """Role IS in the allowed list → no match."""
        policy = make_policy(
            rules=[
                {"name": "allowed-roles-prod", "severity": "high", "match": {"role_not_in": ["Reader", "Contributor"]}},
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="Reader"),
            ]
        )
        report = check_compliance(policy, scan)
        rule_ids = [f.rule_id for f in report.findings]
        assert "allowed-roles-prod" not in rule_ids

    def test_match_role_not_in_case_insensitive(self):
        policy = make_policy(
            rules=[
                {"name": "allowed-roles", "severity": "high", "match": {"role_not_in": ["READER"]}},
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="reader"),
            ]
        )
        report = check_compliance(policy, scan)
        rule_ids = [f.rule_id for f in report.findings]
        assert "allowed-roles" not in rule_ids

    # ── role_in match ────────────────────────────────────────

    def test_match_role_in_positive(self):
        policy = make_policy(
            rules=[
                {
                    "name": "dangerous-roles",
                    "severity": "critical",
                    "match": {"role_in": ["Owner", "User Access Administrator"]},
                },
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="Owner"),
            ]
        )
        report = check_compliance(policy, scan)
        assert "dangerous-roles" in [f.rule_id for f in report.findings]

    def test_match_role_in_negative(self):
        policy = make_policy(
            rules=[
                {
                    "name": "dangerous-roles",
                    "severity": "critical",
                    "match": {"role_in": ["Owner", "User Access Administrator"]},
                },
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="Reader"),
            ]
        )
        report = check_compliance(policy, scan)
        assert "dangerous-roles" not in [f.rule_id for f in report.findings]

    # ── role_type match ──────────────────────────────────────

    def test_match_role_type_custom_positive(self):
        policy = make_policy(
            rules=[
                {"name": "no-custom-roles", "severity": "medium", "match": {"role_type": "CustomRole"}},
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="MyCustomRole", role_type=RoleType.CUSTOM),
            ]
        )
        report = check_compliance(policy, scan)
        assert "no-custom-roles" in [f.rule_id for f in report.findings]

    def test_match_role_type_custom_negative(self):
        policy = make_policy(
            rules=[
                {"name": "no-custom-roles", "severity": "medium", "match": {"role_type": "CustomRole"}},
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="Reader", role_type=RoleType.BUILT_IN),
            ]
        )
        report = check_compliance(policy, scan)
        assert "no-custom-roles" not in [f.rule_id for f in report.findings]

    # ── scope_prefix match ───────────────────────────────────

    def test_match_scope_prefix_child_scope(self):
        """Rule with scope_prefix applies to child resource group."""
        policy = make_policy(
            rules=[
                {
                    "name": "no-owner-prod",
                    "severity": "critical",
                    "match": {"scope_prefix": f"/subscriptions/{VALID_SUB_ID}", "role": "Owner"},
                },
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(
                    role_name="Owner",
                    scope=f"/subscriptions/{VALID_SUB_ID}/resourceGroups/rg-prod",
                ),
            ]
        )
        report = check_compliance(policy, scan)
        assert "no-owner-prod" in [f.rule_id for f in report.findings]

    def test_match_scope_prefix_exact(self):
        """scope_prefix matches the exact scope too."""
        policy = make_policy(
            rules=[
                {
                    "name": "no-owner-prod",
                    "severity": "critical",
                    "match": {"scope_prefix": f"/subscriptions/{VALID_SUB_ID}", "role": "Owner"},
                },
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="Owner"),
            ]
        )
        report = check_compliance(policy, scan)
        assert "no-owner-prod" in [f.rule_id for f in report.findings]

    def test_match_scope_prefix_no_false_positive(self):
        """scope_prefix on one subscription doesn't match a different one."""
        other_sub = "99999999-9999-9999-9999-999999999999"
        policy = make_policy(
            rules=[
                {
                    "name": "no-owner",
                    "severity": "critical",
                    "match": {"scope_prefix": f"/subscriptions/{other_sub}", "role": "Owner"},
                },
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="Owner"),  # default scope is VALID_SUB_ID
            ]
        )
        report = check_compliance(policy, scan)
        assert "no-owner" not in [f.rule_id for f in report.findings]

    # ── scope exact match ────────────────────────────────────

    def test_match_scope_exact(self):
        policy = make_policy(
            rules=[
                {
                    "name": "no-owner-exact",
                    "severity": "critical",
                    "match": {"scope": f"/subscriptions/{VALID_SUB_ID}", "role": "Owner"},
                },
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="Owner"),
            ]
        )
        report = check_compliance(policy, scan)
        assert "no-owner-exact" in [f.rule_id for f in report.findings]

    def test_match_scope_exact_no_child(self):
        """Exact scope match does NOT match child scopes."""
        policy = make_policy(
            rules=[
                {
                    "name": "no-owner-exact",
                    "severity": "critical",
                    "match": {"scope": f"/subscriptions/{VALID_SUB_ID}", "role": "Owner"},
                },
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(
                    role_name="Owner",
                    scope=f"/subscriptions/{VALID_SUB_ID}/resourceGroups/rg-prod",
                ),
            ]
        )
        report = check_compliance(policy, scan)
        assert "no-owner-exact" not in [f.rule_id for f in report.findings]

    # ── principal_id match ───────────────────────────────────

    def test_match_principal_id_positive(self):
        policy = make_policy(
            rules=[
                {"name": "block-bad-sp", "severity": "critical", "match": {"principal_id": VALID_PRINCIPAL_SP}},
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(
                    principal_id=VALID_PRINCIPAL_SP,
                    principal_type=PrincipalType.SERVICE_PRINCIPAL,
                    role_name="Contributor",
                ),
            ]
        )
        report = check_compliance(policy, scan)
        assert "block-bad-sp" in [f.rule_id for f in report.findings]

    def test_match_principal_id_negative(self):
        policy = make_policy(
            rules=[
                {"name": "block-bad-sp", "severity": "critical", "match": {"principal_id": VALID_PRINCIPAL_SP}},
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="Reader"),  # default principal is VALID_PRINCIPAL_USER
            ]
        )
        report = check_compliance(policy, scan)
        assert "block-bad-sp" not in [f.rule_id for f in report.findings]

    # ── principal_type_in match ──────────────────────────────

    def test_match_principal_type_in_positive(self):
        policy = make_policy(
            rules=[
                {
                    "name": "no-direct-principals",
                    "severity": "high",
                    "match": {"principal_type_in": ["User", "ServicePrincipal"]},
                },
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(principal_type=PrincipalType.USER, role_name="Reader"),
            ]
        )
        report = check_compliance(policy, scan)
        assert "no-direct-principals" in [f.rule_id for f in report.findings]

    def test_match_principal_type_in_negative(self):
        policy = make_policy(
            rules=[
                {
                    "name": "no-direct-principals",
                    "severity": "high",
                    "match": {"principal_type_in": ["User", "ServicePrincipal"]},
                },
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(
                    principal_type=PrincipalType.GROUP,
                    principal_id=VALID_PRINCIPAL_GROUP,
                    role_name="Reader",
                ),
            ]
        )
        report = check_compliance(policy, scan)
        assert "no-direct-principals" not in [f.rule_id for f in report.findings]

    # ── AND combination ──────────────────────────────────────

    def test_and_combination_all_match(self):
        """Multiple conditions all true → finding."""
        policy = make_policy(
            rules=[
                {
                    "name": "user-owner-on-sub",
                    "severity": "critical",
                    "match": {
                        "scope_prefix": f"/subscriptions/{VALID_SUB_ID}",
                        "principal_type": "User",
                        "role": "Owner",
                    },
                },
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(
                    principal_type=PrincipalType.USER,
                    role_name="Owner",
                ),
            ]
        )
        report = check_compliance(policy, scan)
        assert "user-owner-on-sub" in [f.rule_id for f in report.findings]

    def test_and_combination_partial_match(self):
        """Not all conditions met → no finding."""
        policy = make_policy(
            rules=[
                {
                    "name": "user-owner-on-sub",
                    "severity": "critical",
                    "match": {
                        "scope_prefix": f"/subscriptions/{VALID_SUB_ID}",
                        "principal_type": "User",
                        "role": "Owner",
                    },
                },
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(
                    principal_type=PrincipalType.USER,
                    role_name="Reader",  # not Owner → partial match
                ),
            ]
        )
        report = check_compliance(policy, scan)
        assert "user-owner-on-sub" not in [f.rule_id for f in report.findings]

    # ── Empty match = global rule ────────────────────────────

    def test_empty_match_matches_everything(self):
        """No conditions → rule matches every assignment."""
        policy = make_policy(
            rules=[
                {"name": "catch-all", "severity": "info", "match": {}},
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="Reader"),
                make_assignment(
                    role_name="Owner",
                    assignment_id="a2",
                    principal_id=VALID_PRINCIPAL_SP,
                    principal_type=PrincipalType.SERVICE_PRINCIPAL,
                ),
            ]
        )
        report = check_compliance(policy, scan)
        catch_all = [f for f in report.findings if f.rule_id == "catch-all"]
        assert len(catch_all) == 2

    # ── Case-insensitive matching ────────────────────────────

    def test_case_insensitive_role(self):
        policy = make_policy(
            rules=[
                {"name": "no-owner", "severity": "critical", "match": {"role": "OWNER"}},
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="owner"),
            ]
        )
        report = check_compliance(policy, scan)
        assert "no-owner" in [f.rule_id for f in report.findings]

    def test_case_insensitive_principal_type(self):
        policy = make_policy(
            rules=[
                {"name": "no-users", "severity": "high", "match": {"principal_type": "user"}},
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(principal_type=PrincipalType.USER, role_name="Reader"),
            ]
        )
        report = check_compliance(policy, scan)
        assert "no-users" in [f.rule_id for f in report.findings]

    def test_case_insensitive_scope_prefix(self):
        policy = make_policy(
            rules=[
                {
                    "name": "no-owner",
                    "severity": "critical",
                    "match": {"scope_prefix": f"/Subscriptions/{VALID_SUB_ID}", "role": "Owner"},
                },
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="Owner"),
            ]
        )
        report = check_compliance(policy, scan)
        assert "no-owner" in [f.rule_id for f in report.findings]

    def test_case_insensitive_principal_id(self):
        upper_id = VALID_PRINCIPAL_SP.upper()
        policy = make_policy(
            rules=[
                {"name": "block-sp", "severity": "critical", "match": {"principal_id": upper_id}},
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(
                    principal_id=VALID_PRINCIPAL_SP.lower(),
                    principal_type=PrincipalType.SERVICE_PRINCIPAL,
                    role_name="Contributor",
                ),
            ]
        )
        report = check_compliance(policy, scan)
        assert "block-sp" in [f.rule_id for f in report.findings]

    # ── role_name=None ignored ───────────────────────────────

    def test_role_name_none_ignored(self):
        """Assignments with role_name=None are skipped by rules."""
        policy = make_policy(
            rules=[
                {"name": "catch-all", "severity": "info", "match": {}},
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name=None),
            ]
        )
        report = check_compliance(policy, scan)
        assert "catch-all" not in [f.rule_id for f in report.findings]

    # ── Multi-rules on same assignment ───────────────────────

    def test_multi_rules_same_assignment(self):
        """Multiple rules matching the same assignment all produce findings."""
        policy = make_policy(
            rules=[
                {"name": "no-owner", "severity": "critical", "match": {"role": "Owner"}},
                {"name": "no-direct-users", "severity": "high", "match": {"principal_type": "User"}},
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(
                    principal_type=PrincipalType.USER,
                    role_name="Owner",
                ),
            ]
        )
        report = check_compliance(policy, scan)
        rule_ids = [f.rule_id for f in report.findings]
        assert "no-owner" in rule_ids
        assert "no-direct-users" in rule_ids

    # ── No rules = no extra findings ─────────────────────────

    def test_no_rules_no_extra_findings(self):
        """Empty rules → no additional findings."""
        policy = make_policy()
        scan = make_scan_result([])
        report = check_compliance(policy, scan)
        assert report.summary.total_findings == 0

    # ── rule_id = rule.name ──────────────────────────────────

    def test_rule_id_is_rule_name(self):
        policy = make_policy(
            rules=[
                {"name": "my-custom-rule", "severity": "medium", "match": {"role": "Owner"}},
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="Owner"),
            ]
        )
        report = check_compliance(policy, scan)
        owner_findings = [f for f in report.findings if f.rule_id == "my-custom-rule"]
        assert len(owner_findings) == 1

    # ── Findings counted in total ────────────────────────────

    def test_rules_findings_in_total(self):
        """Rule findings are counted in total_findings."""
        policy = make_policy(
            rules=[
                {"name": "no-owner", "severity": "critical", "match": {"role": "Owner"}},
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="Owner"),
            ]
        )
        report = check_compliance(policy, scan)
        assert report.summary.total_findings >= 1

    # ── principal_display_name propagation ────────────────────

    def test_display_name_in_rule_finding(self):
        """Rule findings include principal_display_name when available."""
        policy = make_policy(
            rules=[
                {"name": "no-users", "severity": "high", "match": {"principal_type": "User"}},
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(
                    principal_type=PrincipalType.USER,
                    role_name="Reader",
                    principal_display_name="John Doe",
                ),
            ]
        )
        report = check_compliance(policy, scan)
        rule_findings = [f for f in report.findings if f.rule_id == "no-users"]
        assert len(rule_findings) == 1
        assert rule_findings[0].principal_display_name == "John Doe"
        assert "John Doe" in rule_findings[0].message

    def test_display_name_in_out_of_baseline_finding(self):
        """OUT_OF_BASELINE findings include principal_display_name when available."""
        policy = make_policy(
            rules=[
                {"name": "allow-nothing", "type": "baseline", "match": {"role": "NonExistent"}},
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(
                    role_name="Owner",
                    principal_display_name="GRP-TEAM-INFRA",
                ),
            ]
        )
        report = check_compliance(policy, scan)
        oob = [f for f in report.findings if f.rule_id == OUT_OF_BASELINE]
        assert len(oob) == 1
        assert oob[0].principal_display_name == "GRP-TEAM-INFRA"
        assert "GRP-TEAM-INFRA" in oob[0].message

    def test_display_name_empty_when_not_resolved(self):
        """principal_display_name defaults to empty when not resolved."""
        policy = make_policy(
            rules=[
                {"name": "allow-nothing", "type": "baseline", "match": {"role": "NonExistent"}},
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="Owner"),
            ]
        )
        report = check_compliance(policy, scan)
        oob = [f for f in report.findings if f.rule_id == OUT_OF_BASELINE]
        assert len(oob) == 1
        assert oob[0].principal_display_name == ""


# ── TestNameBasedRules ──────────────────────────────────────


class TestNameBasedRules:
    """Tests for principal_name_* match operators."""

    # ── principal_name_prefix ────────────────────────────────

    def test_name_prefix_positive(self):
        policy = make_policy(
            rules=[{"name": "perm-groups", "severity": "info", "match": {"principal_name_prefix": "GRP-PERM-"}}],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="Reader", principal_display_name="GRP-PERM-Readers"),
            ]
        )
        report = check_compliance(policy, scan)
        assert "perm-groups" in [f.rule_id for f in report.findings]

    def test_name_prefix_negative(self):
        policy = make_policy(
            rules=[{"name": "perm-groups", "severity": "info", "match": {"principal_name_prefix": "GRP-PERM-"}}],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="Reader", principal_display_name="GRP-TEAM-INFRA"),
            ]
        )
        report = check_compliance(policy, scan)
        assert "perm-groups" not in [f.rule_id for f in report.findings]

    # ── principal_name_not_prefix ────────────────────────────

    def test_name_not_prefix_positive(self):
        """Name does NOT start with prefix → match."""
        policy = make_policy(
            rules=[
                {
                    "name": "only-perm",
                    "severity": "high",
                    "match": {"principal_type": "Group", "principal_name_not_prefix": "GRP-PERM-"},
                }
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(
                    principal_type=PrincipalType.GROUP,
                    principal_id=VALID_PRINCIPAL_GROUP,
                    role_name="Reader",
                    principal_display_name="GRP-TEAM-INFRA",
                ),
            ]
        )
        report = check_compliance(policy, scan)
        assert "only-perm" in [f.rule_id for f in report.findings]

    def test_name_not_prefix_negative(self):
        """Name starts with prefix → no match."""
        policy = make_policy(
            rules=[
                {
                    "name": "only-perm",
                    "severity": "high",
                    "match": {"principal_type": "Group", "principal_name_not_prefix": "GRP-PERM-"},
                }
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(
                    principal_type=PrincipalType.GROUP,
                    principal_id=VALID_PRINCIPAL_GROUP,
                    role_name="Reader",
                    principal_display_name="GRP-PERM-Readers",
                ),
            ]
        )
        report = check_compliance(policy, scan)
        assert "only-perm" not in [f.rule_id for f in report.findings]

    # ── principal_name_contains ──────────────────────────────

    def test_name_contains_positive(self):
        policy = make_policy(
            rules=[{"name": "no-temp", "severity": "medium", "match": {"principal_name_contains": "TEMP"}}],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="Reader", principal_display_name="GRP-TEMP-Deploy"),
            ]
        )
        report = check_compliance(policy, scan)
        assert "no-temp" in [f.rule_id for f in report.findings]

    def test_name_contains_negative(self):
        policy = make_policy(
            rules=[{"name": "no-temp", "severity": "medium", "match": {"principal_name_contains": "TEMP"}}],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="Reader", principal_display_name="GRP-PERM-Readers"),
            ]
        )
        report = check_compliance(policy, scan)
        assert "no-temp" not in [f.rule_id for f in report.findings]

    # ── principal_name_not_contains ──────────────────────────

    def test_name_not_contains_positive(self):
        """Name does NOT contain substring → match."""
        policy = make_policy(
            rules=[{"name": "must-have-azure", "severity": "low", "match": {"principal_name_not_contains": "AZURE"}}],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="Reader", principal_display_name="GRP-TEAM-INFRA"),
            ]
        )
        report = check_compliance(policy, scan)
        assert "must-have-azure" in [f.rule_id for f in report.findings]

    def test_name_not_contains_negative(self):
        """Name contains substring → no match."""
        policy = make_policy(
            rules=[{"name": "must-have-azure", "severity": "low", "match": {"principal_name_not_contains": "AZURE"}}],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="Reader", principal_display_name="SP-AZURE-Deploy"),
            ]
        )
        report = check_compliance(policy, scan)
        assert "must-have-azure" not in [f.rule_id for f in report.findings]

    # ── Case insensitive ─────────────────────────────────────

    def test_name_prefix_case_insensitive(self):
        policy = make_policy(
            rules=[{"name": "perm-groups", "severity": "info", "match": {"principal_name_prefix": "grp-perm-"}}],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="Reader", principal_display_name="GRP-PERM-Readers"),
            ]
        )
        report = check_compliance(policy, scan)
        assert "perm-groups" in [f.rule_id for f in report.findings]

    def test_name_contains_case_insensitive(self):
        policy = make_policy(
            rules=[{"name": "no-temp", "severity": "medium", "match": {"principal_name_contains": "temp"}}],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="Reader", principal_display_name="GRP-TEMP-Deploy"),
            ]
        )
        report = check_compliance(policy, scan)
        assert "no-temp" in [f.rule_id for f in report.findings]

    # ── Unresolved name → no match ───────────────────────────

    def test_name_prefix_unresolved_no_match(self):
        """When display name is None, principal_name_prefix returns False."""
        policy = make_policy(
            rules=[{"name": "perm-groups", "severity": "info", "match": {"principal_name_prefix": "GRP-PERM-"}}],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="Reader"),  # no display name
            ]
        )
        report = check_compliance(policy, scan)
        assert "perm-groups" not in [f.rule_id for f in report.findings]

    def test_name_not_prefix_unresolved_no_match(self):
        """When display name is None, principal_name_not_prefix returns False (no false positives)."""
        policy = make_policy(
            rules=[{"name": "only-perm", "severity": "high", "match": {"principal_name_not_prefix": "GRP-PERM-"}}],
        )
        scan = make_scan_result(
            [
                make_assignment(role_name="Reader"),  # no display name
            ]
        )
        report = check_compliance(policy, scan)
        assert "only-perm" not in [f.rule_id for f in report.findings]

    # ── AND combination ──────────────────────────────────────

    def test_and_with_principal_type(self):
        """principal_name_not_prefix + principal_type combined."""
        policy = make_policy(
            rules=[
                {
                    "name": "non-perm-groups",
                    "severity": "high",
                    "match": {"principal_type": "Group", "principal_name_not_prefix": "GRP-PERM-"},
                }
            ],
        )
        # User with non-perm name → no match (principal_type doesn't match)
        scan = make_scan_result(
            [
                make_assignment(
                    principal_type=PrincipalType.USER,
                    role_name="Reader",
                    principal_display_name="John Doe",
                ),
            ]
        )
        report = check_compliance(policy, scan)
        assert "non-perm-groups" not in [f.rule_id for f in report.findings]

    def test_and_with_scope_prefix(self):
        """principal_name_contains + scope_prefix combined."""
        policy = make_policy(
            rules=[
                {
                    "name": "temp-on-prod",
                    "severity": "critical",
                    "match": {
                        "scope_prefix": f"/subscriptions/{VALID_SUB_ID}",
                        "principal_name_contains": "TEMP",
                    },
                }
            ],
        )
        scan = make_scan_result(
            [
                make_assignment(
                    role_name="Reader",
                    principal_display_name="GRP-TEMP-Deploy",
                    scope=f"/subscriptions/{VALID_SUB_ID}/resourceGroups/rg-prod",
                ),
            ]
        )
        report = check_compliance(policy, scan)
        assert "temp-on-prod" in [f.rule_id for f in report.findings]


# ── TestRemediation ─────────────────────────────────────────


class TestRemediation:
    """Tests for remediation hint propagation in findings."""

    def test_governance_rule_remediation_propagated(self):
        """Governance rule with remediation → finding.details has remediation."""
        policy = make_policy(
            rules=[
                {
                    "name": "no-direct-users",
                    "type": "governance",
                    "match": {"principal_type": "User"},
                    "remediation": "Use groups instead",
                },
            ]
        )
        scan = make_scan_result([make_assignment()])
        report = check_compliance(policy, scan)
        assert len(report.findings) == 1
        assert report.findings[0].details.get("remediation") == "Use groups instead"

    def test_governance_rule_without_remediation(self):
        """Governance rule without remediation → details has no remediation key."""
        policy = make_policy(
            rules=[
                {
                    "name": "no-direct-users",
                    "type": "governance",
                    "match": {"principal_type": "User"},
                },
            ]
        )
        scan = make_scan_result([make_assignment()])
        report = check_compliance(policy, scan)
        assert len(report.findings) == 1
        assert "remediation" not in report.findings[0].details

    def test_out_of_baseline_has_default_remediation(self):
        """OUT_OF_BASELINE findings have default remediation."""
        policy = make_policy(
            rules=[
                {
                    "name": "allow-nothing",
                    "type": "baseline",
                    "match": {"role": "NonExistent"},
                },
            ]
        )
        scan = make_scan_result([make_assignment()])
        report = check_compliance(policy, scan)
        oob = [f for f in report.findings if f.rule_id == OUT_OF_BASELINE]
        assert len(oob) == 1
        assert "remediation" in oob[0].details


# ── TestWarningsPropagation ─────────────────────────────────


class TestWarningsPropagation:
    """Tests for scan warnings propagated to ComplianceReport."""

    def test_warnings_from_scan_result(self):
        """Warnings from RbacScanResult appear in ComplianceReport."""
        from az_rbac_watch.scanner.rbac_scanner import RbacScanResult, SubscriptionScanResult

        scan = RbacScanResult(
            subscription_results=[
                SubscriptionScanResult(
                    subscription_id=VALID_SUB_ID,
                    subscription_name="Sub",
                )
            ],
            warnings=["Graph API unavailable"],
        )
        policy = make_policy()
        report = check_compliance(policy, scan)
        assert report.warnings == ["Graph API unavailable"]

    def test_no_warnings_by_default(self):
        """No warnings when scan has none."""
        scan = make_scan_result([])
        policy = make_policy()
        report = check_compliance(policy, scan)
        assert report.warnings == []
