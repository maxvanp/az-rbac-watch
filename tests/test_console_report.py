"""Tests for the Rich console reporter."""

from __future__ import annotations

from datetime import UTC, datetime
from io import StringIO
from pathlib import Path

from rich.console import Console

from az_rbac_watch.analyzers.compliance import (
    GOVERNANCE_VIOLATION,
    OUT_OF_BASELINE,
    ComplianceFinding,
    ComplianceReport,
    ComplianceSummary,
    Severity,
)
from az_rbac_watch.config.policy_model import PolicyModel, Rule, RuleMatch
from az_rbac_watch.reporters.console_report import (
    print_compliance_report,
    print_discover_summary,
    print_drift_report,
)

TENANT_ID = "11111111-1111-1111-1111-111111111111"


def _make_console() -> tuple[Console, StringIO]:
    """Create a Rich console capturing output to a StringIO (no color)."""
    buf = StringIO()
    console = Console(file=buf, highlight=False, no_color=True, width=200)
    return console, buf


def _empty_report() -> ComplianceReport:
    return ComplianceReport(
        policy_version="2.0",
        tenant_id=TENANT_ID,
        scan_timestamp=datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC),
        findings=[],
        summary=ComplianceSummary(
            total_assignments_checked=5,
            total_findings=0,
            drift_count=0,
            violation_count=0,
        ),
        scan_errors=[],
    )


def _report_with_findings() -> ComplianceReport:
    return ComplianceReport(
        policy_version="2.0",
        tenant_id=TENANT_ID,
        scan_timestamp=datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC),
        findings=[
            ComplianceFinding(
                rule_id=OUT_OF_BASELINE,
                severity=Severity.HIGH,
                message="Unauthorized assignment",
                principal_id="aaaa-bbbb",
                role_name="Contributor",
                scope="/subscriptions/sub1",
            ),
            ComplianceFinding(
                rule_id="no-direct-users",
                severity=Severity.MEDIUM,
                message="Governance rule violation",
                principal_id="cccc-dddd",
                role_name="Reader",
                scope="/subscriptions/sub2",
            ),
        ],
        summary=ComplianceSummary(
            total_assignments_checked=10,
            total_findings=2,
            findings_by_severity={"high": 1, "medium": 1},
            drift_count=1,
            violation_count=1,
        ),
        scan_errors=[],
    )


# ── Tests print_compliance_report ────────────────────────────


class TestPrintComplianceReportEmpty:
    def test_empty_report_shows_compliant(self) -> None:
        console, buf = _make_console()
        report = _empty_report()
        print_compliance_report(report, console=console)
        output = buf.getvalue()
        assert "Compliant" in output
        assert "no findings" in output.lower()

    def test_empty_report_shows_header(self) -> None:
        console, buf = _make_console()
        report = _empty_report()
        print_compliance_report(report, console=console)
        output = buf.getvalue()
        assert TENANT_ID in output
        assert "2.0" in output

    def test_empty_report_shows_summary(self) -> None:
        console, buf = _make_console()
        report = _empty_report()
        print_compliance_report(report, console=console)
        output = buf.getvalue()
        assert "5" in output  # total_assignments_checked


class TestPrintComplianceReportWithFindings:
    def test_findings_shows_count(self) -> None:
        console, buf = _make_console()
        report = _report_with_findings()
        print_compliance_report(report, console=console)
        output = buf.getvalue()
        assert "2 finding(s) detected" in output

    def test_findings_shows_rule_ids(self) -> None:
        console, buf = _make_console()
        report = _report_with_findings()
        print_compliance_report(report, console=console)
        output = buf.getvalue()
        assert OUT_OF_BASELINE in output
        assert "no-direct-users" in output

    def test_findings_shows_principals(self) -> None:
        console, buf = _make_console()
        report = _report_with_findings()
        print_compliance_report(report, console=console)
        output = buf.getvalue()
        assert "aaaa-bbbb" in output
        assert "cccc-dddd" in output

    def test_findings_shows_roles(self) -> None:
        console, buf = _make_console()
        report = _report_with_findings()
        print_compliance_report(report, console=console)
        output = buf.getvalue()
        assert "Contributor" in output
        assert "Reader" in output

    def test_summary_shows_drift_and_violations(self) -> None:
        console, buf = _make_console()
        report = _report_with_findings()
        print_compliance_report(report, console=console)
        output = buf.getvalue()
        assert "undeclared" in output.lower()
        assert "guardrail" in output.lower()


class TestPrintComplianceReportDisplayName:
    def test_display_name_shown_when_available(self) -> None:
        console, buf = _make_console()
        report = _report_with_findings()
        report.findings[0].principal_display_name = "GRP-TEAM-INFRA"
        print_compliance_report(report, console=console)
        output = buf.getvalue()
        assert "GRP-TEAM-INFRA" in output
        assert "aaaa-bbbb" in output


class TestPrintComplianceReportWithErrors:
    def test_scan_errors_displayed(self) -> None:
        console, buf = _make_console()
        report = _empty_report()
        report.scan_errors = ["Access error on subscription X", "API Timeout"]
        print_compliance_report(report, console=console)
        output = buf.getvalue()
        assert "Access" in output
        assert "Timeout" in output

    def test_scan_errors_panel_title(self) -> None:
        console, buf = _make_console()
        report = _empty_report()
        report.scan_errors = ["Network error"]
        print_compliance_report(report, console=console)
        output = buf.getvalue()
        assert "Scan errors" in output


# ── Tests print_discover_summary ─────────────────────────────


class TestPrintDiscoverSummary:
    def test_shows_baseline_rule_count(self) -> None:
        console, buf = _make_console()
        policy = PolicyModel(
            version="2.0",
            tenant_id=TENANT_ID,
            rules=[
                Rule(
                    name="user-reader",
                    type="baseline",
                    match=RuleMatch(principal_id="aaa", role="Reader", scope="/subscriptions/sub1"),
                ),
                Rule(
                    name="group-contributor",
                    type="baseline",
                    match=RuleMatch(principal_id="bbb", role="Contributor", scope="/subscriptions/sub2"),
                ),
            ],
        )
        print_discover_summary(policy, Path("output.yaml"), console=console)
        output = buf.getvalue()
        assert "2" in output
        assert "baseline" in output
        assert "discovered" in output

    def test_shows_output_path(self) -> None:
        console, buf = _make_console()
        policy = PolicyModel(version="2.0", tenant_id=TENANT_ID)
        print_discover_summary(policy, Path("/tmp/discovered.yaml"), console=console)
        output = buf.getvalue()
        assert "/tmp/discovered.yaml" in output

    def test_shows_review_reminder(self) -> None:
        console, buf = _make_console()
        policy = PolicyModel(version="2.0", tenant_id=TENANT_ID)
        print_discover_summary(policy, Path("out.yaml"), console=console)
        output = buf.getvalue()
        assert "Review" in output


# ── TestWarningsPanel ────────────────────────────────────────


class TestWarningsPanel:
    """Tests for warnings display in console report."""

    def test_no_warnings_no_panel(self) -> None:
        """No warnings → no Warnings panel."""
        console, buf = _make_console()
        report = _empty_report()
        print_compliance_report(report, console=console)
        output = buf.getvalue()
        assert "Warnings" not in output

    def test_warnings_shown(self) -> None:
        """Warnings → Warnings panel with content."""
        console, buf = _make_console()
        report = _empty_report()
        report.warnings = ["Graph API indisponible"]
        print_compliance_report(report, console=console)
        output = buf.getvalue()
        assert "Warnings" in output
        assert "Graph API indisponible" in output

    def test_multiple_warnings(self) -> None:
        console, buf = _make_console()
        report = _empty_report()
        report.warnings = ["Warning 1", "Warning 2"]
        print_compliance_report(report, console=console)
        output = buf.getvalue()
        assert "Warning 1" in output
        assert "Warning 2" in output


# ── TestRemediationHint ──────────────────────────────────────


class TestRemediationHint:
    """Tests for remediation hint display in console report."""

    def test_remediation_in_output(self) -> None:
        """Finding with remediation → shown in output."""
        console, buf = _make_console()
        report = _empty_report()
        report.findings = [
            ComplianceFinding(
                rule_id=GOVERNANCE_VIOLATION,
                severity=Severity.HIGH,
                message="test",
                role_name="Owner",
                scope="/subscriptions/sub-1",
                details={"remediation": "Remove Owner role"},
            ),
        ]
        report.summary.total_findings = 1
        print_compliance_report(report, console=console)
        output = buf.getvalue()
        assert "Remove Owner role" in output

    def test_no_remediation_no_hint(self) -> None:
        """Finding without remediation → no remediation line."""
        console, buf = _make_console()
        report = _empty_report()
        report.findings = [
            ComplianceFinding(
                rule_id=GOVERNANCE_VIOLATION,
                severity=Severity.HIGH,
                message="test",
                role_name="Owner",
                scope="/subscriptions/sub-1",
            ),
        ]
        report.summary.total_findings = 1
        print_compliance_report(report, console=console)
        output = buf.getvalue()
        assert "Remediation" not in output


# ── TestConsolePortalLinks ─────────────────────────────────


def _make_markup_console() -> tuple[Console, StringIO]:
    """Create a Rich console that preserves markup (for link assertions)."""
    buf = StringIO()
    console = Console(file=buf, highlight=False, no_color=True, width=200, markup=True)
    return console, buf


class TestConsolePortalLinks:
    """Tests for Azure Portal link markup in console output."""

    @staticmethod
    def _make_link_console() -> tuple[Console, StringIO]:
        """Console with force_terminal so Rich emits OSC 8 hyperlink sequences."""
        buf = StringIO()
        console = Console(file=buf, highlight=False, force_terminal=True, width=200)
        return console, buf

    def test_scope_link_in_output(self) -> None:
        """Rich link markup appears for scope."""
        console, buf = self._make_link_console()
        report = _report_with_findings()
        print_drift_report(report, console=console)
        output = buf.getvalue()
        assert "portal.azure.com" in output

    def test_principal_link_in_output(self) -> None:
        """Rich link markup appears for principal."""
        console, buf = self._make_link_console()
        report = _report_with_findings()
        print_drift_report(report, console=console)
        output = buf.getvalue()
        assert "ManagedAppMenuBlade" in output
