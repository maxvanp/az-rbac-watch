"""Tests for the HTML report generator."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from az_rbac_watch.analyzers.compliance import (
    GOVERNANCE_VIOLATION,
    OUT_OF_BASELINE,
    ComplianceFinding,
    ComplianceReport,
    ComplianceSummary,
    Severity,
)
from az_rbac_watch.reporters.html_report import _truncate_scope, generate_html_report

SUB_1 = "11111111-1111-1111-1111-111111111111"
SUB_2 = "22222222-2222-2222-2222-222222222222"


def _empty_report() -> ComplianceReport:
    """Rapport conforme sans findings."""
    return ComplianceReport(
        policy_version="2.0",
        tenant_id="aaaa-bbbb-cccc",
        scan_timestamp=datetime(2026, 1, 15, 10, 30, 0, tzinfo=UTC),
        findings=[],
        summary=ComplianceSummary(total_assignments_checked=10),
    )


def _report_with_findings() -> ComplianceReport:
    """Rapport avec des findings de plusieurs sévérités dans un seul scope."""
    findings = [
        ComplianceFinding(
            rule_id=OUT_OF_BASELINE,
            severity=Severity.HIGH,
            message="Assignation non autorisée",
            principal_id="user-1111",
            principal_type="User",
            role_name="Contributor",
            scope=f"/subscriptions/{SUB_1}/resourceGroups/rg-infra",
        ),
        ComplianceFinding(
            rule_id="no-direct-users",
            severity=Severity.MEDIUM,
            message="Violation de règle governance",
            principal_id="group-2222",
            principal_type="Group",
            role_name="Reader",
            scope=f"/subscriptions/{SUB_1}/resourceGroups/rg-dev",
        ),
    ]
    return ComplianceReport(
        policy_version="2.0",
        tenant_id="aaaa-bbbb-cccc",
        scan_timestamp=datetime(2026, 1, 15, 10, 30, 0, tzinfo=UTC),
        findings=findings,
        summary=ComplianceSummary(
            total_assignments_checked=20,
            total_findings=2,
            drift_count=1,
            violation_count=1,
            findings_by_severity={"high": 1, "medium": 1},
        ),
    )


def _report_multi_scope() -> ComplianceReport:
    """Rapport avec findings sur 2 subscriptions différentes."""
    findings = [
        ComplianceFinding(
            rule_id=OUT_OF_BASELINE,
            severity=Severity.HIGH,
            message="Assignation non autorisée",
            principal_id="user-1111",
            principal_type="User",
            role_name="Owner",
            scope=f"/subscriptions/{SUB_1}",
        ),
        ComplianceFinding(
            rule_id=OUT_OF_BASELINE,
            severity=Severity.HIGH,
            message="Assignation non autorisée",
            principal_id="user-3333",
            principal_type="User",
            role_name="Contributor",
            scope=f"/subscriptions/{SUB_1}/resourceGroups/rg-infra",
        ),
        ComplianceFinding(
            rule_id="no-direct-users",
            severity=Severity.MEDIUM,
            message="Violation de règle governance",
            principal_id="group-4444",
            principal_type="Group",
            role_name="Reader",
            scope=f"/subscriptions/{SUB_2}/resourceGroups/rg-dev",
        ),
    ]
    return ComplianceReport(
        policy_version="2.0",
        tenant_id="aaaa-bbbb-cccc",
        scan_timestamp=datetime(2026, 1, 15, 10, 30, 0, tzinfo=UTC),
        findings=findings,
        summary=ComplianceSummary(
            total_assignments_checked=40,
            total_findings=3,
            drift_count=2,
            violation_count=1,
            findings_by_severity={"high": 2, "medium": 1},
        ),
    )


def _report_with_errors() -> ComplianceReport:
    """Rapport avec des erreurs de scan."""
    return ComplianceReport(
        policy_version="2.0",
        tenant_id="aaaa-bbbb-cccc",
        scan_timestamp=datetime(2026, 1, 15, 10, 30, 0, tzinfo=UTC),
        findings=[],
        summary=ComplianceSummary(total_assignments_checked=5),
        scan_errors=["Subscription sub-x : accès refusé", "Timeout sur sub-y"],
    )


# ── Tests rapport vide ─────────────────────────────────────


class TestEmptyReport:
    def test_generates_valid_html(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_empty_report(), out)
        html = out.read_text(encoding="utf-8")
        assert html.startswith("<!DOCTYPE html>")
        assert 'charset="utf-8"' in html.lower() or "charset=utf-8" in html.lower()

    def test_contains_compliant(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_empty_report(), out)
        html = out.read_text(encoding="utf-8")
        assert "Compliant" in html or "no findings" in html.lower()

    def test_contains_header_info(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_empty_report(), out)
        html = out.read_text(encoding="utf-8")
        assert "aaaa-bbbb-cccc" in html
        assert "2.0" in html
        assert "2026-01-15" in html

    def test_no_findings_table(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_empty_report(), out)
        html = out.read_text(encoding="utf-8")
        assert "<tbody>" not in html

    def test_no_toc_without_findings(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_empty_report(), out)
        html = out.read_text(encoding="utf-8")
        assert "Findings by scope" not in html


# ── Tests rapport avec findings (1 scope) ──────────────────


class TestReportWithFindings:
    def test_file_written(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_report_with_findings(), out)
        assert out.exists()
        assert out.stat().st_size > 0

    def test_contains_rule_ids(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_report_with_findings(), out)
        html = out.read_text(encoding="utf-8")
        assert OUT_OF_BASELINE in html
        assert "no-direct-users" in html

    def test_contains_principals(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_report_with_findings(), out)
        html = out.read_text(encoding="utf-8")
        assert "user-1111" in html
        assert "group-2222" in html

    def test_contains_roles(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_report_with_findings(), out)
        html = out.read_text(encoding="utf-8")
        assert "Contributor" in html
        assert "Reader" in html

    def test_contains_scopes(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_report_with_findings(), out)
        html = out.read_text(encoding="utf-8")
        assert f"/subscriptions/{SUB_1}" in html
        assert "rg-dev" in html

    def test_verdict_shows_count(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_report_with_findings(), out)
        html = out.read_text(encoding="utf-8")
        assert "2 finding(s)" in html

    def test_severity_css_classes(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_report_with_findings(), out)
        html = out.read_text(encoding="utf-8")
        assert "severity-high" in html
        assert "severity-medium" in html

    def test_severity_colors_present(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_report_with_findings(), out)
        html = out.read_text(encoding="utf-8")
        assert "#e74c3c" in html  # HIGH
        assert "#f39c12" in html  # MEDIUM

    def test_findings_sorted_by_severity(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_report_with_findings(), out)
        html = out.read_text(encoding="utf-8")
        high_pos = html.index("severity-high")
        medium_pos = html.index("severity-medium")
        assert high_pos < medium_pos

    def test_html_structure(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_report_with_findings(), out)
        html = out.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in html
        assert "<table>" in html
        assert "</table>" in html
        assert "<thead>" in html
        assert "<tbody>" in html

    def test_no_toc_single_scope(self, tmp_path: Path) -> None:
        """Pas de sommaire quand tous les findings sont dans le même scope."""
        out = tmp_path / "report.html"
        generate_html_report(_report_with_findings(), out)
        html = out.read_text(encoding="utf-8")
        assert "Findings by scope" not in html

    def test_scope_group_header(self, tmp_path: Path) -> None:
        """Le header de groupe scope est présent avec le count badge."""
        out = tmp_path / "report.html"
        generate_html_report(_report_with_findings(), out)
        html = out.read_text(encoding="utf-8")
        assert "count-badge" in html
        assert "2 finding(s)" in html

    def test_scope_names_in_header(self, tmp_path: Path) -> None:
        """Le nom de la subscription apparaît si scope_names est fourni."""
        out = tmp_path / "report.html"
        generate_html_report(
            _report_with_findings(),
            out,
            scope_names={SUB_1.lower(): "Production"},
        )
        html = out.read_text(encoding="utf-8")
        assert "Production" in html


class TestReportDisplayName:
    def test_display_name_shown_in_html(self, tmp_path: Path) -> None:
        """Display name appears with principal_id when available."""
        report = _report_with_findings()
        report.findings[0].principal_display_name = "GRP-TEAM-INFRA"
        out = tmp_path / "report.html"
        generate_html_report(report, out)
        html = out.read_text(encoding="utf-8")
        assert "GRP-TEAM-INFRA" in html
        assert "user-1111" in html


# ── Tests rapport multi-scope (TOC) ────────────────────────


class TestReportMultiScope:
    def test_toc_present(self, tmp_path: Path) -> None:
        """Le sommaire apparaît quand il y a 2+ scope groups."""
        out = tmp_path / "report.html"
        generate_html_report(_report_multi_scope(), out)
        html = out.read_text(encoding="utf-8")
        assert "Findings by scope" in html
        assert 'id="toc"' in html

    def test_toc_links(self, tmp_path: Path) -> None:
        """Le TOC contient des liens vers les sections scope."""
        out = tmp_path / "report.html"
        generate_html_report(_report_multi_scope(), out)
        html = out.read_text(encoding="utf-8")
        assert "toc-link" in html
        assert f"scope-{SUB_1.replace('-', '-')}" in html.replace("-", "-")

    def test_toc_counts(self, tmp_path: Path) -> None:
        """Le TOC affiche les compteurs par scope."""
        out = tmp_path / "report.html"
        generate_html_report(_report_multi_scope(), out)
        html = out.read_text(encoding="utf-8")
        # SUB_1 has 2 drift, 0 violations
        # SUB_2 has 0 drift, 1 violation
        assert "Drift" in html or "drift" in html
        assert "Violation" in html or "violation" in html

    def test_back_to_top_links(self, tmp_path: Path) -> None:
        """Les liens 'Sommaire' apparaissent dans chaque section scope."""
        out = tmp_path / "report.html"
        generate_html_report(_report_multi_scope(), out)
        html = out.read_text(encoding="utf-8")
        assert "back-to-top" in html
        assert "Summary" in html

    def test_two_scope_sections(self, tmp_path: Path) -> None:
        """Deux sections scope distinctes sont générées."""
        out = tmp_path / "report.html"
        generate_html_report(_report_multi_scope(), out)
        html = out.read_text(encoding="utf-8")
        assert html.count("<tbody>") == 3  # 1 TOC + 2 scope tables

    def test_scope_names_in_toc(self, tmp_path: Path) -> None:
        """Les noms de subscription apparaissent dans le TOC."""
        out = tmp_path / "report.html"
        generate_html_report(
            _report_multi_scope(),
            out,
            scope_names={SUB_1.lower(): "Production", SUB_2.lower(): "Development"},
        )
        html = out.read_text(encoding="utf-8")
        assert "Production" in html
        assert "Development" in html

    def test_findings_grouped_correctly(self, tmp_path: Path) -> None:
        """Les findings de chaque scope sont dans la bonne section."""
        out = tmp_path / "report.html"
        generate_html_report(_report_multi_scope(), out)
        html = out.read_text(encoding="utf-8")
        # Use id= to find actual sections (not TOC links)
        sub1_section_start = html.index(f'id="scope-{SUB_1}"')
        sub2_section_start = html.index(f'id="scope-{SUB_2}"')
        user_1111_pos = html.index("user-1111")
        group_4444_pos = html.index("group-4444")
        assert sub1_section_start < user_1111_pos < sub2_section_start
        assert sub2_section_start < group_4444_pos


# ── Tests erreurs de scan ──────────────────────────────────


class TestReportWithErrors:
    def test_contains_error_section(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_report_with_errors(), out)
        html = out.read_text(encoding="utf-8")
        assert "Scan errors" in html

    def test_contains_error_messages(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_report_with_errors(), out)
        html = out.read_text(encoding="utf-8")
        assert "accès refusé" in html or "accès refusé" in html
        assert "Timeout" in html

    def test_no_error_section_when_empty(self, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        generate_html_report(_empty_report(), out)
        html = out.read_text(encoding="utf-8")
        assert "Scan errors" not in html


# ── Tests sécurité ─────────────────────────────────────────


class TestHtmlEscaping:
    def test_xss_in_principal_id(self, tmp_path: Path) -> None:
        """Vérifie que les valeurs sont échappées (pas de XSS)."""
        report = _empty_report()
        report.findings = [
            ComplianceFinding(
                rule_id=OUT_OF_BASELINE,
                severity=Severity.HIGH,
                message="test",
                principal_id='<script>alert("xss")</script>',
                role_name="Reader",
                scope="/subscriptions/sub-1",
            ),
        ]
        report.summary.total_findings = 1
        out = tmp_path / "report.html"
        generate_html_report(report, out)
        html = out.read_text(encoding="utf-8")
        assert '<script>alert("xss")</script>' not in html
        assert "&lt;script&gt;" in html


# ── TestTruncateScope ────────────────────────────────────────


class TestTruncateScope:
    def test_short_scope_unchanged(self) -> None:
        scope = "/subscriptions/sub-1"
        assert _truncate_scope(scope) == scope

    def test_long_scope_truncated(self) -> None:
        scope = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1"
        result = _truncate_scope(scope)
        assert result.startswith("...")
        assert "virtualMachines/vm-1" in result

    def test_exact_threshold(self) -> None:
        scope = "/subscriptions/sub-1/resourceGroups/rg"
        assert _truncate_scope(scope) == scope


# ── TestHtmlWarnings ─────────────────────────────────────────


class TestHtmlWarnings:
    def test_no_warnings_no_banner(self, tmp_path: Path) -> None:
        report = _empty_report()
        out = tmp_path / "report.html"
        generate_html_report(report, out)
        html = out.read_text(encoding="utf-8")
        assert "Warnings" not in html

    def test_warnings_shown(self, tmp_path: Path) -> None:
        report = _empty_report()
        report.warnings = ["Graph API indisponible"]
        out = tmp_path / "report.html"
        generate_html_report(report, out)
        html = out.read_text(encoding="utf-8")
        assert "Warnings" in html
        assert "Graph API indisponible" in html


# ── TestHtmlFiltering ────────────────────────────────────────


class TestHtmlFiltering:
    def test_filter_bar_present(self, tmp_path: Path) -> None:
        report = _report_with_findings()
        out = tmp_path / "report.html"
        generate_html_report(report, out)
        html = out.read_text(encoding="utf-8")
        assert "filter-bar" in html
        assert "toggleFilter" in html
        assert "applyFilters" in html
        assert "filter-search" in html

    def test_data_severity_attributes(self, tmp_path: Path) -> None:
        report = _report_with_findings()
        out = tmp_path / "report.html"
        generate_html_report(report, out)
        html = out.read_text(encoding="utf-8")
        assert 'data-severity="high"' in html
        assert 'data-severity="medium"' in html


# ── TestHtmlRemediation ──────────────────────────────────────


class TestHtmlRemediation:
    def test_remediation_shown(self, tmp_path: Path) -> None:
        report = _empty_report()
        report.findings = [
            ComplianceFinding(
                rule_id=GOVERNANCE_VIOLATION,
                severity=Severity.HIGH,
                message="test",
                principal_id="p1",
                role_name="Owner",
                scope=f"/subscriptions/{SUB_1}",
                details={"remediation": "Remove Owner role"},
            ),
        ]
        report.summary.total_findings = 1
        out = tmp_path / "report.html"
        generate_html_report(report, out)
        html = out.read_text(encoding="utf-8")
        assert "Remove Owner role" in html
        assert "remediation" in html

    def test_no_remediation_no_div(self, tmp_path: Path) -> None:
        report = _report_with_findings()
        out = tmp_path / "report.html"
        generate_html_report(report, out)
        html = out.read_text(encoding="utf-8")
        # Existing findings don't have remediation, so no remediation divs
        assert 'class="remediation"' not in html
