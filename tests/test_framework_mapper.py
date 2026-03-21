"""Tests for the framework mapper and models.

Covers: FrameworkMapper, load_framework_definition, CIS YAML loading,
and framework HTML report generation.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from az_rbac_watch.analyzers.compliance import (
    ComplianceFinding,
    ComplianceReport,
    ComplianceSummary,
    Severity,
)
from az_rbac_watch.frameworks.mapper import FrameworkMapper, load_framework_definition
from az_rbac_watch.frameworks.models import (
    FrameworkComplianceReport,
    FrameworkControl,
    FrameworkDefinition,
)
from az_rbac_watch.reporters.html_report import generate_framework_html_report

TENANT = "11111111-1111-1111-1111-111111111111"


def _sample_framework() -> FrameworkDefinition:
    """A minimal framework with 3 controls."""
    return FrameworkDefinition(
        name="Test Framework",
        version="1.0",
        section="IAM",
        controls=[
            FrameworkControl(
                id="T-1",
                title="No owners",
                description="Limit owners",
                severity="critical",
                rule_names=["no-owner"],
            ),
            FrameworkControl(
                id="T-2",
                title="No guests",
                description="Block guest admin",
                severity="high",
                rule_names=["no-guest-admin"],
            ),
            FrameworkControl(
                id="T-3",
                title="MFA required",
                description="Requires MFA",
                severity="critical",
                rule_names=[],  # manual
            ),
        ],
    )


def _empty_report() -> ComplianceReport:
    return ComplianceReport(
        policy_version="2.0",
        tenant_id=TENANT,
        scan_timestamp=datetime(2026, 1, 15, 10, 0, 0, tzinfo=UTC),
        findings=[],
        summary=ComplianceSummary(total_assignments_checked=10),
    )


def _report_with_findings() -> ComplianceReport:
    findings = [
        ComplianceFinding(
            rule_id="no-owner",
            severity=Severity.CRITICAL,
            message="Owner at sub",
            principal_id="user-1",
            principal_type="User",
            role_name="Owner",
            scope="/subscriptions/sub-1",
        ),
        ComplianceFinding(
            rule_id="no-owner",
            severity=Severity.CRITICAL,
            message="Owner at sub",
            principal_id="user-2",
            principal_type="User",
            role_name="Owner",
            scope="/subscriptions/sub-1",
        ),
        ComplianceFinding(
            rule_id="no-guest-admin",
            severity=Severity.HIGH,
            message="Guest admin",
            principal_id="guest-1",
            principal_type="Guest",
            role_name="Contributor",
            scope="/subscriptions/sub-1",
        ),
    ]
    return ComplianceReport(
        policy_version="2.0",
        tenant_id=TENANT,
        scan_timestamp=datetime(2026, 1, 15, 10, 0, 0, tzinfo=UTC),
        findings=findings,
        summary=ComplianceSummary(
            total_assignments_checked=20,
            total_findings=3,
            findings_by_severity={"critical": 2, "high": 1},
        ),
    )


# ── FrameworkMapper tests ────────────────────────────────────


class TestFrameworkMapper:
    def test_all_passing(self) -> None:
        """No findings → all automatable controls pass."""
        mapper = FrameworkMapper(_sample_framework())
        result = mapper.map_report(_empty_report())
        assert result.compliance_score == 100
        assert result.passing_controls == 2
        assert result.failing_controls == 0
        assert result.total_findings == 0

    def test_manual_controls_excluded_from_score(self) -> None:
        """Manual controls don't affect the compliance score."""
        mapper = FrameworkMapper(_sample_framework())
        result = mapper.map_report(_empty_report())
        manual = [r for r in result.control_results if r.status == "manual"]
        assert len(manual) == 1
        assert manual[0].control.id == "T-3"

    def test_failing_controls(self) -> None:
        """Findings mapped → controls fail."""
        mapper = FrameworkMapper(_sample_framework())
        result = mapper.map_report(_report_with_findings())
        assert result.failing_controls == 2
        assert result.passing_controls == 0
        assert result.compliance_score == 0

    def test_finding_count_per_control(self) -> None:
        """Each control gets its matching findings."""
        mapper = FrameworkMapper(_sample_framework())
        result = mapper.map_report(_report_with_findings())
        by_id = {r.control.id: r for r in result.control_results}
        assert by_id["T-1"].finding_count == 2
        assert by_id["T-2"].finding_count == 1
        assert by_id["T-3"].finding_count == 0

    def test_total_findings(self) -> None:
        mapper = FrameworkMapper(_sample_framework())
        result = mapper.map_report(_report_with_findings())
        assert result.total_findings == 3

    def test_severity_breakdown(self) -> None:
        mapper = FrameworkMapper(_sample_framework())
        result = mapper.map_report(_report_with_findings())
        assert result.findings_by_severity["critical"] == 2
        assert result.findings_by_severity["high"] == 1

    def test_partial_pass(self) -> None:
        """One control fails, one passes → 50% score."""
        findings = [
            ComplianceFinding(
                rule_id="no-owner",
                severity=Severity.CRITICAL,
                message="test",
                principal_id="p1",
                role_name="Owner",
                scope="/subscriptions/sub-1",
            ),
        ]
        report = ComplianceReport(
            policy_version="2.0",
            tenant_id=TENANT,
            scan_timestamp=datetime(2026, 1, 15, 10, 0, 0, tzinfo=UTC),
            findings=findings,
            summary=ComplianceSummary(total_assignments_checked=10, total_findings=1),
        )
        mapper = FrameworkMapper(_sample_framework())
        result = mapper.map_report(report)
        assert result.passing_controls == 1
        assert result.failing_controls == 1
        assert result.compliance_score == 50

    def test_framework_metadata(self) -> None:
        mapper = FrameworkMapper(_sample_framework())
        result = mapper.map_report(_empty_report())
        assert result.framework.name == "Test Framework"
        assert result.tenant_id == TENANT

    def test_empty_framework(self) -> None:
        """Framework with no controls → 100% score."""
        fw = FrameworkDefinition(name="Empty", version="0", section="", controls=[])
        mapper = FrameworkMapper(fw)
        result = mapper.map_report(_empty_report())
        assert result.compliance_score == 100
        assert result.total_controls == 0


# ── load_framework_definition tests ──────────────────────────


class TestLoadFrameworkDefinition:
    def test_load_builtin_cis(self) -> None:
        """Load the built-in CIS framework."""
        fw = load_framework_definition("CIS")
        assert "CIS" in fw.name
        assert fw.version == "1.4.0"
        assert len(fw.controls) == 13

    def test_load_builtin_case_insensitive(self) -> None:
        fw = load_framework_definition("cis")
        assert "CIS" in fw.name

    def test_load_nonexistent_raises(self) -> None:
        with pytest.raises(FileNotFoundError, match="not found"):
            load_framework_definition("nonexistent-framework")

    def test_load_from_yaml_path(self, tmp_path: Path) -> None:
        yaml_content = """
framework:
  name: "Custom Framework"
  version: "1.0"
  section: "Test"

controls:
  - id: "C-1"
    title: "Test control"
    severity: "high"
    rule_names:
      - my-rule
"""
        yaml_file = tmp_path / "custom.yaml"
        yaml_file.write_text(yaml_content, encoding="utf-8")

        fw = load_framework_definition(str(yaml_file))
        assert fw.name == "Custom Framework"
        assert len(fw.controls) == 1
        assert fw.controls[0].rule_names == ["my-rule"]

    def test_invalid_yaml_raises(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "bad.yaml"
        yaml_file.write_text(": :\n  - bad yaml: [", encoding="utf-8")

        with pytest.raises(ValueError, match="YAML"):
            load_framework_definition(str(yaml_file))

    def test_non_dict_raises(self, tmp_path: Path) -> None:
        yaml_file = tmp_path / "list.yaml"
        yaml_file.write_text("- item1\n- item2\n", encoding="utf-8")

        with pytest.raises(ValueError, match="mapping"):
            load_framework_definition(str(yaml_file))


# ── CIS YAML integrity tests ────────────────────────────────


class TestCisYamlIntegrity:
    def test_all_controls_have_ids(self) -> None:
        fw = load_framework_definition("CIS")
        for c in fw.controls:
            assert c.id.startswith("CIS-")

    def test_automatable_controls_have_rule_names(self) -> None:
        """Controls CIS-1.2 through CIS-1.7 should have rule_names."""
        fw = load_framework_definition("CIS")
        by_id = {c.id: c for c in fw.controls}
        for cid in ["CIS-1.2", "CIS-1.3", "CIS-1.4", "CIS-1.5", "CIS-1.6", "CIS-1.7"]:
            assert len(by_id[cid].rule_names) > 0, f"{cid} should have rule_names"

    def test_manual_controls_empty_rule_names(self) -> None:
        """Manual controls should have empty rule_names."""
        fw = load_framework_definition("CIS")
        by_id = {c.id: c for c in fw.controls}
        for cid in ["CIS-1.1", "CIS-1.8", "CIS-1.9", "CIS-1.10", "CIS-1.11", "CIS-1.12", "CIS-1.13"]:
            assert len(by_id[cid].rule_names) == 0, f"{cid} should be manual"

    def test_severities_valid(self) -> None:
        fw = load_framework_definition("CIS")
        valid = {"critical", "high", "medium", "low", "info"}
        for c in fw.controls:
            assert c.severity in valid, f"{c.id} has invalid severity: {c.severity}"


# ── Framework HTML report tests ──────────────────────────────


class TestFrameworkHtmlReport:
    def _make_fw_report(self) -> FrameworkComplianceReport:
        fw = _sample_framework()
        mapper = FrameworkMapper(fw)
        return mapper.map_report(_report_with_findings())

    def test_generates_valid_html(self, tmp_path: Path) -> None:
        out = tmp_path / "fw_report.html"
        generate_framework_html_report(self._make_fw_report(), out)
        html = out.read_text(encoding="utf-8")
        assert html.startswith("<!DOCTYPE html>")

    def test_contains_framework_name(self, tmp_path: Path) -> None:
        out = tmp_path / "fw_report.html"
        generate_framework_html_report(self._make_fw_report(), out)
        html = out.read_text(encoding="utf-8")
        assert "Test Framework" in html

    def test_contains_controls_table(self, tmp_path: Path) -> None:
        out = tmp_path / "fw_report.html"
        generate_framework_html_report(self._make_fw_report(), out)
        html = out.read_text(encoding="utf-8")
        assert "T-1" in html
        assert "T-2" in html
        assert "T-3" in html

    def test_pass_fail_badges(self, tmp_path: Path) -> None:
        out = tmp_path / "fw_report.html"
        generate_framework_html_report(self._make_fw_report(), out)
        html = out.read_text(encoding="utf-8")
        assert "badge-fail" in html
        assert "badge-manual" in html

    def test_failing_control_detail(self, tmp_path: Path) -> None:
        out = tmp_path / "fw_report.html"
        generate_framework_html_report(self._make_fw_report(), out)
        html = out.read_text(encoding="utf-8")
        assert "user-1" in html
        assert "Owner" in html

    def test_compliance_score_displayed(self, tmp_path: Path) -> None:
        out = tmp_path / "fw_report.html"
        generate_framework_html_report(self._make_fw_report(), out)
        html = out.read_text(encoding="utf-8")
        assert "0%" in html  # all controls fail

    def test_all_passing_report(self, tmp_path: Path) -> None:
        fw = _sample_framework()
        mapper = FrameworkMapper(fw)
        fw_report = mapper.map_report(_empty_report())
        out = tmp_path / "fw_report.html"
        generate_framework_html_report(fw_report, out)
        html = out.read_text(encoding="utf-8")
        assert "100%" in html
        assert "badge-pass" in html

    def test_donut_chart_present(self, tmp_path: Path) -> None:
        out = tmp_path / "fw_report.html"
        generate_framework_html_report(self._make_fw_report(), out)
        html = out.read_text(encoding="utf-8")
        assert "donut-chart" in html

    def test_remediation_shown(self, tmp_path: Path) -> None:
        fw = FrameworkDefinition(
            name="Test",
            version="1.0",
            section="Test",
            controls=[
                FrameworkControl(
                    id="R-1",
                    title="Remediation test",
                    severity="high",
                    rule_names=["rule-1"],
                    remediation="Fix this issue by doing X.",
                ),
            ],
        )
        findings = [
            ComplianceFinding(
                rule_id="rule-1",
                severity=Severity.HIGH,
                message="test",
                principal_id="p1",
                role_name="Owner",
                scope="/subscriptions/sub-1",
            ),
        ]
        report = ComplianceReport(
            policy_version="2.0",
            tenant_id=TENANT,
            scan_timestamp=datetime(2026, 1, 15, 10, 0, 0, tzinfo=UTC),
            findings=findings,
            summary=ComplianceSummary(total_findings=1),
        )
        mapper = FrameworkMapper(fw)
        fw_report = mapper.map_report(report)
        out = tmp_path / "fw_report.html"
        generate_framework_html_report(fw_report, out)
        html = out.read_text(encoding="utf-8")
        assert "Fix this issue by doing X." in html
