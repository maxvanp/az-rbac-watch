"""Tests for the JSON reporter."""

from __future__ import annotations

import json

from az_rbac_watch.analyzers.compliance import (
    OUT_OF_BASELINE,
    ComplianceFinding,
    ComplianceReport,
    ComplianceSummary,
    Severity,
)
from az_rbac_watch.reporters.json_report import generate_json_report

from .conftest import VALID_TENANT_ID


def _make_report(findings: list[ComplianceFinding] | None = None) -> ComplianceReport:
    return ComplianceReport(
        policy_version="2.0",
        tenant_id=VALID_TENANT_ID,
        scan_timestamp="2025-01-15T12:00:00Z",
        findings=findings or [],
        summary=ComplianceSummary(
            total_assignments_checked=10,
            total_findings=len(findings or []),
            drift_count=len(findings or []),
        ),
    )


class TestGenerateJsonReport:
    def test_valid_json(self) -> None:
        report = _make_report()
        result = generate_json_report(report)
        data = json.loads(result)
        assert isinstance(data, dict)

    def test_empty_findings(self) -> None:
        report = _make_report()
        data = json.loads(generate_json_report(report))
        assert data["findings"] == []
        assert data["summary"]["total_findings"] == 0

    def test_findings_present(self) -> None:
        findings = [
            ComplianceFinding(
                rule_id=OUT_OF_BASELINE,
                severity=Severity.HIGH,
                message="Test finding",
                principal_id="aaa",
                role_name="Owner",
                scope="/subscriptions/xxx",
            )
        ]
        data = json.loads(generate_json_report(_make_report(findings)))
        assert len(data["findings"]) == 1
        assert data["findings"][0]["rule_id"] == OUT_OF_BASELINE

    def test_enums_serialized_as_strings(self) -> None:
        findings = [
            ComplianceFinding(
                rule_id="TEST",
                severity=Severity.CRITICAL,
                message="test",
            )
        ]
        data = json.loads(generate_json_report(_make_report(findings)))
        assert data["findings"][0]["severity"] == "critical"

    def test_expected_top_level_keys(self) -> None:
        data = json.loads(generate_json_report(_make_report()))
        expected_keys = {
            "policy_version", "tenant_id", "scan_timestamp", "findings", "summary", "scan_errors", "warnings",
        }
        assert expected_keys == set(data.keys())

    def test_summary_keys(self) -> None:
        data = json.loads(generate_json_report(_make_report()))
        summary = data["summary"]
        assert "total_assignments_checked" in summary
        assert "total_findings" in summary
        assert "drift_count" in summary
        assert "violation_count" in summary

    def test_scan_errors_included(self) -> None:
        report = _make_report()
        report.scan_errors = ["API 403 error"]
        data = json.loads(generate_json_report(report))
        assert data["scan_errors"] == ["API 403 error"]

    def test_display_name_in_json(self) -> None:
        findings = [
            ComplianceFinding(
                rule_id=OUT_OF_BASELINE,
                severity=Severity.HIGH,
                message="Test finding",
                principal_id="aaa",
                principal_display_name="GRP-TEAM-INFRA",
                role_name="Owner",
                scope="/subscriptions/xxx",
            )
        ]
        data = json.loads(generate_json_report(_make_report(findings)))
        assert data["findings"][0]["principal_display_name"] == "GRP-TEAM-INFRA"
