"""Tests for the Azure Permissions Watch CLI (typer)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from typer.testing import CliRunner

from az_rbac_watch.cli import _detect_policy_file, app
from az_rbac_watch.scanner.rbac_scanner import (
    PrincipalType,
    RbacScanResult,
    ScannedRoleAssignment,
    SubscriptionScanResult,
)

runner = CliRunner()

VALID_TENANT_ID = "11111111-1111-1111-1111-111111111111"


@pytest.fixture(autouse=True)
def _mock_check_credentials() -> object:
    """Mock check_credentials for all CLI tests — avoids actual Azure calls."""
    with patch("az_rbac_watch.cli.check_credentials", return_value=True):
        yield
VALID_SUB_ID = "22222222-2222-2222-2222-222222222222"
VALID_SUB_ID_2 = "33333333-3333-3333-3333-333333333333"


def _write_policy(
    tmp_path: Path,
    *,
    with_baseline_rules: bool = False,
    with_governance_rules: bool = False,
    with_mg: bool = False,
    sub_ids: list[str] | None = None,
    scope: str | None = None,
    exclude_subscriptions: list[str] | None = None,
    exclude_management_groups: list[str] | None = None,
) -> Path:
    """Write a minimal v2.0 policy YAML file in tmp_path."""
    subs = [{"id": sid, "name": f"Sub-{i}"} for i, sid in enumerate(sub_ids or [VALID_SUB_ID])]
    data: dict = {
        "version": "2.0",
        "tenant_id": VALID_TENANT_ID,
        "subscriptions": subs,
    }
    if scope is not None:
        data["scope"] = scope
    if with_mg:
        data["management_groups"] = [{"id": "mg-test", "name": "Test MG"}]
    if exclude_subscriptions:
        data["exclude_subscriptions"] = exclude_subscriptions
    if exclude_management_groups:
        data["exclude_management_groups"] = exclude_management_groups

    rules: list[dict] = []
    if with_baseline_rules:
        for sid in (sub_ids or [VALID_SUB_ID]):
            rules.append(
                {
                    "name": f"allow-reader-{sid[:8]}",
                    "type": "baseline",
                    "match": {
                        "principal_id": "aaaa-bbbb",
                        "role": "Reader",
                        "scope": f"/subscriptions/{sid}",
                    },
                }
            )
    if with_governance_rules:
        rules.append(
            {
                "name": "no-owner",
                "type": "governance",
                "severity": "critical",
                "match": {"role": "Owner"},
            }
        )
    if rules:
        data["rules"] = rules

    p = tmp_path / "policy.yaml"
    p.write_text(yaml.dump(data), encoding="utf-8")
    return p


def _mock_scan_result(*, with_assignments: bool = True, sub_id: str = VALID_SUB_ID) -> RbacScanResult:
    """Build a simulated RbacScanResult."""
    assignments = []
    if with_assignments:
        assignments.append(
            ScannedRoleAssignment(
                id="/sub/role/assignment1",
                scope=f"/subscriptions/{sub_id}",
                role_definition_id="/providers/Microsoft.Authorization/roleDefinitions/xxx",
                principal_id="aaaa-bbbb",
                principal_type=PrincipalType.USER,
                role_name="Reader",
            )
        )
    return RbacScanResult(
        subscription_results=[
            SubscriptionScanResult(
                subscription_id=sub_id,
                subscription_name="Test-Sub",
                assignments=assignments,
            )
        ]
    )


# ── Tests validate command ────────────────────────────────────


class TestValidateCommand:
    def test_help(self) -> None:
        result = runner.invoke(app, ["validate", "--help"])
        assert result.exit_code == 0
        assert "policy" in result.output.lower()

    def test_valid_policy(self, tmp_path: Path) -> None:
        policy_path = _write_policy(tmp_path, with_baseline_rules=True)
        result = runner.invoke(app, ["validate", "--policy", str(policy_path)])
        assert result.exit_code == 0
        assert "valid" in result.output.lower()

    def test_valid_policy_shows_summary(self, tmp_path: Path) -> None:
        policy_path = _write_policy(tmp_path, with_baseline_rules=True)
        result = runner.invoke(app, ["validate", "--policy", str(policy_path)])
        assert result.exit_code == 0
        assert "Subscriptions" in result.output
        assert "Rules" in result.output
        assert "baseline" in result.output

    def test_scope_explicit_shown(self, tmp_path: Path) -> None:
        policy_path = _write_policy(tmp_path)
        result = runner.invoke(app, ["validate", "--policy", str(policy_path)])
        assert result.exit_code == 0
        assert "explicit" in result.output

    def test_scope_all_shown(self, tmp_path: Path) -> None:
        policy_path = _write_policy(tmp_path, scope="all")
        result = runner.invoke(app, ["validate", "--policy", str(policy_path)])
        assert result.exit_code == 0
        assert "all" in result.output

    def test_missing_file(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["validate", "--policy", str(tmp_path / "nope.yaml")])
        assert result.exit_code == 2

    def test_invalid_yaml(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("not: [valid: yaml: {", encoding="utf-8")
        result = runner.invoke(app, ["validate", "--policy", str(bad)])
        assert result.exit_code == 2

    def test_malformed_policy(self, tmp_path: Path) -> None:
        p = tmp_path / "malformed.yaml"
        p.write_text(yaml.dump({"version": "2.0"}), encoding="utf-8")
        result = runner.invoke(app, ["validate", "--policy", str(p)])
        assert result.exit_code == 2

    def test_with_rules(self, tmp_path: Path) -> None:
        data: dict = {
            "version": "2.0",
            "tenant_id": VALID_TENANT_ID,
            "subscriptions": [{"id": VALID_SUB_ID, "name": "Prod"}],
            "rules": [
                {"name": "no-owner", "type": "governance", "severity": "critical", "match": {"role": "Owner"}},
            ],
        }
        p = tmp_path / "policy.yaml"
        p.write_text(yaml.dump(data), encoding="utf-8")
        result = runner.invoke(app, ["validate", "--policy", str(p)])
        assert result.exit_code == 0
        assert "Rules" in result.output
        assert "1" in result.output


# ── Tests scan command (drift detection) ──────────────────────


class TestScanCommand:
    def test_help(self) -> None:
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "policy" in result.output.lower()

    def test_missing_policy_file(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["scan", "--policy", str(tmp_path / "nope.yaml")])
        assert result.exit_code == 2

    def test_invalid_yaml(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("not: [valid: yaml: {", encoding="utf-8")
        result = runner.invoke(app, ["scan", "--policy", str(bad)])
        assert result.exit_code == 2

    def test_no_subscriptions(self, tmp_path: Path) -> None:
        p = tmp_path / "empty.yaml"
        p.write_text(
            yaml.dump({"version": "2.0", "tenant_id": VALID_TENANT_ID}),
            encoding="utf-8",
        )
        result = runner.invoke(app, ["scan", "--policy", str(p)])
        assert result.exit_code == 0

    def test_no_baseline_rules_exits_0(self, tmp_path: Path) -> None:
        """Policy with no baseline rules → exit 0 with actionable guidance."""
        policy_path = _write_policy(tmp_path)  # no rules at all
        result = runner.invoke(app, ["scan", "--policy", str(policy_path)])
        assert result.exit_code == 0
        assert "No baseline rules in policy model" in result.output
        assert "az-rbac-watch discover" in result.output

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    def test_scan_compliant(self, mock_scan, _mock_resolve, tmp_path: Path) -> None:
        """Policy matches reality → exit 0, output contains drift-free message."""
        policy_path = _write_policy(tmp_path, with_baseline_rules=True)
        mock_scan.return_value = _mock_scan_result(with_assignments=True)

        result = runner.invoke(app, ["scan", "--policy", str(policy_path)])
        assert result.exit_code == 0
        assert "drift" in result.output.lower() or "aucun" in result.output.lower()

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    def test_scan_with_drift(self, mock_scan, _mock_resolve, tmp_path: Path) -> None:
        """Undeclared assignment → exit 1."""
        data: dict = {
            "version": "2.0",
            "tenant_id": VALID_TENANT_ID,
            "subscriptions": [{"id": VALID_SUB_ID, "name": "Sub-0"}],
            "rules": [
                {
                    "name": "allow-nothing",
                    "type": "baseline",
                    "match": {"role": "NonExistent"},
                }
            ],
        }
        p = tmp_path / "policy.yaml"
        p.write_text(yaml.dump(data), encoding="utf-8")
        mock_scan.return_value = _mock_scan_result(with_assignments=True)

        result = runner.invoke(app, ["scan", "--policy", str(p)])
        assert result.exit_code == 1

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    def test_scan_error_exit_code(self, mock_scan, _mock_resolve, tmp_path: Path) -> None:
        """Azure error during scan → exit 2."""
        policy_path = _write_policy(tmp_path, with_baseline_rules=True)
        mock_scan.side_effect = RuntimeError("Azure auth failed")

        result = runner.invoke(app, ["scan", "--policy", str(policy_path)])
        assert result.exit_code == 2

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    def test_scan_verbose_flag(self, mock_scan, _mock_resolve, tmp_path: Path) -> None:
        """The --verbose flag does not break execution."""
        policy_path = _write_policy(tmp_path, with_baseline_rules=True)
        mock_scan.return_value = _mock_scan_result(with_assignments=True)

        result = runner.invoke(app, ["scan", "--policy", str(policy_path), "--verbose"])
        assert result.exit_code == 0

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    def test_scan_output_html(self, mock_scan, _mock_resolve, tmp_path: Path) -> None:
        """--output report.html generates an HTML file."""
        policy_path = _write_policy(tmp_path, with_baseline_rules=True)
        mock_scan.return_value = _mock_scan_result(with_assignments=True)
        html_path = tmp_path / "report.html"

        result = runner.invoke(app, ["scan", "--policy", str(policy_path), "--output", str(html_path)])
        assert result.exit_code == 0
        assert html_path.exists()
        html = html_path.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in html

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    def test_scan_without_output_no_html(self, mock_scan, _mock_resolve, tmp_path: Path) -> None:
        """Without --output, no HTML file is created."""
        policy_path = _write_policy(tmp_path, with_baseline_rules=True)
        mock_scan.return_value = _mock_scan_result(with_assignments=True)

        result = runner.invoke(app, ["scan", "--policy", str(policy_path)])
        assert result.exit_code == 0
        html_files = list(tmp_path.glob("*.html"))
        assert len(html_files) == 0

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    def test_scan_output_with_drift(self, mock_scan, _mock_resolve, tmp_path: Path) -> None:
        """--output with drift → HTML contains DRIFT."""
        data: dict = {
            "version": "2.0",
            "tenant_id": VALID_TENANT_ID,
            "subscriptions": [{"id": VALID_SUB_ID, "name": "Sub-0"}],
            "rules": [
                {"name": "allow-nothing", "type": "baseline", "match": {"role": "NonExistent"}},
            ],
        }
        p = tmp_path / "policy.yaml"
        p.write_text(yaml.dump(data), encoding="utf-8")
        mock_scan.return_value = _mock_scan_result(with_assignments=True)
        html_path = tmp_path / "report.html"

        result = runner.invoke(app, ["scan", "--policy", str(p), "--output", str(html_path)])
        assert result.exit_code == 1
        assert html_path.exists()
        html = html_path.read_text(encoding="utf-8")
        assert "DRIFT" in html

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    def test_scan_format_json(self, mock_scan, _mock_resolve, tmp_path: Path) -> None:
        """--format json outputs valid JSON to stdout."""
        import json

        policy_path = _write_policy(tmp_path, with_baseline_rules=True)
        mock_scan.return_value = _mock_scan_result(with_assignments=True)

        result = runner.invoke(app, ["scan", "--policy", str(policy_path), "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "findings" in data
        assert "summary" in data

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    def test_scan_format_json_with_output(self, mock_scan, _mock_resolve, tmp_path: Path) -> None:
        """--format json --output writes JSON file."""
        import json

        policy_path = _write_policy(tmp_path, with_baseline_rules=True)
        mock_scan.return_value = _mock_scan_result(with_assignments=True)
        json_path = tmp_path / "report.json"

        result = runner.invoke(
            app,
            [
                "scan",
                "--policy",
                str(policy_path),
                "--format",
                "json",
                "--output",
                str(json_path),
            ],
        )
        assert result.exit_code == 0
        assert json_path.exists()
        data = json.loads(json_path.read_text(encoding="utf-8"))
        assert "findings" in data

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    def test_scan_format_json_with_drift(self, mock_scan, _mock_resolve, tmp_path: Path) -> None:
        """--format json includes drift findings in output."""
        import json

        data_yaml: dict = {
            "version": "2.0",
            "tenant_id": VALID_TENANT_ID,
            "subscriptions": [{"id": VALID_SUB_ID, "name": "Sub-0"}],
            "rules": [
                {"name": "allow-nothing", "type": "baseline", "match": {"role": "NonExistent"}},
            ],
        }
        p = tmp_path / "policy.yaml"
        p.write_text(yaml.dump(data_yaml), encoding="utf-8")
        mock_scan.return_value = _mock_scan_result(with_assignments=True)

        result = runner.invoke(app, ["scan", "--policy", str(p), "--format", "json"])
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert len(data["findings"]) > 0
        assert data["findings"][0]["rule_id"] == "DRIFT"

    def test_scan_format_invalid(self, tmp_path: Path) -> None:
        """--format with invalid value exits with code 2."""
        policy_path = _write_policy(tmp_path, with_baseline_rules=True)
        result = runner.invoke(app, ["scan", "--policy", str(policy_path), "--format", "xml"])
        assert result.exit_code == 2

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    def test_scan_exclude_subscription(self, mock_scan, _mock_resolve, tmp_path: Path) -> None:
        """--exclude-subscription filters the subscription from scan."""
        policy_path = _write_policy(tmp_path, with_baseline_rules=True, sub_ids=[VALID_SUB_ID, VALID_SUB_ID_2])
        mock_scan.return_value = _mock_scan_result(with_assignments=False, sub_id=VALID_SUB_ID_2)

        result = runner.invoke(
            app,
            [
                "scan",
                "--policy",
                str(policy_path),
                "--exclude-subscription",
                VALID_SUB_ID,
            ],
        )
        assert result.exit_code == 0
        mock_scan.assert_called_once()
        model_arg = mock_scan.call_args.args[0]
        sub_ids = [str(s.id) for s in model_arg.subscriptions]
        assert VALID_SUB_ID not in sub_ids
        assert VALID_SUB_ID_2 in sub_ids

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    @patch("az_rbac_watch.cli.resolve_scopes")
    def test_scan_scope_all_triggers_auto_discovery(
        self, mock_resolve_scopes, mock_scan, _mock_resolve, tmp_path: Path
    ) -> None:
        """Policy with scope=all triggers resolve_scopes() call."""
        policy_path = _write_policy(tmp_path, scope="all", with_baseline_rules=True)
        from az_rbac_watch.config.policy_model import PolicyModel

        mock_resolve_scopes.return_value = PolicyModel(
            version="2.0",
            tenant_id=VALID_TENANT_ID,
            subscriptions=[{"id": VALID_SUB_ID, "name": "Prod"}],
            rules=[
                {
                    "name": "allow-reader",
                    "type": "baseline",
                    "match": {"principal_id": "aaaa-bbbb", "role": "Reader", "scope": f"/subscriptions/{VALID_SUB_ID}"},
                }
            ],
        )
        mock_scan.return_value = _mock_scan_result(with_assignments=False)

        result = runner.invoke(app, ["scan", "--policy", str(policy_path)])
        assert result.exit_code == 0
        mock_resolve_scopes.assert_called_once()

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    @patch("az_rbac_watch.cli.resolve_scopes")
    def test_scan_scope_all_with_yaml_exclusions(
        self, mock_resolve_scopes, mock_scan, _mock_resolve, tmp_path: Path
    ) -> None:
        """Policy with scope=all + exclude_subscriptions passes through resolve_scopes."""
        policy_path = _write_policy(
            tmp_path,
            scope="all",
            with_baseline_rules=True,
            exclude_subscriptions=[VALID_SUB_ID_2],
        )
        from az_rbac_watch.config.policy_model import PolicyModel

        mock_resolve_scopes.return_value = PolicyModel(
            version="2.0",
            tenant_id=VALID_TENANT_ID,
            subscriptions=[{"id": VALID_SUB_ID, "name": "Prod"}],
            rules=[
                {
                    "name": "allow-reader",
                    "type": "baseline",
                    "match": {"principal_id": "aaaa-bbbb", "role": "Reader", "scope": f"/subscriptions/{VALID_SUB_ID}"},
                }
            ],
        )
        mock_scan.return_value = _mock_scan_result(with_assignments=False)

        result = runner.invoke(app, ["scan", "--policy", str(policy_path)])
        assert result.exit_code == 0
        mock_resolve_scopes.assert_called_once()

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    @patch("az_rbac_watch.cli.resolve_scopes")
    def test_scan_scope_all_with_cli_exclusions(
        self, mock_resolve_scopes, mock_scan, _mock_resolve, tmp_path: Path
    ) -> None:
        """scope=all + CLI --exclude-subscription → both cumulate."""
        policy_path = _write_policy(tmp_path, scope="all", with_baseline_rules=True)
        from az_rbac_watch.config.policy_model import PolicyModel

        mock_resolve_scopes.return_value = PolicyModel(
            version="2.0",
            tenant_id=VALID_TENANT_ID,
            subscriptions=[
                {"id": VALID_SUB_ID, "name": "Prod"},
                {"id": VALID_SUB_ID_2, "name": "Dev"},
            ],
            rules=[
                {
                    "name": "allow-reader",
                    "type": "baseline",
                    "match": {"principal_id": "aaaa-bbbb", "role": "Reader", "scope": f"/subscriptions/{VALID_SUB_ID}"},
                }
            ],
        )
        mock_scan.return_value = _mock_scan_result(with_assignments=False, sub_id=VALID_SUB_ID)

        result = runner.invoke(
            app,
            [
                "scan",
                "--policy",
                str(policy_path),
                "--exclude-subscription",
                VALID_SUB_ID_2,
            ],
        )
        assert result.exit_code == 0
        mock_scan.assert_called_once()
        model_arg = mock_scan.call_args.args[0]
        sub_ids = [str(s.id) for s in model_arg.subscriptions]
        assert VALID_SUB_ID in sub_ids
        assert VALID_SUB_ID_2 not in sub_ids

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    def test_scan_scope_explicit_no_resolve(self, mock_scan, _mock_resolve, tmp_path: Path) -> None:
        """Policy with scope=explicit does NOT call resolve_scopes."""
        policy_path = _write_policy(tmp_path, with_baseline_rules=True)
        mock_scan.return_value = _mock_scan_result(with_assignments=True)

        with patch("az_rbac_watch.cli.resolve_scopes") as mock_rs:
            result = runner.invoke(app, ["scan", "--policy", str(policy_path)])
            assert result.exit_code == 0
            mock_rs.assert_not_called()

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    def test_scan_exclude_management_group(self, mock_scan, _mock_resolve, tmp_path: Path) -> None:
        """--exclude-management-group filters the MG from scan."""
        policy_path = _write_policy(tmp_path, with_mg=True, with_baseline_rules=True)
        mock_scan.return_value = _mock_scan_result(with_assignments=False)

        result = runner.invoke(
            app,
            [
                "scan",
                "--policy",
                str(policy_path),
                "--exclude-management-group",
                "mg-test",
            ],
        )
        assert result.exit_code == 0
        mock_scan.assert_called_once()
        model_arg = mock_scan.call_args.args[0]
        assert len(model_arg.management_groups) == 0


# ── Tests audit command (guardrails) ──────────────────────────


class TestAuditCommand:
    def test_help(self) -> None:
        result = runner.invoke(app, ["audit", "--help"])
        assert result.exit_code == 0
        assert "policy" in result.output.lower()

    def test_missing_policy_file(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["audit", "--policy", str(tmp_path / "nope.yaml")])
        assert result.exit_code == 2

    def test_no_governance_rules_exits_0(self, tmp_path: Path) -> None:
        """Policy with no governance rules → exit 0 with hint."""
        policy_path = _write_policy(tmp_path, with_baseline_rules=True)  # baseline only
        result = runner.invoke(app, ["audit", "--policy", str(policy_path)])
        assert result.exit_code == 0
        assert "governance" in result.output.lower()

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    def test_audit_no_violations(self, mock_scan, _mock_resolve, tmp_path: Path) -> None:
        """No matching governance rules → exit 0."""
        policy_path = _write_policy(tmp_path, with_governance_rules=True)
        mock_scan.return_value = _mock_scan_result(with_assignments=True)  # Reader, not Owner

        result = runner.invoke(app, ["audit", "--policy", str(policy_path)])
        assert result.exit_code == 0
        assert "violation" in result.output.lower() or "guardrail" in result.output.lower()

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    def test_audit_with_violations(self, mock_scan, _mock_resolve, tmp_path: Path) -> None:
        """Governance rule matches assignment → exit 1."""
        policy_path = _write_policy(tmp_path, with_governance_rules=True)
        mock_scan.return_value = RbacScanResult(
            subscription_results=[
                SubscriptionScanResult(
                    subscription_id=VALID_SUB_ID,
                    subscription_name="Test-Sub",
                    assignments=[
                        ScannedRoleAssignment(
                            id="/sub/role/assignment1",
                            scope=f"/subscriptions/{VALID_SUB_ID}",
                            role_definition_id="/providers/Microsoft.Authorization/roleDefinitions/xxx",
                            principal_id="aaaa-bbbb",
                            principal_type=PrincipalType.USER,
                            role_name="Owner",
                        )
                    ],
                )
            ]
        )

        result = runner.invoke(app, ["audit", "--policy", str(policy_path)])
        assert result.exit_code == 1

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    def test_audit_error_exit_code(self, mock_scan, _mock_resolve, tmp_path: Path) -> None:
        """Azure error during audit → exit 2."""
        policy_path = _write_policy(tmp_path, with_governance_rules=True)
        mock_scan.side_effect = RuntimeError("Azure auth failed")

        result = runner.invoke(app, ["audit", "--policy", str(policy_path)])
        assert result.exit_code == 2

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    def test_audit_format_json(self, mock_scan, _mock_resolve, tmp_path: Path) -> None:
        """--format json outputs valid JSON."""
        import json

        policy_path = _write_policy(tmp_path, with_governance_rules=True)
        mock_scan.return_value = _mock_scan_result(with_assignments=True)

        result = runner.invoke(app, ["audit", "--policy", str(policy_path), "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "findings" in data
        assert "summary" in data

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    def test_audit_output_html(self, mock_scan, _mock_resolve, tmp_path: Path) -> None:
        """--output generates HTML report."""
        policy_path = _write_policy(tmp_path, with_governance_rules=True)
        mock_scan.return_value = _mock_scan_result(with_assignments=True)
        html_path = tmp_path / "audit_report.html"

        result = runner.invoke(app, ["audit", "--policy", str(policy_path), "--output", str(html_path)])
        assert result.exit_code == 0
        assert html_path.exists()
        html = html_path.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in html
        assert "Audit" in html


# ── Tests discover command ────────────────────────────────────


class TestDiscoverCommand:
    def test_help(self) -> None:
        result = runner.invoke(app, ["discover", "--help"])
        assert result.exit_code == 0
        assert "output" in result.output.lower()

    def test_missing_policy_file(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["discover", "--policy", str(tmp_path / "nope.yaml")])
        assert result.exit_code == 2

    @patch("az_rbac_watch.cli.discover_policy")
    @patch("az_rbac_watch.cli.scan_rbac")
    def test_discover_creates_file(self, mock_scan, mock_discover, tmp_path: Path) -> None:
        """Discovery scans, resolves names, and creates the output file."""
        from az_rbac_watch.config.policy_model import PolicyModel, Rule, RuleMatch

        policy_path = _write_policy(tmp_path)
        output_path = tmp_path / "discovered.yaml"
        mock_scan.return_value = _mock_scan_result()
        mock_discover.return_value = PolicyModel(
            version="2.0",
            tenant_id=VALID_TENANT_ID,
            subscriptions=[{"id": VALID_SUB_ID, "name": "Test-Sub"}],
            rules=[
                Rule(
                    name="aaaa-bbbb-reader",
                    type="baseline",
                    match=RuleMatch(
                        principal_id="aaaa-bbbb",
                        role="Reader",
                        scope=f"/subscriptions/{VALID_SUB_ID}",
                    ),
                ),
            ],
        )

        result = runner.invoke(app, ["discover", "--policy", str(policy_path), "--output", str(output_path)])
        assert result.exit_code == 0
        assert output_path.exists()
        assert "discovered" in result.output

    @patch("az_rbac_watch.cli.scan_rbac")
    def test_discover_scan_error(self, mock_scan, tmp_path: Path) -> None:
        """Azure error during discover → exit 2."""
        policy_path = _write_policy(tmp_path)
        mock_scan.side_effect = RuntimeError("No access")

        result = runner.invoke(app, ["discover", "--policy", str(policy_path)])
        assert result.exit_code == 2

    def test_discover_no_subscriptions(self, tmp_path: Path) -> None:
        p = tmp_path / "empty.yaml"
        p.write_text(
            yaml.dump({"version": "2.0", "tenant_id": VALID_TENANT_ID}),
            encoding="utf-8",
        )
        result = runner.invoke(app, ["discover", "--policy", str(p)])
        assert result.exit_code == 0

    @patch("az_rbac_watch.cli.discover_policy")
    @patch("az_rbac_watch.cli.scan_rbac")
    @patch("az_rbac_watch.cli.list_accessible_management_groups")
    @patch("az_rbac_watch.cli.list_accessible_subscriptions")
    def test_discover_no_args_auto_discovery(
        self, mock_list_subs, mock_list_mgs, mock_scan, mock_discover, tmp_path: Path
    ) -> None:
        """Without --policy, auto-discover accessible scopes."""
        from az_rbac_watch.config.policy_model import PolicyModel

        mock_list_subs.return_value = [
            (VALID_SUB_ID, "Prod", VALID_TENANT_ID),
        ]
        mock_list_mgs.return_value = []
        mock_scan.return_value = _mock_scan_result()
        mock_discover.return_value = PolicyModel(
            version="2.0",
            tenant_id=VALID_TENANT_ID,
            subscriptions=[{"id": VALID_SUB_ID, "name": "Prod"}],
        )

        output_path = tmp_path / "discovered.yaml"
        result = runner.invoke(app, ["discover", "--output", str(output_path)])
        assert result.exit_code == 0
        assert output_path.exists()
        mock_list_subs.assert_called()
        mock_scan.assert_called_once()

    @patch("az_rbac_watch.cli.discover_policy")
    @patch("az_rbac_watch.cli.scan_rbac")
    @patch("az_rbac_watch.cli.list_accessible_management_groups")
    @patch("az_rbac_watch.cli.list_accessible_subscriptions")
    def test_discover_with_tenant_and_subs(
        self, mock_list_subs, mock_list_mgs, mock_scan, mock_discover, tmp_path: Path
    ) -> None:
        """Explicit --tenant-id and --subscription."""
        from az_rbac_watch.config.policy_model import PolicyModel

        mock_list_subs.return_value = [
            (VALID_SUB_ID, "Prod", VALID_TENANT_ID),
        ]
        mock_list_mgs.return_value = []
        mock_scan.return_value = _mock_scan_result()
        mock_discover.return_value = PolicyModel(
            version="2.0",
            tenant_id=VALID_TENANT_ID,
            subscriptions=[{"id": VALID_SUB_ID, "name": "Prod"}],
        )

        output_path = tmp_path / "discovered.yaml"
        result = runner.invoke(
            app,
            [
                "discover",
                "--tenant-id",
                VALID_TENANT_ID,
                "--subscription",
                VALID_SUB_ID,
                "--output",
                str(output_path),
            ],
        )
        assert result.exit_code == 0
        assert output_path.exists()
        mock_scan.assert_called_once()

    @patch("az_rbac_watch.cli.discover_policy")
    @patch("az_rbac_watch.cli.scan_rbac")
    @patch("az_rbac_watch.cli.list_accessible_management_groups")
    @patch("az_rbac_watch.cli.list_accessible_subscriptions")
    def test_discover_with_exclusions(
        self, mock_list_subs, mock_list_mgs, mock_scan, mock_discover, tmp_path: Path
    ) -> None:
        """Auto-discovery minus exclusions."""
        from az_rbac_watch.config.policy_model import PolicyModel

        mock_list_subs.return_value = [
            (VALID_SUB_ID, "Prod", VALID_TENANT_ID),
            (VALID_SUB_ID_2, "Dev", VALID_TENANT_ID),
        ]
        mock_list_mgs.return_value = []
        mock_scan.return_value = _mock_scan_result(with_assignments=False, sub_id=VALID_SUB_ID_2)
        mock_discover.return_value = PolicyModel(
            version="2.0",
            tenant_id=VALID_TENANT_ID,
            subscriptions=[{"id": VALID_SUB_ID_2, "name": "Dev"}],
        )

        output_path = tmp_path / "discovered.yaml"
        result = runner.invoke(
            app,
            [
                "discover",
                "--exclude-subscription",
                VALID_SUB_ID,
                "--output",
                str(output_path),
            ],
        )
        assert result.exit_code == 0
        mock_scan.assert_called_once()
        model_arg = mock_scan.call_args.args[0]
        sub_ids = [str(s.id) for s in model_arg.subscriptions]
        assert VALID_SUB_ID not in sub_ids
        assert VALID_SUB_ID_2 in sub_ids

    @patch("az_rbac_watch.cli.list_accessible_management_groups")
    @patch("az_rbac_watch.cli.list_accessible_subscriptions")
    def test_discover_no_accessible_scopes(self, mock_list_subs, mock_list_mgs) -> None:
        """No accessible scope → exit 2."""
        mock_list_subs.return_value = []
        mock_list_mgs.return_value = []

        result = runner.invoke(app, ["discover", "--tenant-id", VALID_TENANT_ID])
        assert result.exit_code == 2

    @patch("az_rbac_watch.cli.discover_policy")
    @patch("az_rbac_watch.cli.scan_rbac")
    def test_discover_policy_still_works(self, mock_scan, mock_discover, tmp_path: Path) -> None:
        """--policy still works."""
        from az_rbac_watch.config.policy_model import PolicyModel

        policy_path = _write_policy(tmp_path)
        output_path = tmp_path / "discovered.yaml"
        mock_scan.return_value = _mock_scan_result()
        mock_discover.return_value = PolicyModel(
            version="2.0",
            tenant_id=VALID_TENANT_ID,
            subscriptions=[{"id": VALID_SUB_ID, "name": "Test-Sub"}],
        )

        result = runner.invoke(app, ["discover", "--policy", str(policy_path), "--output", str(output_path)])
        assert result.exit_code == 0
        assert output_path.exists()


# ── Test global help ─────────────────────────────────────────


class TestDebugFlag:
    """Tests for the --debug flag on scan and discover commands."""

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac", side_effect=RuntimeError("boom"))
    def test_scan_debug_shows_traceback(self, _mock_scan, _mock_resolve, tmp_path: Path) -> None:
        policy_path = _write_policy(tmp_path, with_baseline_rules=True)
        result = runner.invoke(app, ["scan", "--policy", str(policy_path), "--debug"])
        assert result.exit_code == 2
        assert "Traceback" in result.output or "RuntimeError" in result.output

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac", side_effect=RuntimeError("boom"))
    def test_scan_no_debug_shows_hint(self, _mock_scan, _mock_resolve, tmp_path: Path) -> None:
        policy_path = _write_policy(tmp_path, with_baseline_rules=True)
        result = runner.invoke(app, ["scan", "--policy", str(policy_path)])
        assert result.exit_code == 2
        assert "--debug" in result.output

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    def test_scan_debug_no_error(self, mock_scan, _mock_resolve, tmp_path: Path) -> None:
        """--debug does not break normal execution."""
        policy_path = _write_policy(tmp_path, with_baseline_rules=True)
        mock_scan.return_value = _mock_scan_result(with_assignments=True)
        result = runner.invoke(app, ["scan", "--policy", str(policy_path), "--debug"])
        assert result.exit_code == 0


# ── Tests ad-hoc mode (scan/audit without --policy) ──────────


class TestAdHocScan:
    """Tests for scan command in ad-hoc mode (no --policy)."""

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    @patch("az_rbac_watch.cli.list_accessible_subscriptions")
    def test_scan_adhoc_with_subscription(
        self, mock_list_subs, mock_scan, _mock_resolve
    ) -> None:
        """scan -s <id> without --policy builds model on-the-fly."""
        mock_list_subs.return_value = [
            (VALID_SUB_ID, "Prod", VALID_TENANT_ID),
        ]
        mock_scan.return_value = _mock_scan_result(with_assignments=True)

        result = runner.invoke(app, ["scan", "-s", VALID_SUB_ID])
        assert result.exit_code == 1  # all assignments = drift (no baseline)
        mock_scan.assert_called_once()
        model_arg = mock_scan.call_args.args[0]
        assert len(model_arg.subscriptions) == 1
        assert str(model_arg.subscriptions[0].id) == VALID_SUB_ID

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    @patch("az_rbac_watch.cli.list_accessible_subscriptions")
    def test_scan_adhoc_shows_hint(
        self, mock_list_subs, mock_scan, _mock_resolve
    ) -> None:
        """Ad-hoc scan prints hint about no baseline rules."""
        mock_list_subs.return_value = [
            (VALID_SUB_ID, "Prod", VALID_TENANT_ID),
        ]
        mock_scan.return_value = _mock_scan_result(with_assignments=False)

        result = runner.invoke(app, ["scan", "-s", VALID_SUB_ID])
        assert result.exit_code == 0
        assert "ad-hoc" in result.output.lower()

    def test_scan_policy_and_subscription_mutually_exclusive(self, tmp_path: Path) -> None:
        """--policy and -s are mutually exclusive."""
        policy_path = _write_policy(tmp_path, with_baseline_rules=True)
        result = runner.invoke(app, ["scan", "--policy", str(policy_path), "-s", VALID_SUB_ID])
        assert result.exit_code == 2
        assert "mutually exclusive" in result.output

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    @patch("az_rbac_watch.cli.list_accessible_subscriptions")
    def test_scan_adhoc_json_format(
        self, mock_list_subs, mock_scan, _mock_resolve
    ) -> None:
        """Ad-hoc scan works with --format json."""
        import json

        mock_list_subs.return_value = [
            (VALID_SUB_ID, "Prod", VALID_TENANT_ID),
        ]
        mock_scan.return_value = _mock_scan_result(with_assignments=True)

        result = runner.invoke(app, ["scan", "-s", VALID_SUB_ID, "--format", "json"])
        assert result.exit_code == 1
        # CliRunner merges stderr+stdout; extract JSON portion
        json_start = result.output.index("{")
        data = json.loads(result.output[json_start:])
        assert "findings" in data


class TestAdHocAudit:
    """Tests for audit command in ad-hoc mode (no --policy)."""

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    @patch("az_rbac_watch.cli.list_accessible_subscriptions")
    def test_audit_adhoc_uses_default_rules(
        self, mock_list_subs, mock_scan, _mock_resolve
    ) -> None:
        """audit -s <id> without --policy injects default governance rules."""
        mock_list_subs.return_value = [
            (VALID_SUB_ID, "Prod", VALID_TENANT_ID),
        ]
        mock_scan.return_value = _mock_scan_result(with_assignments=True)

        result = runner.invoke(app, ["audit", "-s", VALID_SUB_ID])
        # Default rules include no-direct-users (User principal type) → should find violations
        assert result.exit_code in (0, 1)
        mock_scan.assert_called_once()
        model_arg = mock_scan.call_args.args[0]
        governance_rules = [r for r in model_arg.rules if r.type == "governance"]
        assert len(governance_rules) > 0

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    @patch("az_rbac_watch.cli.list_accessible_subscriptions")
    def test_audit_adhoc_prints_default_rules_hint(
        self, mock_list_subs, mock_scan, _mock_resolve
    ) -> None:
        """Ad-hoc audit prints hint about default rules."""
        mock_list_subs.return_value = [
            (VALID_SUB_ID, "Prod", VALID_TENANT_ID),
        ]
        mock_scan.return_value = _mock_scan_result(with_assignments=True)

        result = runner.invoke(app, ["audit", "-s", VALID_SUB_ID])
        assert "ad-hoc" in result.output.lower() or "default" in result.output.lower()

    def test_audit_policy_and_subscription_mutually_exclusive(self, tmp_path: Path) -> None:
        """--policy and -s are mutually exclusive."""
        policy_path = _write_policy(tmp_path, with_governance_rules=True)
        result = runner.invoke(app, ["audit", "--policy", str(policy_path), "-s", VALID_SUB_ID])
        assert result.exit_code == 2

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    @patch("az_rbac_watch.cli.list_accessible_subscriptions")
    def test_audit_adhoc_detects_violations(
        self, mock_list_subs, mock_scan, _mock_resolve
    ) -> None:
        """Ad-hoc audit with User principal → violation (no-direct-users rule)."""
        mock_list_subs.return_value = [
            (VALID_SUB_ID, "Prod", VALID_TENANT_ID),
        ]
        # User with Reader role — triggers no-direct-users default rule
        mock_scan.return_value = _mock_scan_result(with_assignments=True)

        result = runner.invoke(app, ["audit", "-s", VALID_SUB_ID])
        assert result.exit_code == 1  # violations detected

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    @patch("az_rbac_watch.cli.list_accessible_management_groups")
    @patch("az_rbac_watch.cli.list_accessible_subscriptions")
    def test_audit_adhoc_auto_discovery(
        self, mock_list_subs, mock_list_mgs, mock_scan, _mock_resolve
    ) -> None:
        """audit without --policy and without -s/-m triggers auto-discovery."""
        mock_list_subs.return_value = [
            (VALID_SUB_ID, "Prod", VALID_TENANT_ID),
        ]
        mock_list_mgs.return_value = []
        mock_scan.return_value = _mock_scan_result(with_assignments=False)

        result = runner.invoke(app, ["audit"])
        assert result.exit_code == 0
        mock_list_subs.assert_called()


class TestActionableErrorMessages:
    """Tests pour les messages d'erreur actionnables."""

    @patch("az_rbac_watch.cli.list_accessible_management_groups")
    @patch("az_rbac_watch.cli.list_accessible_subscriptions")
    def test_no_tenant_id_shows_actionable_message(self, mock_list_subs, mock_list_mgs) -> None:
        """Cannot resolve tenant_id → message with remediation steps."""
        mock_list_subs.return_value = [(VALID_SUB_ID, "Prod", "")]  # empty tenant_id
        mock_list_mgs.return_value = []

        result = runner.invoke(app, ["scan", "-s", VALID_SUB_ID])
        assert result.exit_code == 2
        assert "could not determine tenant ID" in result.output
        assert "az login" in result.output
        assert "--tenant-id" in result.output

    @patch("az_rbac_watch.cli.list_accessible_management_groups")
    @patch("az_rbac_watch.cli.list_accessible_subscriptions")
    def test_no_accessible_subscriptions_shows_actionable_message(self, mock_list_subs, mock_list_mgs) -> None:
        """No accessible scopes → message with remediation steps."""
        mock_list_subs.return_value = []
        mock_list_mgs.return_value = []

        result = runner.invoke(app, ["scan", "--tenant-id", VALID_TENANT_ID])
        assert result.exit_code == 2
        assert "no accessible subscriptions found" in result.output
        assert "az login" in result.output
        assert "Reader role" in result.output

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    @patch("az_rbac_watch.cli.list_accessible_subscriptions")
    def test_adhoc_scan_warning_is_bold(self, mock_list_subs, mock_scan, _mock_resolve) -> None:
        """Ad-hoc scan message contains expected text (bold yellow in real terminal)."""
        mock_list_subs.return_value = [(VALID_SUB_ID, "Prod", VALID_TENANT_ID)]
        mock_scan.return_value = _mock_scan_result(with_assignments=False)

        result = runner.invoke(app, ["scan", "-s", VALID_SUB_ID])
        assert result.exit_code == 0
        assert "Ad-hoc mode: no baseline rules" in result.output

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    @patch("az_rbac_watch.cli.list_accessible_subscriptions")
    def test_adhoc_audit_default_rules_warning(self, mock_list_subs, mock_scan, _mock_resolve) -> None:
        """Ad-hoc audit message contains expected text (bold yellow in real terminal)."""
        mock_list_subs.return_value = [(VALID_SUB_ID, "Prod", VALID_TENANT_ID)]
        mock_scan.return_value = _mock_scan_result(with_assignments=True)

        result = runner.invoke(app, ["audit", "-s", VALID_SUB_ID])
        assert "Ad-hoc mode" in result.output
        assert "default governance rule" in result.output


class TestGlobalHelp:
    def test_help(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output
        assert "audit" in result.output
        assert "discover" in result.output
        assert "migrate" not in result.output


class TestQuietFlag:
    """Tests pour le flag --quiet qui supprime les messages de statut."""

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    def test_quiet_suppresses_status_messages(self, mock_scan, _mock_resolve, tmp_path: Path) -> None:
        """--quiet suppresses status/progress messages."""
        policy_path = _write_policy(tmp_path, with_governance_rules=True)
        mock_scan.return_value = _mock_scan_result(with_assignments=True)

        result = runner.invoke(app, ["--quiet", "audit", "--policy", str(policy_path)])
        # Status messages must not appear
        assert "Auto-discover" not in result.output
        assert "Resolving" not in result.output

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    def test_quiet_short_flag(self, mock_scan, _mock_resolve, tmp_path: Path) -> None:
        """Short flag -q works the same as --quiet."""
        policy_path = _write_policy(tmp_path, with_governance_rules=True)
        mock_scan.return_value = _mock_scan_result(with_assignments=True)

        result = runner.invoke(app, ["-q", "audit", "--policy", str(policy_path)])
        assert "Auto-discover" not in result.output
        assert "Resolving" not in result.output

    def test_quiet_flag_on_validate(self, tmp_path: Path) -> None:
        """--quiet is accepted on validate command."""
        policy_path = _write_policy(tmp_path, with_baseline_rules=True)
        result = runner.invoke(app, ["--quiet", "validate", "--policy", str(policy_path)])
        assert result.exit_code == 0


class TestNoColorFlag:
    """Tests for the --no-color flag which disables coloring."""

    def test_no_color_flag_accepted(self, tmp_path: Path) -> None:
        """--no-color flag is accepted without error."""
        policy_path = _write_policy(tmp_path, with_baseline_rules=True)
        result = runner.invoke(app, ["--no-color", "validate", "--policy", str(policy_path)])
        assert result.exit_code == 0

    def test_no_color_with_env_var(self, tmp_path: Path) -> None:
        """NO_COLOR env var is respected."""
        policy_path = _write_policy(tmp_path, with_baseline_rules=True)
        result = runner.invoke(
            app,
            ["validate", "--policy", str(policy_path)],
            env={"NO_COLOR": "1"},
        )
        assert result.exit_code == 0

    def test_no_color_on_help(self) -> None:
        """--no-color appears in global help."""
        import re

        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        clean = re.sub(r"\x1b\[[0-9;]*m", "", result.output)
        assert "--no-color" in clean

    def test_quiet_on_help(self) -> None:
        """--quiet appears in global help."""
        import re

        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        clean = re.sub(r"\x1b\[[0-9;]*m", "", result.output)
        assert "--quiet" in clean


class TestDryRun:
    """Tests for the --dry-run flag on scan, audit, discover."""

    def test_scan_dry_run(self, tmp_path: Path) -> None:
        """--dry-run validates the policy and shows the plan without calling Azure."""
        policy_path = _write_policy(tmp_path, with_baseline_rules=True)
        result = runner.invoke(app, ["scan", "--policy", str(policy_path), "--dry-run"])
        assert result.exit_code == 0
        assert "dry run" in result.output.lower()
        assert "1 subscription" in result.output.lower()
        assert "1 baseline rule" in result.output.lower()

    @patch("az_rbac_watch.cli.scan_rbac")
    def test_scan_dry_run_no_api_call(self, mock_scan: MagicMock, tmp_path: Path) -> None:
        """--dry-run must NOT call scan_rbac."""
        policy_path = _write_policy(tmp_path, with_baseline_rules=True)
        runner.invoke(app, ["scan", "--policy", str(policy_path), "--dry-run"])
        mock_scan.assert_not_called()

    def test_audit_dry_run(self, tmp_path: Path) -> None:
        """--dry-run on audit shows the plan without calling Azure."""
        policy_path = _write_policy(tmp_path, with_governance_rules=True)
        result = runner.invoke(app, ["audit", "--policy", str(policy_path), "--dry-run"])
        assert result.exit_code == 0
        assert "dry run" in result.output.lower()
        assert "1 governance rule" in result.output.lower()

    @patch("az_rbac_watch.cli.scan_rbac")
    def test_audit_dry_run_no_api_call(self, mock_scan: MagicMock, tmp_path: Path) -> None:
        """--dry-run on audit must NOT call scan_rbac."""
        policy_path = _write_policy(tmp_path, with_governance_rules=True)
        runner.invoke(app, ["audit", "--policy", str(policy_path), "--dry-run"])
        mock_scan.assert_not_called()

    def test_discover_dry_run(self, tmp_path: Path) -> None:
        """--dry-run on discover shows the plan without calling Azure."""
        policy_path = _write_policy(tmp_path)
        result = runner.invoke(app, ["discover", "--policy", str(policy_path), "--dry-run"])
        assert result.exit_code == 0
        assert "dry run" in result.output.lower()

    @patch("az_rbac_watch.cli.scan_rbac")
    def test_discover_dry_run_no_api_call(self, mock_scan: MagicMock, tmp_path: Path) -> None:
        """--dry-run on discover must NOT call scan_rbac."""
        policy_path = _write_policy(tmp_path)
        runner.invoke(app, ["discover", "--policy", str(policy_path), "--dry-run"])
        mock_scan.assert_not_called()

    def test_scan_dry_run_with_mg(self, tmp_path: Path) -> None:
        """--dry-run shows management groups in the plan."""
        policy_path = _write_policy(tmp_path, with_baseline_rules=True, with_mg=True)
        result = runner.invoke(app, ["scan", "--policy", str(policy_path), "--dry-run"])
        assert result.exit_code == 0
        assert "1 management group" in result.output.lower()
        assert "mg-test" in result.output


class TestAutoDetectPolicy:
    """Tests for auto-detection of policy file in the current directory."""

    def _write_policy_in_cwd(self, cwd: Path, filename: str = "policy.yaml") -> Path:
        """Write a minimal policy file to the given directory."""
        data = {
            "version": "2.0",
            "tenant_id": VALID_TENANT_ID,
            "subscriptions": [{"id": VALID_SUB_ID, "name": "Test-Sub"}],
        }
        p = cwd / filename
        p.write_text(yaml.dump(data), encoding="utf-8")
        return p

    def test_detect_policy_yaml(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """_detect_policy_file finds policy.yaml in the current directory."""
        monkeypatch.chdir(tmp_path)
        self._write_policy_in_cwd(tmp_path, "policy.yaml")
        detected = _detect_policy_file()
        assert detected is not None
        assert detected.name == "policy.yaml"

    def test_detect_dot_az_rbac_watch_yaml(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """_detect_policy_file finds .az-rbac-watch.yaml in the current directory."""
        monkeypatch.chdir(tmp_path)
        self._write_policy_in_cwd(tmp_path, ".az-rbac-watch.yaml")
        detected = _detect_policy_file()
        assert detected is not None
        assert detected.name == ".az-rbac-watch.yaml"

    def test_detect_az_rbac_watch_yaml(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """_detect_policy_file finds az-rbac-watch.yaml in the current directory."""
        monkeypatch.chdir(tmp_path)
        self._write_policy_in_cwd(tmp_path, "az-rbac-watch.yaml")
        detected = _detect_policy_file()
        assert detected is not None
        assert detected.name == "az-rbac-watch.yaml"

    def test_detect_priority_order(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """policy.yaml takes priority over .az-rbac-watch.yaml."""
        monkeypatch.chdir(tmp_path)
        self._write_policy_in_cwd(tmp_path, "policy.yaml")
        self._write_policy_in_cwd(tmp_path, ".az-rbac-watch.yaml")
        detected = _detect_policy_file()
        assert detected is not None
        assert detected.name == "policy.yaml"

    def test_detect_no_policy_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """_detect_policy_file returns None when no file is found."""
        monkeypatch.chdir(tmp_path)
        detected = _detect_policy_file()
        assert detected is None

    def test_scan_auto_detect_policy_yaml(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """scan without --policy uses policy.yaml found in cwd (via --dry-run)."""
        monkeypatch.chdir(tmp_path)
        self._write_policy_in_cwd(tmp_path, "policy.yaml")
        result = runner.invoke(app, ["scan", "--dry-run"])
        assert result.exit_code == 0
        assert "Using policy file: ./policy.yaml" in result.output

    def test_scan_auto_detect_dot_az_rbac_watch(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """scan without --policy uses .az-rbac-watch.yaml found in cwd."""
        monkeypatch.chdir(tmp_path)
        self._write_policy_in_cwd(tmp_path, ".az-rbac-watch.yaml")
        result = runner.invoke(app, ["scan", "--dry-run"])
        assert result.exit_code == 0
        assert "Using policy file: ./.az-rbac-watch.yaml" in result.output

    def test_no_auto_detect_when_policy_flag_given(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """--policy explicit takes priority over auto-detection."""
        monkeypatch.chdir(tmp_path)
        # Write two files: one in cwd, one in a subfolder
        self._write_policy_in_cwd(tmp_path, "policy.yaml")
        sub = tmp_path / "sub"
        sub.mkdir()
        explicit = self._write_policy_in_cwd(sub, "explicit.yaml")
        result = runner.invoke(app, ["scan", "--policy", str(explicit), "--dry-run"])
        assert result.exit_code == 0
        # Must NOT display the auto-detection message
        assert "Using policy file:" not in result.output

    @patch("az_rbac_watch.cli._build_model_from_args")
    def test_no_policy_file_falls_through(
        self, mock_build: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When no policy file is in cwd, we fall through to ad-hoc mode."""
        monkeypatch.chdir(tmp_path)
        # Mock _build_model_from_args to avoid Azure calls
        from az_rbac_watch.config.policy_model import PolicyModel, Subscription

        mock_build.return_value = PolicyModel(
            version="2.0",
            tenant_id=VALID_TENANT_ID,
            subscriptions=[Subscription(id=VALID_SUB_ID, name="Test-Sub")],
        )
        result = runner.invoke(app, ["scan", "--dry-run"])
        assert "Using policy file:" not in result.output
        mock_build.assert_called_once()


class TestZeroArgsDefault:
    """Tests for zero-args behavior → audit by default."""

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    @patch("az_rbac_watch.cli.list_accessible_subscriptions")
    @patch("az_rbac_watch.cli.list_accessible_management_groups")
    def test_no_args_runs_audit(
        self, mock_mgs: MagicMock, mock_subs: MagicMock, mock_scan: MagicMock, _mock_resolve: MagicMock
    ) -> None:
        """Zero arguments runs audit with default governance rules."""
        mock_subs.return_value = [(VALID_SUB_ID, "Prod", VALID_TENANT_ID)]
        mock_mgs.return_value = []
        mock_scan.return_value = _mock_scan_result(with_assignments=True)
        result = runner.invoke(app, [])
        assert result.exit_code in (0, 1)
        mock_scan.assert_called_once()

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    @patch("az_rbac_watch.cli.list_accessible_subscriptions")
    @patch("az_rbac_watch.cli.list_accessible_management_groups")
    def test_no_args_shows_next_steps(
        self, mock_mgs: MagicMock, mock_subs: MagicMock, mock_scan: MagicMock, _mock_resolve: MagicMock
    ) -> None:
        """Zero arguments shows next steps (discover + scan)."""
        mock_subs.return_value = [(VALID_SUB_ID, "Prod", VALID_TENANT_ID)]
        mock_mgs.return_value = []
        mock_scan.return_value = _mock_scan_result(with_assignments=True)
        result = runner.invoke(app, [])
        assert "Next steps" in result.output
        assert "az-rbac-watch discover" in result.output

    def test_help_still_works(self) -> None:
        """--help displays help even with invoke_without_command."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "audit" in result.output
        assert "scan" in result.output
        assert "Quick start" in result.output


class TestCredentialCheck:
    """Tests for Azure credentials verification."""

    def test_credential_check_failure_exits_2(self) -> None:
        """Credentials unavailable → exit code 2 with actionable message."""
        with patch("az_rbac_watch.cli.check_credentials", return_value=False):
            result = runner.invoke(app, ["audit", "-s", VALID_SUB_ID])
            assert result.exit_code == 2
            assert "no Azure credentials found" in result.output
            assert "az login" in result.output

    def test_credential_check_skipped_on_dry_run(self) -> None:
        """--dry-run does not check credentials."""
        policy_path_content = yaml.dump({
            "version": "2.0",
            "tenant_id": VALID_TENANT_ID,
            "subscriptions": [{"id": VALID_SUB_ID, "name": "Test"}],
            "rules": [{"name": "r", "type": "governance", "severity": "high", "match": {"role": "Owner"}}],
        })
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(policy_path_content)
            f.flush()
            with patch("az_rbac_watch.cli.check_credentials", return_value=False):
                result = runner.invoke(app, ["audit", "--policy", f.name, "--dry-run"])
                assert result.exit_code == 0
                assert "no Azure credentials found" not in result.output

    def test_credential_check_skipped_on_validate(self) -> None:
        """validate does not check credentials (offline)."""
        policy_path_content = yaml.dump({
            "version": "2.0",
            "tenant_id": VALID_TENANT_ID,
            "subscriptions": [{"id": VALID_SUB_ID, "name": "Test"}],
        })
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(policy_path_content)
            f.flush()
            with patch("az_rbac_watch.cli.check_credentials", return_value=False):
                result = runner.invoke(app, ["validate", "--policy", f.name])
                assert result.exit_code == 0

    def test_scan_credential_check_failure(self) -> None:
        """scan sans credentials → exit code 2."""
        with patch("az_rbac_watch.cli.check_credentials", return_value=False):
            result = runner.invoke(app, ["scan", "-s", VALID_SUB_ID])
            assert result.exit_code == 2
            assert "az login" in result.output

    @patch("az_rbac_watch.cli.discover_policy")
    @patch("az_rbac_watch.cli.scan_rbac")
    @patch("az_rbac_watch.cli.list_accessible_management_groups")
    @patch("az_rbac_watch.cli.list_accessible_subscriptions")
    def test_discover_credential_check_failure(
        self,
        _mock_subs: MagicMock,
        _mock_mgs: MagicMock,
        _mock_scan: MagicMock,
        _mock_discover: MagicMock,
    ) -> None:
        """discover sans credentials → exit code 2."""
        with patch("az_rbac_watch.cli.check_credentials", return_value=False):
            result = runner.invoke(app, ["discover", "-s", VALID_SUB_ID])
            assert result.exit_code == 2
            assert "az login" in result.output


class TestNextStepsFooter:
    """Tests for the 'Next steps' footer after reports."""

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    def test_scan_compliant_shows_ci_hint(self, mock_scan: MagicMock, _mock_resolve: MagicMock, tmp_path: Path) -> None:
        """compliant scan shows CI hint."""
        policy_path = _write_policy(tmp_path, with_baseline_rules=True)
        mock_scan.return_value = _mock_scan_result(with_assignments=False)
        result = runner.invoke(app, ["scan", "--policy", str(policy_path)])
        assert result.exit_code == 0
        assert "All clear" in result.output
        assert "--format json" in result.output

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    def test_scan_findings_shows_review_hint(
        self, mock_scan: MagicMock, _mock_resolve: MagicMock, tmp_path: Path
    ) -> None:
        """scan with findings shows review hint."""
        # Create an assignment that does NOT match the baseline (different principal_id)
        drift_result = RbacScanResult(
            subscription_results=[
                SubscriptionScanResult(
                    subscription_id=VALID_SUB_ID,
                    subscription_name="Test-Sub",
                    assignments=[
                        ScannedRoleAssignment(
                            id="/sub/role/assignment-drift",
                            scope=f"/subscriptions/{VALID_SUB_ID}",
                            role_definition_id="/providers/Microsoft.Authorization/roleDefinitions/xxx",
                            principal_id="unknown-principal",
                            principal_type=PrincipalType.USER,
                            role_name="Contributor",
                        )
                    ],
                )
            ]
        )
        policy_path = _write_policy(tmp_path, with_baseline_rules=True)
        mock_scan.return_value = drift_result
        result = runner.invoke(app, ["scan", "--policy", str(policy_path)])
        assert result.exit_code == 1
        assert "Review findings" in result.output

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    @patch("az_rbac_watch.cli.list_accessible_subscriptions")
    @patch("az_rbac_watch.cli.list_accessible_management_groups")
    def test_audit_adhoc_shows_discover_hint(
        self, mock_mgs: MagicMock, mock_subs: MagicMock, mock_scan: MagicMock, _mock_resolve: MagicMock
    ) -> None:
        """ad-hoc audit shows next steps discover + scan."""
        mock_subs.return_value = [(VALID_SUB_ID, "Prod", VALID_TENANT_ID)]
        mock_mgs.return_value = []
        mock_scan.return_value = _mock_scan_result(with_assignments=True)
        result = runner.invoke(app, ["audit", "-s", VALID_SUB_ID])
        assert "az-rbac-watch discover" in result.output
        assert "az-rbac-watch scan" in result.output

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    def test_audit_with_policy_no_next_steps(
        self, mock_scan: MagicMock, _mock_resolve: MagicMock, tmp_path: Path
    ) -> None:
        """audit with --policy does not show ad-hoc next steps."""
        policy_path = _write_policy(tmp_path, with_governance_rules=True)
        mock_scan.return_value = _mock_scan_result(with_assignments=True)
        result = runner.invoke(app, ["audit", "--policy", str(policy_path)])
        assert "az-rbac-watch discover" not in result.output

    @patch("az_rbac_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_rbac_watch.cli.scan_rbac")
    def test_scan_json_no_next_steps(self, mock_scan: MagicMock, _mock_resolve: MagicMock, tmp_path: Path) -> None:
        """scan --format json does not show next steps."""
        policy_path = _write_policy(tmp_path, with_baseline_rules=True)
        mock_scan.return_value = _mock_scan_result(with_assignments=False)
        result = runner.invoke(app, ["scan", "--policy", str(policy_path), "--format", "json"])
        assert "All clear" not in result.output
        assert "Next steps" not in result.output


class TestOrphansOnlyFlag:
    def test_orphans_only_requires_tenant_id(self) -> None:
        result = runner.invoke(app, ["scan", "--orphans-only"])
        assert result.exit_code == 2

    def test_orphans_only_incompatible_with_policy(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text('version: "2.0"\ntenant_id: "11111111-1111-1111-1111-111111111111"\n')
        result = runner.invoke(app, ["scan", "--orphans-only", "-p", str(policy_file)])
        assert result.exit_code == 2
