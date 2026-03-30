"""Tests for the rbac_discover MCP tool."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
import yaml

from az_rbac_watch.scanner.rbac_scanner import (
    PrincipalType,
    RbacScanResult,
    RoleType,
    ScannedRoleAssignment,
    SubscriptionScanResult,
)

# ── Helpers ──────────────────────────────────────────────────────


_SUB_ID = "00000000-0000-0000-0000-000000000001"


def _make_assignment(
    *,
    principal_id: str = "user-1",
    principal_display_name: str | None = "Alice Admin",
    principal_type: PrincipalType = PrincipalType.USER,
    role_name: str = "Reader",
    scope: str = f"/subscriptions/{_SUB_ID}",
    role_type: RoleType = RoleType.BUILT_IN,
) -> ScannedRoleAssignment:
    return ScannedRoleAssignment(
        id=f"/subscriptions/{_SUB_ID}/providers/Microsoft.Authorization/roleAssignments/{principal_id}",
        scope=scope,
        role_definition_id=f"/subscriptions/{_SUB_ID}/providers/Microsoft.Authorization/roleDefinitions/fake-guid",
        principal_id=principal_id,
        principal_type=principal_type,
        role_name=role_name,
        role_type=role_type,
        principal_display_name=principal_display_name,
    )


def _make_scan_result(
    assignments: list[ScannedRoleAssignment],
    subscription_id: str = _SUB_ID,
    subscription_name: str = "Test Subscription",
) -> RbacScanResult:
    return RbacScanResult(
        subscription_results=[
            SubscriptionScanResult(
                subscription_id=subscription_id,
                subscription_name=subscription_name,
                assignments=assignments,
            )
        ],
    )


# ── Tests ────────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestDiscoverTool:
    """Tests for handle_discover."""

    async def _run_discover(
        self,
        assignments: list[ScannedRoleAssignment],
        subscription_id: str | None = _SUB_ID,
        output_path: str | None = None,
    ) -> tuple[dict, str]:
        """Helper: mock Azure scanning and run handle_discover, return parsed JSON and output path."""
        from az_rbac_watch.mcp.tools.discover import handle_discover

        scan_result = _make_scan_result(assignments, subscription_id or "sub-1")

        with patch(
            "az_rbac_watch.mcp.tools.discover._scan_subscription",
            new_callable=AsyncMock,
            return_value=scan_result,
        ):
            kwargs: dict = {}
            if subscription_id is not None:
                kwargs["subscription_id"] = subscription_id
            if output_path is not None:
                kwargs["output_path"] = output_path
            raw = await handle_discover(**kwargs)
            return json.loads(raw), output_path or "./cloudsight.yaml"

    async def test_discover_generates_yaml_file(self) -> None:
        """File exists at output path, contains 'version' and 'rules'."""
        assignments = [_make_assignment()]
        with tempfile.TemporaryDirectory() as tmpdir:
            out = str(Path(tmpdir) / "cloudsight.yaml")
            _result, _ = await self._run_discover(assignments, output_path=out)

            path = Path(out)
            assert path.exists(), "YAML file should be created"
            content = path.read_text()
            assert "version" in content
            assert "rules" in content

    async def test_discover_baseline_rules_from_assignments(self) -> None:
        """Each unique assignment has a baseline rule."""
        assignments = [
            _make_assignment(principal_id="user-alice", role_name="Owner", principal_display_name="Alice Admin"),
            _make_assignment(principal_id="user-bob", role_name="Reader", principal_display_name="Bob Dev"),
            # Duplicate of alice — should be deduplicated
            _make_assignment(principal_id="user-alice", role_name="Owner", principal_display_name="Alice Admin"),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            out = str(Path(tmpdir) / "cloudsight.yaml")
            _result, _ = await self._run_discover(assignments, output_path=out)

            content = Path(out).read_text()
            parsed = yaml.safe_load(content)
            baseline_rules = [r for r in parsed["rules"] if r["type"] == "baseline"]
            # 2 unique assignments → 2 baseline rules
            assert len(baseline_rules) == 2

    async def test_discover_includes_governance_rules(self) -> None:
        """Default governance rules present (no-owner-at-subscription)."""
        assignments = [_make_assignment()]
        with tempfile.TemporaryDirectory() as tmpdir:
            out = str(Path(tmpdir) / "cloudsight.yaml")
            _result, _ = await self._run_discover(assignments, output_path=out)

            content = Path(out).read_text()
            parsed = yaml.safe_load(content)
            governance_rules = [r for r in parsed["rules"] if r["type"] == "governance"]
            assert len(governance_rules) > 0
            rule_names = [r["name"] for r in governance_rules]
            assert "no-owner-at-subscription" in rule_names

    async def test_discover_summary_counts(self) -> None:
        """Summary has correct counts."""
        assignments = [
            _make_assignment(principal_id="user-alice", role_name="Owner"),
            _make_assignment(principal_id="user-bob", role_name="Reader"),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            out = str(Path(tmpdir) / "cloudsight.yaml")
            result, _ = await self._run_discover(assignments, output_path=out)

            summary = result["summary"]
            assert summary["subscriptionsDiscovered"] == 1
            assert summary["assignmentsBaselined"] == 2
            # 2 baseline + 3 default governance = 5
            assert summary["rulesGenerated"] == 5

    async def test_discover_next_steps(self) -> None:
        """nextSteps is non-empty list."""
        assignments = [_make_assignment()]
        with tempfile.TemporaryDirectory() as tmpdir:
            out = str(Path(tmpdir) / "cloudsight.yaml")
            result, _ = await self._run_discover(assignments, output_path=out)

            assert isinstance(result["nextSteps"], list)
            assert len(result["nextSteps"]) > 0
