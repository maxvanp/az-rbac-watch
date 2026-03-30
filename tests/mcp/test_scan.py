"""Tests for the rbac_scan MCP tool."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from az_rbac_watch.scanner.rbac_scanner import (
    PrincipalType,
    RbacScanResult,
    RoleType,
    ScannedRoleAssignment,
    SubscriptionScanResult,
)

# ── Helpers ──────────────────────────────────────────────────────


def _make_assignment(
    *,
    principal_id: str = "user-1",
    principal_display_name: str | None = "Alice",
    principal_type: PrincipalType = PrincipalType.USER,
    role_name: str = "Reader",
    scope: str = "/subscriptions/sub-1",
    role_type: RoleType = RoleType.BUILT_IN,
) -> ScannedRoleAssignment:
    return ScannedRoleAssignment(
        id=f"/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments/{principal_id}",
        scope=scope,
        role_definition_id="/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/fake-guid",
        principal_id=principal_id,
        principal_type=principal_type,
        role_name=role_name,
        role_type=role_type,
        principal_display_name=principal_display_name,
    )


def _make_scan_result(
    assignments: list[ScannedRoleAssignment],
    subscription_id: str = "sub-1",
) -> RbacScanResult:
    return RbacScanResult(
        subscription_results=[
            SubscriptionScanResult(
                subscription_id=subscription_id,
                subscription_name="Test Subscription",
                assignments=assignments,
            )
        ],
    )


# ── Tests ────────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestScanTool:
    """Tests for handle_scan."""

    async def _run_scan(
        self,
        assignments: list[ScannedRoleAssignment],
        subscription_id: str | None = "00000000-0000-0000-0000-000000000001",
        policy_path: str | None = None,
    ) -> dict:
        """Helper: mock Azure scanning and run handle_scan, return parsed JSON."""
        from az_rbac_watch.mcp.tools.scan import handle_scan

        scan_result = _make_scan_result(assignments, subscription_id or "sub-1")

        with patch(
            "az_rbac_watch.mcp.tools.scan.scan_subscription_async",
            new_callable=AsyncMock,
            return_value=scan_result,
        ):
            raw = await handle_scan(
                subscription_id=subscription_id,
                policy_path=policy_path,
            )
        return json.loads(raw)

    async def test_scan_returns_risk_score(self):
        assignments = [
            _make_assignment(role_name="Owner", principal_id="u1", principal_display_name="Alice Admin"),
        ]
        result = await self._run_scan(assignments)
        assert "riskScore" in result
        assert 0 <= result["riskScore"] <= 100

    async def test_scan_returns_findings(self):
        assignments = [
            _make_assignment(
                role_name="Owner",
                scope="/subscriptions/sub-1",
                principal_id="u1",
                principal_display_name="Alice Admin",
            ),
        ]
        result = await self._run_scan(assignments)
        assert len(result["findings"]) > 0
        # Should have the no-owner-at-subscription rule
        rule_ids = [f["rule"] for f in result["findings"]]
        assert "no-owner-at-subscription" in rule_ids

    async def test_scan_detects_orphans(self):
        assignments = [
            _make_assignment(
                principal_id="deleted-id",
                principal_display_name=None,
                principal_type=PrincipalType.UNKNOWN,
                role_name="Contributor",
            ),
        ]
        result = await self._run_scan(assignments)
        assert len(result["orphans"]) == 1
        assert result["orphans"][0]["principalId"] == "deleted-id"

    async def test_scan_returns_summary_stats(self):
        assignments = [
            _make_assignment(principal_id="u1", role_name="Reader"),
            _make_assignment(principal_id="u2", role_name="Reader"),
            _make_assignment(
                principal_id="sp1",
                role_name="Contributor",
                principal_type=PrincipalType.SERVICE_PRINCIPAL,
                principal_display_name="My SP",
            ),
        ]
        result = await self._run_scan(assignments)
        summary = result["summary"]
        assert summary["totalAssignments"] == 3
        assert summary["roleDistribution"]["Reader"] == 2
        assert summary["roleDistribution"]["Contributor"] == 1
        assert summary["subscriptionsScanned"] == 1

    async def test_scan_returns_top_actions(self):
        assignments = [
            _make_assignment(
                role_name="Owner",
                principal_id="u1",
                principal_display_name="Alice Admin",
            ),
        ]
        result = await self._run_scan(assignments)
        assert len(result["topActions"]) >= 1

    async def test_scan_with_no_findings(self):
        """Reader-only assignments by a ServicePrincipal generate no findings with default rules."""
        assignments = [
            _make_assignment(
                principal_id="sp1",
                principal_display_name="Read-Only SP",
                principal_type=PrincipalType.SERVICE_PRINCIPAL,
                role_name="Reader",
                role_type=RoleType.BUILT_IN,
            ),
        ]
        result = await self._run_scan(assignments)
        assert result["riskScore"] == 0
        assert len(result["findings"]) == 0
        assert len(result["orphans"]) == 0
