"""Tests for the rbac_blast_radius MCP tool."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from az_rbac_watch.scanner.rbac_scanner import (
    PrincipalType,
    RbacScanResult,
    RoleType,
    ScannedRoleAssignment,
    ScannedRoleDefinition,
    SubscriptionScanResult,
)

# ── Fixtures ────────────────────────────────────────────────────


def _owner_def() -> ScannedRoleDefinition:
    return ScannedRoleDefinition(
        id="/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/owner-guid",
        role_name="Owner",
        role_type=RoleType.BUILT_IN,
        permissions=[{"actions": ["*"], "not_actions": []}],
    )


def _reader_def() -> ScannedRoleDefinition:
    return ScannedRoleDefinition(
        id="/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/reader-guid",
        role_name="Reader",
        role_type=RoleType.BUILT_IN,
        permissions=[{"actions": ["*/read"], "not_actions": []}],
    )


def _contributor_def() -> ScannedRoleDefinition:
    return ScannedRoleDefinition(
        id="/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/contrib-guid",
        role_name="Contributor",
        role_type=RoleType.BUILT_IN,
        permissions=[{
            "actions": ["*"],
            "not_actions": [
                "Microsoft.Authorization/*/Delete",
                "Microsoft.Authorization/*/Write",
                "Microsoft.Authorization/elevateAccess/Action",
            ],
        }],
    )


def _build_scan_result() -> RbacScanResult:
    """Build a scan result with Alice (Owner), Bob (Reader), deploy-sp (Contributor)."""
    definitions = [_owner_def(), _reader_def(), _contributor_def()]

    alice = ScannedRoleAssignment(
        id="/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments/alice-assign",
        scope="/subscriptions/sub-1",
        role_definition_id="/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/owner-guid",
        principal_id="user-alice",
        principal_type=PrincipalType.USER,
        role_name="Owner",
        role_type=RoleType.BUILT_IN,
        principal_display_name="Alice Admin",
    )
    bob = ScannedRoleAssignment(
        id="/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments/bob-assign",
        scope="/subscriptions/sub-1/resourceGroups/rg-dev",
        role_definition_id="/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/reader-guid",
        principal_id="user-bob",
        principal_type=PrincipalType.USER,
        role_name="Reader",
        role_type=RoleType.BUILT_IN,
        principal_display_name="Bob Viewer",
    )
    deploy_sp = ScannedRoleAssignment(
        id="/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments/deploy-assign",
        scope="/subscriptions/sub-1",
        role_definition_id="/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/contrib-guid",
        principal_id="sp-deploy",
        principal_type=PrincipalType.SERVICE_PRINCIPAL,
        role_name="Contributor",
        role_type=RoleType.BUILT_IN,
        principal_display_name="deploy-sp",
    )

    return RbacScanResult(
        subscription_results=[
            SubscriptionScanResult(
                subscription_id="sub-1",
                subscription_name="Test Sub",
                assignments=[alice, bob, deploy_sp],
                definitions=definitions,
            ),
        ],
    )


async def _run_blast_radius(
    principal: str,
    subscription_id: str | None = None,
    scan_result: RbacScanResult | None = None,
) -> dict:
    from az_rbac_watch.mcp.tools.blast_radius import handle_blast_radius

    result = scan_result or _build_scan_result()

    with patch(
        "az_rbac_watch.mcp.tools.blast_radius.scan_subscription_async",
        new_callable=AsyncMock,
        return_value=result,
    ):
        raw = await handle_blast_radius(principal=principal, subscription_id=subscription_id)
    return json.loads(raw)


# ── Tests ───────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestBlastRadius:
    async def test_blast_radius_owner_is_critical(self):
        """Alice (Owner at subscription scope) should have impact 'critical'."""
        result = await _run_blast_radius("Alice Admin")
        assert result["impactScore"] == "critical"

    async def test_blast_radius_reader_is_low(self):
        """Bob (Reader at resource group scope) should have impact 'low'."""
        result = await _run_blast_radius("Bob Viewer")
        assert result["impactScore"] == "low"

    async def test_blast_radius_has_roles(self):
        """Alice's roles list should include Owner."""
        result = await _run_blast_radius("Alice Admin")
        role_names = [r["roleName"] for r in result["roles"]]
        assert "Owner" in role_names

    async def test_blast_radius_effective_permissions(self):
        """Alice (Owner with *) should have iam category populated."""
        result = await _run_blast_radius("Alice Admin")
        assert len(result["effectivePermissions"]["iam"]) > 0

    async def test_blast_radius_critical_access(self):
        """Alice should have critical access flagged."""
        result = await _run_blast_radius("Alice Admin")
        assert len(result["criticalAccess"]) > 0

    async def test_blast_radius_recommendations(self):
        """Alice should get Owner-specific recommendations."""
        result = await _run_blast_radius("Alice Admin")
        assert any("Owner" in r for r in result["recommendations"])

    async def test_blast_radius_unknown_principal(self):
        """NonexistentUser should return impactScore 'none' and empty roles."""
        result = await _run_blast_radius("NonexistentUser")
        assert result["impactScore"] == "none"
        assert result["roles"] == []
