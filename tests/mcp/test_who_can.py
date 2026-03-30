"""Tests for the rbac_who_can MCP tool."""

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


async def _run_who_can(
    action: str,
    scope: str,
    subscription_id: str | None = None,
    scan_result: RbacScanResult | None = None,
) -> dict:
    from az_rbac_watch.mcp.tools.who_can import handle_who_can

    result = scan_result or _build_scan_result()

    with patch(
        "az_rbac_watch.mcp.tools.who_can.scan_subscription_async",
        new_callable=AsyncMock,
        return_value=result,
    ):
        raw = await handle_who_can(action=action, scope=scope, subscription_id=subscription_id)
    return json.loads(raw)


# ── Tests ───────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestWhoCanTool:
    async def test_who_can_finds_owner(self):
        """Alice (Owner at /subscriptions/sub-1) is found for delete on that scope."""
        result = await _run_who_can(
            action="Microsoft.Compute/virtualMachines/delete",
            scope="/subscriptions/sub-1",
        )
        assert result["action"] == "Microsoft.Compute/virtualMachines/delete"
        assert result["scope"] == "/subscriptions/sub-1"
        principal_ids = [p["principalId"] for p in result["principals"]]
        assert "user-alice" in principal_ids
        alice = next(p for p in result["principals"] if p["principalId"] == "user-alice")
        assert alice["via"]["role"] == "Owner"
        assert alice["via"]["inherited"] is False

    async def test_who_can_excludes_reader(self):
        """Bob (Reader) should NOT appear for a delete action."""
        result = await _run_who_can(
            action="Microsoft.Compute/virtualMachines/delete",
            scope="/subscriptions/sub-1/resourceGroups/rg-dev",
        )
        principal_ids = [p["principalId"] for p in result["principals"]]
        assert "user-bob" not in principal_ids

    async def test_who_can_includes_contributor(self):
        """deploy-sp (Contributor) grants Compute delete (notActions only exclude Authorization/*)."""
        result = await _run_who_can(
            action="Microsoft.Compute/virtualMachines/delete",
            scope="/subscriptions/sub-1",
        )
        principal_ids = [p["principalId"] for p in result["principals"]]
        assert "sp-deploy" in principal_ids
        sp = next(p for p in result["principals"] if p["principalId"] == "sp-deploy")
        assert sp["via"]["role"] == "Contributor"

    async def test_who_can_scope_inheritance(self):
        """Alice (Owner at /subscriptions/sub-1) is found for action on child scope."""
        result = await _run_who_can(
            action="Microsoft.Compute/virtualMachines/delete",
            scope="/subscriptions/sub-1/resourceGroups/rg-prod",
        )
        principal_ids = [p["principalId"] for p in result["principals"]]
        assert "user-alice" in principal_ids
        alice = next(p for p in result["principals"] if p["principalId"] == "user-alice")
        assert alice["via"]["inherited"] is True
        assert alice["via"]["assignmentScope"] == "/subscriptions/sub-1"

    async def test_who_can_no_match_wrong_scope(self):
        """Nobody found for action on a scope under a different subscription."""
        result = await _run_who_can(
            action="Microsoft.Compute/virtualMachines/delete",
            scope="/subscriptions/sub-999/resourceGroups/rg-other",
            subscription_id="sub-1",
        )
        assert result["totalPrincipals"] == 0
        assert result["principals"] == []

    async def test_who_can_matching_roles(self):
        """matchingRoles should list role names that grant the action."""
        result = await _run_who_can(
            action="Microsoft.Compute/virtualMachines/delete",
            scope="/subscriptions/sub-1",
        )
        assert "Owner" in result["matchingRoles"]
        assert "Contributor" in result["matchingRoles"]
        assert "Reader" not in result["matchingRoles"]

    async def test_who_can_extracts_subscription_from_scope(self):
        """When subscription_id not provided, it should be extracted from scope."""
        result = await _run_who_can(
            action="Microsoft.Compute/virtualMachines/delete",
            scope="/subscriptions/sub-1/resourceGroups/rg-prod",
        )
        # Should work without subscription_id (extracted from scope)
        assert result["totalPrincipals"] > 0
