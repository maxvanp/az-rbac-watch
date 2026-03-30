"""Tests for the shared MCP scanning helper."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from az_rbac_watch.scanner.rbac_scanner import (
    RbacScanResult,
    ScannedRoleAssignment,
    ScannedRoleDefinition,
    SubscriptionScanResult,
)


@pytest.fixture
def mock_scan_result():
    assignment = ScannedRoleAssignment(
        id="/sub/123/assignment/1",
        principal_id="p-1",
        principal_type="User",
        role_definition_id="role-def-1",
        role_name="Reader",
        scope="/subscriptions/sub-123",
    )
    definition = ScannedRoleDefinition(
        id="role-def-1",
        role_name="Reader",
        role_type="BuiltInRole",
        permissions=[{"actions": ["*/read"], "notActions": []}],
    )
    sub_result = SubscriptionScanResult(
        subscription_id="sub-123",
        subscription_name="Test Sub",
        assignments=[assignment],
        definitions=[definition],
    )
    return RbacScanResult(subscription_results=[sub_result])


@pytest.mark.asyncio
async def test_scan_subscription_specific(mock_scan_result):
    from az_rbac_watch.mcp.azure_scan import scan_subscription_async

    with (
        patch("az_rbac_watch.mcp.azure_scan.get_authorization_client") as mock_client,
        patch("az_rbac_watch.mcp.azure_scan.scan_subscription") as mock_scan,
        patch(
            "az_rbac_watch.mcp.azure_scan.resolve_display_names",
            side_effect=lambda r: r,
        ),
    ):
        mock_scan.return_value = mock_scan_result.subscription_results[0]
        result = await scan_subscription_async("sub-123")

    assert len(result.subscription_results) == 1
    assert result.subscription_results[0].subscription_id == "sub-123"
    mock_client.assert_called_once_with("sub-123")


@pytest.mark.asyncio
async def test_scan_subscription_all(mock_scan_result):
    from az_rbac_watch.mcp.azure_scan import scan_subscription_async

    with (
        patch(
            "az_rbac_watch.mcp.azure_scan.list_accessible_subscriptions",
            return_value=[("sub-123", "Test Sub", "tenant-1")],
        ),
        patch("az_rbac_watch.mcp.azure_scan.get_authorization_client"),
        patch("az_rbac_watch.mcp.azure_scan.scan_subscription") as mock_scan,
        patch(
            "az_rbac_watch.mcp.azure_scan.resolve_display_names",
            side_effect=lambda r: r,
        ),
    ):
        mock_scan.return_value = mock_scan_result.subscription_results[0]
        result = await scan_subscription_async(None)

    assert len(result.subscription_results) == 1


def test_collect_all_definitions(mock_scan_result):
    from az_rbac_watch.mcp.azure_scan import collect_all_definitions

    definitions = collect_all_definitions(mock_scan_result)
    assert len(definitions) == 1
    assert definitions[0].role_name == "Reader"


def test_collect_all_definitions_deduplicates():
    from az_rbac_watch.mcp.azure_scan import collect_all_definitions

    defn = ScannedRoleDefinition(
        id="role-def-1",
        role_name="Reader",
        role_type="BuiltInRole",
        permissions=[],
    )
    result = RbacScanResult(
        subscription_results=[
            SubscriptionScanResult(
                subscription_id="sub-1",
                subscription_name="Sub 1",
                assignments=[],
                definitions=[defn],
            ),
            SubscriptionScanResult(
                subscription_id="sub-2",
                subscription_name="Sub 2",
                assignments=[],
                definitions=[defn],
            ),
        ]
    )
    definitions = collect_all_definitions(result)
    assert len(definitions) == 1
