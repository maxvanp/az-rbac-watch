"""Tests for Azure Portal URL builders."""

from __future__ import annotations

from az_rbac_watch.utils.portal_links import build_principal_url, build_scope_url


class TestBuildScopeUrl:
    def test_subscription(self) -> None:
        url = build_scope_url("/subscriptions/sub-123", "tenant-abc")
        assert url == "https://portal.azure.com/#@tenant-abc/resource/subscriptions/sub-123/overview"

    def test_resource_group(self) -> None:
        url = build_scope_url(
            "/subscriptions/sub-123/resourceGroups/rg-infra",
            "tenant-abc",
        )
        assert url == (
            "https://portal.azure.com/#@tenant-abc/resource/subscriptions/sub-123/resourceGroups/rg-infra/overview"
        )

    def test_management_group(self) -> None:
        url = build_scope_url(
            "/providers/Microsoft.Management/managementGroups/mg-prod",
            "tenant-abc",
        )
        assert url == (
            "https://portal.azure.com/#view/Microsoft_Azure_ManagementGroups"
            "/ManagmentGroupDrilldownMenuBlade/~/overview"
            "/tenantId/tenant-abc/mgId/mg-prod"
        )

    def test_deep_resource_scope(self) -> None:
        url = build_scope_url(
            "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-1",
            "tenant-abc",
        )
        assert url is not None
        assert "sub-1" in url

    def test_unknown_scope(self) -> None:
        url = build_scope_url("/something/weird", "tenant-abc")
        assert url is None

    def test_empty_scope(self) -> None:
        url = build_scope_url("", "tenant-abc")
        assert url is None

    def test_case_insensitive(self) -> None:
        url = build_scope_url("/Subscriptions/SUB-123", "tenant-abc")
        assert url is not None
        assert "SUB-123" in url


class TestBuildPrincipalUrl:
    def test_normal_id(self) -> None:
        url = build_principal_url("aaaa-bbbb-cccc")
        assert url == (
            "https://portal.azure.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/aaaa-bbbb-cccc"
        )

    def test_empty_id(self) -> None:
        url = build_principal_url("")
        assert url is None
