"""Tests for action categorization."""

from __future__ import annotations

from az_rbac_watch.mcp.categorize import CATEGORY_PREFIXES, categorize_permissions


class TestCategorizePermissions:
    def test_categorize_compute_actions(self):
        result = categorize_permissions(["Microsoft.Compute/virtualMachines/read"])
        assert result["compute"] == ["Microsoft.Compute/virtualMachines/read"]

    def test_categorize_multiple_categories(self):
        actions = [
            "Microsoft.Compute/virtualMachines/read",
            "Microsoft.Network/virtualNetworks/read",
            "Microsoft.Storage/storageAccounts/read",
        ]
        result = categorize_permissions(actions)
        assert result["compute"] == ["Microsoft.Compute/virtualMachines/read"]
        assert result["network"] == ["Microsoft.Network/virtualNetworks/read"]
        assert result["storage"] == ["Microsoft.Storage/storageAccounts/read"]

    def test_categorize_critical_flagging(self):
        actions = [
            "Microsoft.Authorization/roleAssignments/write",
            "Microsoft.KeyVault/vaults/delete",
        ]
        result = categorize_permissions(actions)
        assert "Microsoft.Authorization/roleAssignments/write" in result["critical"]
        assert "Microsoft.KeyVault/vaults/delete" in result["critical"]
        # Also in their respective categories
        assert "Microsoft.Authorization/roleAssignments/write" in result["iam"]
        assert "Microsoft.KeyVault/vaults/delete" in result["keyVault"]

    def test_categorize_other(self):
        result = categorize_permissions(["Microsoft.CognitiveServices/accounts/read"])
        assert result["other"] == ["Microsoft.CognitiveServices/accounts/read"]

    def test_categorize_empty(self):
        result = categorize_permissions([])
        for cat in CATEGORY_PREFIXES:
            assert result[cat] == []
        assert result["other"] == []
        assert result["critical"] == []
