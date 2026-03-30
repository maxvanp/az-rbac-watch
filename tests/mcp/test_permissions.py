"""Tests for permission reverse lookup — action matching and role search."""

from __future__ import annotations

from az_rbac_watch.mcp.permissions import action_matches, find_roles_granting_action
from az_rbac_watch.scanner.rbac_scanner import RoleType, ScannedRoleDefinition


class TestActionMatches:
    def test_exact_action_match(self):
        assert action_matches("Microsoft.Compute/virtualMachines/delete", "Microsoft.Compute/virtualMachines/delete")

    def test_wildcard_star_match(self):
        assert action_matches("Microsoft.Compute/virtualMachines/delete", "*")

    def test_wildcard_provider_match(self):
        assert action_matches("Microsoft.Compute/virtualMachines/delete", "Microsoft.Compute/*")

    def test_partial_wildcard(self):
        assert action_matches("Microsoft.Compute/virtualMachines/delete", "Microsoft.Compute/virtualMachines/*")

    def test_no_match(self):
        assert not action_matches("Microsoft.Storage/storageAccounts/read", "Microsoft.Compute/*")

    def test_case_insensitive(self):
        assert action_matches("microsoft.compute/virtualmachines/delete", "Microsoft.Compute/virtualMachines/delete")
        assert action_matches("Microsoft.Compute/VirtualMachines/Delete", "microsoft.compute/*")

    def test_not_actions_exclusion(self):
        assert not action_matches(
            "Microsoft.Compute/virtualMachines/delete",
            "Microsoft.Compute/*",
            not_actions=["Microsoft.Compute/virtualMachines/delete"],
        )

    def test_not_actions_no_exclusion(self):
        """Action matches pattern and not_actions do not exclude it."""
        assert action_matches(
            "Microsoft.Compute/virtualMachines/start/action",
            "Microsoft.Compute/*",
            not_actions=["Microsoft.Compute/virtualMachines/delete"],
        )


class TestFindRolesGrantingAction:
    def test_find_roles_granting_action(self):
        owner = ScannedRoleDefinition(
            id="/providers/Microsoft.Authorization/roleDefinitions/owner-guid",
            role_name="Owner",
            role_type=RoleType.BUILT_IN,
            permissions=[{"actions": ["*"], "not_actions": [], "data_actions": [], "not_data_actions": []}],
        )
        reader = ScannedRoleDefinition(
            id="/providers/Microsoft.Authorization/roleDefinitions/reader-guid",
            role_name="Reader",
            role_type=RoleType.BUILT_IN,
            permissions=[{"actions": ["*/read"], "not_actions": [], "data_actions": [], "not_data_actions": []}],
        )
        definitions = [owner, reader]

        result = find_roles_granting_action("Microsoft.Compute/virtualMachines/delete", definitions)
        assert len(result) == 1
        assert result[0].role_name == "Owner"

    def test_find_roles_read_action(self):
        reader = ScannedRoleDefinition(
            id="/providers/Microsoft.Authorization/roleDefinitions/reader-guid",
            role_name="Reader",
            role_type=RoleType.BUILT_IN,
            permissions=[{"actions": ["*/read"], "not_actions": [], "data_actions": [], "not_data_actions": []}],
        )
        result = find_roles_granting_action("Microsoft.Compute/virtualMachines/read", [reader])
        assert len(result) == 1
        assert result[0].role_name == "Reader"

    def test_not_actions_in_role(self):
        custom = ScannedRoleDefinition(
            id="/providers/Microsoft.Authorization/roleDefinitions/custom-guid",
            role_name="CustomNoDelete",
            role_type=RoleType.CUSTOM,
            permissions=[{
                "actions": ["Microsoft.Compute/*"],
                "not_actions": ["Microsoft.Compute/virtualMachines/delete"],
                "data_actions": [],
                "not_data_actions": [],
            }],
        )
        result = find_roles_granting_action("Microsoft.Compute/virtualMachines/delete", [custom])
        assert len(result) == 0
