"""Unit tests for the Azure ARM RBAC scanner.

All Azure SDK calls are mocked — no credentials required.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from az_rbac_watch.config.policy_model import PolicyModel
from az_rbac_watch.scanner.rbac_scanner import (
    ManagementGroupScanResult,
    PrincipalType,
    RbacScanResult,
    RoleType,
    ScannedRoleAssignment,
    ScannedRoleDefinition,
    SubscriptionScanResult,
    extract_role_def_guid,
    resolve_display_names,
    resolve_role_names,
    scan_management_group,
    scan_rbac,
    scan_role_assignments,
    scan_role_assignments_for_scope,
    scan_role_definitions,
    scan_role_definitions_for_scope,
    scan_subscription,
)

from .conftest import VALID_MG_ID, VALID_SUB_ID, VALID_SUB_ID_2, VALID_TENANT_ID

# ── Mock Helpers ──────────────────────────────────────────────

_DEFAULT_ROLE_DEF_ID = (
    f"/subscriptions/{VALID_SUB_ID}/providers/Microsoft.Authorization"
    "/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"
)


def _make_azure_role_assignment(**overrides: object) -> SimpleNamespace:
    """Mock a RoleAssignment object as returned by the Azure SDK."""
    defaults = {
        "id": f"/subscriptions/{VALID_SUB_ID}/providers/Microsoft.Authorization/roleAssignments/assignment-1",
        "scope": f"/subscriptions/{VALID_SUB_ID}",
        "role_definition_id": _DEFAULT_ROLE_DEF_ID,
        "principal_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "principal_type": "User",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_azure_role_definition(**overrides: object) -> SimpleNamespace:
    """Mock a RoleDefinition object as returned by the Azure SDK."""
    defaults = {
        "id": _DEFAULT_ROLE_DEF_ID,
        "role_name": "Reader",
        "role_type": "BuiltInRole",
        "assignable_scopes": ["/"],
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_mock_client(
    assignments: list | None = None,
    definitions: list | None = None,
    scope_assignments: list | None = None,
    scope_definitions: list | None = None,
) -> MagicMock:
    """Create a mock AuthorizationManagementClient."""
    client = MagicMock()
    client.role_assignments.list_for_subscription.return_value = assignments or []
    client.role_assignments.list_for_scope.return_value = scope_assignments or []
    client.role_definitions.list.return_value = definitions or (scope_definitions or [])
    return client


# ── PrincipalType ─────────────────────────────────────────────


class TestPrincipalTypeParsing:
    def test_known_values(self):
        assert PrincipalType.from_azure("User") == PrincipalType.USER
        assert PrincipalType.from_azure("Group") == PrincipalType.GROUP
        assert PrincipalType.from_azure("ServicePrincipal") == PrincipalType.SERVICE_PRINCIPAL
        assert PrincipalType.from_azure("ForeignGroup") == PrincipalType.FOREIGN_GROUP
        assert PrincipalType.from_azure("Device") == PrincipalType.DEVICE

    def test_unknown_value_returns_unknown(self):
        assert PrincipalType.from_azure("SomeNewType") == PrincipalType.UNKNOWN

    def test_none_returns_unknown(self):
        assert PrincipalType.from_azure(None) == PrincipalType.UNKNOWN


# ── extract_role_def_guid ─────────────────────────────────────


class TestExtractRoleDefGuid:
    def test_valid_arm_path(self):
        path = (
            "/subscriptions/xxx/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"
        )
        assert extract_role_def_guid(path) == "acdd72a7-3385-48ef-bd42-f606fba81ae7"

    def test_management_group_path(self):
        path = (
            "/providers/Microsoft.Management/managementGroups/mg-1"
            "/providers/Microsoft.Authorization"
            "/roleDefinitions/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        )
        assert extract_role_def_guid(path) == "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

    def test_invalid_path_returns_none(self):
        assert extract_role_def_guid("/some/random/path") is None

    def test_empty_string_returns_none(self):
        assert extract_role_def_guid("") is None


# ── scan_role_assignments ─────────────────────────────────────


class TestScanRoleAssignments:
    def test_empty_subscription(self):
        client = _make_mock_client(assignments=[])
        result = scan_role_assignments(client)
        assert result == []

    def test_single_assignment(self):
        ra = _make_azure_role_assignment()
        client = _make_mock_client(assignments=[ra])
        result = scan_role_assignments(client)

        assert len(result) == 1
        assert result[0].principal_type == PrincipalType.USER
        assert result[0].principal_id == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        assert result[0].role_name is None  # Not yet resolved

    def test_multiple_assignments(self):
        assignments = [
            _make_azure_role_assignment(principal_type="User"),
            _make_azure_role_assignment(
                id="assignment-2",
                principal_id="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                principal_type="Group",
            ),
            _make_azure_role_assignment(
                id="assignment-3",
                principal_id="cccccccc-cccc-cccc-cccc-cccccccccccc",
                principal_type="ServicePrincipal",
            ),
        ]
        client = _make_mock_client(assignments=assignments)
        result = scan_role_assignments(client)

        assert len(result) == 3
        assert result[0].principal_type == PrincipalType.USER
        assert result[1].principal_type == PrincipalType.GROUP
        assert result[2].principal_type == PrincipalType.SERVICE_PRINCIPAL

    def test_null_fields_handled(self):
        ra = _make_azure_role_assignment(
            id=None,
            scope=None,
            role_definition_id=None,
            principal_id=None,
            principal_type=None,
        )
        client = _make_mock_client(assignments=[ra])
        result = scan_role_assignments(client)

        assert len(result) == 1
        assert result[0].id == ""
        assert result[0].scope == ""
        assert result[0].role_definition_id == ""
        assert result[0].principal_id == ""
        assert result[0].principal_type == PrincipalType.UNKNOWN


# ── scan_role_definitions ─────────────────────────────────────


class TestScanRoleDefinitions:
    def test_builtin_role(self):
        rd = _make_azure_role_definition(role_name="Reader", role_type="BuiltInRole")
        client = _make_mock_client(definitions=[rd])
        result = scan_role_definitions(client, VALID_SUB_ID)

        assert len(result) == 1
        assert result[0].role_name == "Reader"
        assert result[0].role_type == RoleType.BUILT_IN

    def test_custom_role(self):
        rd = _make_azure_role_definition(
            id="/subscriptions/xxx/providers/Microsoft.Authorization/roleDefinitions/custom-guid",
            role_name="My Custom Role",
            role_type="CustomRole",
            assignable_scopes=[f"/subscriptions/{VALID_SUB_ID}"],
        )
        client = _make_mock_client(definitions=[rd])
        result = scan_role_definitions(client, VALID_SUB_ID)

        assert len(result) == 1
        assert result[0].role_name == "My Custom Role"
        assert result[0].role_type == RoleType.CUSTOM

    def test_scope_parameter(self):
        client = _make_mock_client(definitions=[])
        scan_role_definitions(client, VALID_SUB_ID)
        client.role_definitions.list.assert_called_once_with(
            scope=f"/subscriptions/{VALID_SUB_ID}",
        )

    def test_null_assignable_scopes(self):
        rd = _make_azure_role_definition(assignable_scopes=None)
        client = _make_mock_client(definitions=[rd])
        result = scan_role_definitions(client, VALID_SUB_ID)
        assert result[0].assignable_scopes == []


# ── resolve_role_names ────────────────────────────────────────


class TestResolveRoleNames:
    def test_resolves_role_name_and_type(self):
        guid = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
        role_def_id = f"/subscriptions/xxx/providers/Microsoft.Authorization/roleDefinitions/{guid}"

        assignments = [
            ScannedRoleAssignment(
                id="a1",
                scope="/subscriptions/xxx",
                role_definition_id=role_def_id,
                principal_id="p1",
                principal_type=PrincipalType.USER,
            ),
        ]
        definitions = [
            ScannedRoleDefinition(
                id=role_def_id,
                role_name="Reader",
                role_type=RoleType.BUILT_IN,
            ),
        ]

        resolved = resolve_role_names(assignments, definitions)
        assert len(resolved) == 1
        assert resolved[0].role_name == "Reader"
        assert resolved[0].role_type == RoleType.BUILT_IN

    def test_unresolved_role_stays_none(self):
        assignments = [
            ScannedRoleAssignment(
                id="a1",
                scope="/subscriptions/xxx",
                role_definition_id="/some/unknown/roleDefinitions/unknown-guid",
                principal_id="p1",
                principal_type=PrincipalType.USER,
            ),
        ]
        # Pas de definition correspondante
        resolved = resolve_role_names(assignments, [])
        assert resolved[0].role_name is None
        assert resolved[0].role_type is None

    def test_empty_assignments(self):
        resolved = resolve_role_names([], [])
        assert resolved == []

    def test_case_insensitive_guid_matching(self):
        guid_upper = "ACDD72A7-3385-48EF-BD42-F606FBA81AE7"
        guid_lower = "acdd72a7-3385-48ef-bd42-f606fba81ae7"

        assignments = [
            ScannedRoleAssignment(
                id="a1",
                scope="/sub",
                role_definition_id=f"/subscriptions/xxx/providers/Microsoft.Authorization/roleDefinitions/{guid_upper}",
                principal_id="p1",
                principal_type=PrincipalType.USER,
            ),
        ]
        definitions = [
            ScannedRoleDefinition(
                id=f"/subscriptions/xxx/providers/Microsoft.Authorization/roleDefinitions/{guid_lower}",
                role_name="Contributor",
                role_type=RoleType.BUILT_IN,
            ),
        ]

        resolved = resolve_role_names(assignments, definitions)
        assert resolved[0].role_name == "Contributor"


# ── scan_subscription ─────────────────────────────────────────


class TestScanSubscription:
    def test_happy_path(self):
        ra = _make_azure_role_assignment()
        rd = _make_azure_role_definition()
        client = _make_mock_client(assignments=[ra], definitions=[rd])

        result = scan_subscription(client, VALID_SUB_ID, "Test-Sub")

        assert result.subscription_id == VALID_SUB_ID
        assert result.subscription_name == "Test-Sub"
        assert len(result.assignments) == 1
        assert len(result.definitions) == 1
        assert result.errors == []
        # Verify that role_name was resolved
        assert result.assignments[0].role_name == "Reader"

    def test_api_error_captured(self):
        client = _make_mock_client()
        client.role_assignments.list_for_subscription.side_effect = Exception("403 Forbidden")

        result = scan_subscription(client, VALID_SUB_ID, "Bad-Sub")

        assert len(result.errors) == 1
        assert "403 Forbidden" in result.errors[0]
        assert result.assignments == []
        assert result.definitions == []

    def test_default_subscription_name(self):
        client = _make_mock_client()
        result = scan_subscription(client, VALID_SUB_ID)
        assert result.subscription_name == ""


# ── scan_role_assignments_for_scope ───────────────────────────


class TestScanRoleAssignmentsForScope:
    def test_empty_scope(self):
        client = _make_mock_client(scope_assignments=[])
        result = scan_role_assignments_for_scope(client, "/providers/Microsoft.Management/managementGroups/mg-1")
        assert result == []

    def test_single_assignment(self):
        ra = _make_azure_role_assignment(
            scope="/providers/Microsoft.Management/managementGroups/mg-1",
        )
        client = _make_mock_client(scope_assignments=[ra])
        result = scan_role_assignments_for_scope(client, "/providers/Microsoft.Management/managementGroups/mg-1")
        assert len(result) == 1
        assert result[0].principal_type == PrincipalType.USER

    def test_sdk_call_verified(self):
        client = _make_mock_client(scope_assignments=[])
        scope = "/providers/Microsoft.Management/managementGroups/mg-1"
        scan_role_assignments_for_scope(client, scope)
        client.role_assignments.list_for_scope.assert_called_once_with(scope=scope)


# ── scan_role_definitions_for_scope ──────────────────────────


class TestScanRoleDefinitionsForScope:
    def test_empty_scope(self):
        client = _make_mock_client()
        scope = "/providers/Microsoft.Management/managementGroups/mg-1"
        result = scan_role_definitions_for_scope(client, scope)
        assert result == []

    def test_sdk_call_verified(self):
        client = _make_mock_client()
        scope = "/providers/Microsoft.Management/managementGroups/mg-1"
        scan_role_definitions_for_scope(client, scope)
        client.role_definitions.list.assert_called_once_with(scope=scope)


# ── scan_management_group ────────────────────────────────────


class TestScanManagementGroup:
    def test_happy_path(self):
        ra = _make_azure_role_assignment(
            scope=f"/providers/Microsoft.Management/managementGroups/{VALID_MG_ID}",
        )
        rd = _make_azure_role_definition()
        client = _make_mock_client(scope_assignments=[ra])
        # role_definitions.list is shared — set it for the MG scope
        client.role_definitions.list.return_value = [rd]

        result = scan_management_group(client, VALID_MG_ID, "Test-MG")

        assert result.management_group_id == VALID_MG_ID
        assert result.management_group_name == "Test-MG"
        assert len(result.assignments) == 1
        assert result.errors == []
        assert result.assignments[0].role_name == "Reader"

    def test_api_error_captured(self):
        client = _make_mock_client()
        client.role_assignments.list_for_scope.side_effect = Exception("403 Forbidden")

        result = scan_management_group(client, VALID_MG_ID, "Bad-MG")

        assert len(result.errors) == 1
        assert "403 Forbidden" in result.errors[0]
        assert result.assignments == []

    def test_default_name(self):
        client = _make_mock_client()
        result = scan_management_group(client, VALID_MG_ID)
        assert result.management_group_name == ""


# ── RbacScanResult deduplication ─────────────────────────────


class TestRbacScanResultDeduplication:
    def test_mg_and_sub_deduplicated(self):
        """Assignments present in both MG and sub are counted only once."""
        shared_assignment = ScannedRoleAssignment(
            id="shared-assignment-1",
            scope="/providers/Microsoft.Management/managementGroups/mg-1",
            role_definition_id="/roleDefinitions/fake",
            principal_id="p1",
            principal_type=PrincipalType.GROUP,
            role_name="Reader",
        )
        result = RbacScanResult(
            management_group_results=[
                ManagementGroupScanResult(
                    management_group_id="mg-1",
                    management_group_name="MG-1",
                    assignments=[shared_assignment],
                )
            ],
            subscription_results=[
                SubscriptionScanResult(
                    subscription_id=VALID_SUB_ID,
                    subscription_name="Sub-1",
                    assignments=[shared_assignment],
                )
            ],
        )
        assert len(result.all_assignments) == 1

    def test_mg_preferred_over_sub(self):
        """The MG assignment is kept (processed first)."""
        mg_assignment = ScannedRoleAssignment(
            id="same-id",
            scope="/providers/Microsoft.Management/managementGroups/mg-1",
            role_definition_id="/roleDefinitions/fake",
            principal_id="p1",
            principal_type=PrincipalType.GROUP,
            role_name="Reader",
        )
        sub_assignment = ScannedRoleAssignment(
            id="same-id",
            scope=f"/subscriptions/{VALID_SUB_ID}",
            role_definition_id="/roleDefinitions/fake",
            principal_id="p1",
            principal_type=PrincipalType.GROUP,
            role_name="Reader",
        )
        result = RbacScanResult(
            management_group_results=[
                ManagementGroupScanResult(
                    management_group_id="mg-1",
                    management_group_name="MG-1",
                    assignments=[mg_assignment],
                )
            ],
            subscription_results=[
                SubscriptionScanResult(
                    subscription_id=VALID_SUB_ID,
                    subscription_name="Sub-1",
                    assignments=[sub_assignment],
                )
            ],
        )
        all_a = result.all_assignments
        assert len(all_a) == 1
        assert "managementGroups" in all_a[0].scope

    def test_unique_assignments_all_included(self):
        """Assignments with different IDs are all included."""
        mg_a = ScannedRoleAssignment(
            id="mg-only",
            scope="/providers/Microsoft.Management/managementGroups/mg-1",
            role_definition_id="/roleDefinitions/fake",
            principal_id="p1",
            principal_type=PrincipalType.GROUP,
        )
        sub_a = ScannedRoleAssignment(
            id="sub-only",
            scope=f"/subscriptions/{VALID_SUB_ID}",
            role_definition_id="/roleDefinitions/fake",
            principal_id="p2",
            principal_type=PrincipalType.USER,
        )
        result = RbacScanResult(
            management_group_results=[
                ManagementGroupScanResult(
                    management_group_id="mg-1",
                    management_group_name="MG-1",
                    assignments=[mg_a],
                )
            ],
            subscription_results=[
                SubscriptionScanResult(
                    subscription_id=VALID_SUB_ID,
                    subscription_name="Sub-1",
                    assignments=[sub_a],
                )
            ],
        )
        assert len(result.all_assignments) == 2

    def test_errors_combined(self):
        """Errors from MG and subs are all propagated."""
        result = RbacScanResult(
            management_group_results=[
                ManagementGroupScanResult(
                    management_group_id="mg-1",
                    management_group_name="MG-1",
                    errors=["mg error 1"],
                )
            ],
            subscription_results=[
                SubscriptionScanResult(
                    subscription_id=VALID_SUB_ID,
                    subscription_name="Sub-1",
                    errors=["sub error 1"],
                )
            ],
        )
        assert len(result.all_errors) == 2
        assert "mg error 1" in result.all_errors
        assert "sub error 1" in result.all_errors


# ── scan_rbac ─────────────────────────────────────────────────


class TestScanRbac:
    def test_single_subscription(self, minimal_policy: PolicyModel):
        ra = _make_azure_role_assignment()
        rd = _make_azure_role_definition()
        mock_client = _make_mock_client(assignments=[ra], definitions=[rd])

        result = scan_rbac(minimal_policy, client_factory=lambda _: mock_client)

        assert isinstance(result, RbacScanResult)
        assert len(result.subscription_results) == 1
        assert len(result.all_assignments) == 1
        assert result.all_errors == []

    def test_multiple_subscriptions(self):
        policy = PolicyModel(
            version="2.0",
            tenant_id=VALID_TENANT_ID,
            subscriptions=[
                {"id": VALID_SUB_ID, "name": "Sub-1"},
                {"id": VALID_SUB_ID_2, "name": "Sub-2"},
            ],
        )
        rd = _make_azure_role_definition()
        call_count = 0

        def _factory(sub_id: str) -> MagicMock:
            nonlocal call_count
            call_count += 1
            ra = _make_azure_role_assignment(id=f"assignment-{call_count}", scope=f"/subscriptions/{sub_id}")
            return _make_mock_client(assignments=[ra], definitions=[rd])

        result = scan_rbac(policy, client_factory=_factory)

        assert len(result.subscription_results) == 2
        assert len(result.all_assignments) == 2

    def test_no_subscriptions_no_mg(self):
        policy = PolicyModel(
            version="2.0",
            tenant_id=VALID_TENANT_ID,
            subscriptions=[],
            management_groups=[],
        )
        result = scan_rbac(policy, client_factory=lambda _: MagicMock())

        assert len(result.subscription_results) == 0
        assert len(result.management_group_results) == 0
        assert result.all_assignments == []

    def test_client_factory_error(self, minimal_policy: PolicyModel):
        def failing_factory(sub_id: str):
            raise RuntimeError("Auth failed")

        result = scan_rbac(minimal_policy, client_factory=failing_factory)

        assert len(result.subscription_results) == 1
        assert len(result.subscription_results[0].errors) == 1
        assert "Auth failed" in result.subscription_results[0].errors[0]
        assert result.subscription_results[0].assignments == []

    def test_dependency_injection(self, minimal_policy: PolicyModel):
        """Verify that client_factory is called with the correct subscription_id."""
        factory = MagicMock(return_value=_make_mock_client())

        scan_rbac(minimal_policy, client_factory=factory)

        factory.assert_called_once_with(VALID_SUB_ID)

    def test_default_factory_not_called_when_overridden(self, minimal_policy: PolicyModel):
        """Verify that get_authorization_client is not called when injecting a factory."""
        custom_client = _make_mock_client()
        result = scan_rbac(minimal_policy, client_factory=lambda _: custom_client)

        # If we reach here without auth error, it means the default factory was not used
        assert len(result.subscription_results) == 1

    def test_mg_only(self):
        """Scan with only management groups (no subscriptions)."""
        policy = PolicyModel(
            version="2.0",
            tenant_id=VALID_TENANT_ID,
            management_groups=[{"id": VALID_MG_ID, "name": "Test-MG"}],
        )
        ra = _make_azure_role_assignment(
            scope=f"/providers/Microsoft.Management/managementGroups/{VALID_MG_ID}",
        )
        rd = _make_azure_role_definition()
        mock_client = _make_mock_client(scope_assignments=[ra])
        mock_client.role_definitions.list.return_value = [rd]

        result = scan_rbac(policy, client_factory=lambda _: mock_client)

        assert len(result.management_group_results) == 1
        assert len(result.subscription_results) == 0
        assert len(result.all_assignments) == 1

    def test_mg_and_subs(self):
        """Scan with management groups AND subscriptions."""
        policy = PolicyModel(
            version="2.0",
            tenant_id=VALID_TENANT_ID,
            management_groups=[{"id": VALID_MG_ID, "name": "Test-MG"}],
            subscriptions=[{"id": VALID_SUB_ID, "name": "Sub-1"}],
        )
        mg_ra = _make_azure_role_assignment(
            id="mg-assignment-1",
            scope=f"/providers/Microsoft.Management/managementGroups/{VALID_MG_ID}",
        )
        sub_ra = _make_azure_role_assignment(
            id="sub-assignment-1",
            scope=f"/subscriptions/{VALID_SUB_ID}",
        )
        rd = _make_azure_role_definition()
        mock_client = _make_mock_client(
            assignments=[sub_ra],
            definitions=[rd],
            scope_assignments=[mg_ra],
        )
        mock_client.role_definitions.list.return_value = [rd]

        result = scan_rbac(policy, client_factory=lambda _: mock_client)

        assert len(result.management_group_results) == 1
        assert len(result.subscription_results) == 1
        assert len(result.all_assignments) == 2

    def test_mg_factory_error(self):
        """Factory error for an MG is captured."""
        policy = PolicyModel(
            version="2.0",
            tenant_id=VALID_TENANT_ID,
            management_groups=[{"id": VALID_MG_ID, "name": "Test-MG"}],
        )

        def failing_factory(sub_id: str):
            raise RuntimeError("Auth failed")

        result = scan_rbac(policy, client_factory=failing_factory)

        assert len(result.management_group_results) == 1
        assert len(result.management_group_results[0].errors) == 1
        assert "Auth failed" in result.management_group_results[0].errors[0]

    def test_mg_uses_dummy_sub_id_when_no_subs(self):
        """Without subscriptions, the factory receives a dummy sub ID."""
        policy = PolicyModel(
            version="2.0",
            tenant_id=VALID_TENANT_ID,
            management_groups=[{"id": VALID_MG_ID, "name": "Test-MG"}],
        )
        factory = MagicMock(return_value=_make_mock_client())

        scan_rbac(policy, client_factory=factory)

        factory.assert_called_once_with("00000000-0000-0000-0000-000000000000")

    def test_mg_uses_first_sub_id(self):
        """With subscriptions, the factory receives the first sub ID for MG scan."""
        policy = PolicyModel(
            version="2.0",
            tenant_id=VALID_TENANT_ID,
            management_groups=[{"id": VALID_MG_ID, "name": "Test-MG"}],
            subscriptions=[{"id": VALID_SUB_ID, "name": "Sub-1"}],
        )
        factory = MagicMock(return_value=_make_mock_client())

        scan_rbac(policy, client_factory=factory)

        # First call for MG with first sub ID, second call for sub
        assert factory.call_count == 2
        assert factory.call_args_list[0].args[0] == VALID_SUB_ID
        assert factory.call_args_list[1].args[0] == VALID_SUB_ID

    def test_progress_callback_called(self):
        """progress_callback is called once per scope (order may vary with threading)."""
        policy = PolicyModel(
            version="2.0",
            tenant_id=VALID_TENANT_ID,
            management_groups=[{"id": VALID_MG_ID, "name": "Test-MG"}],
            subscriptions=[
                {"id": VALID_SUB_ID, "name": "Sub-1"},
                {"id": VALID_SUB_ID_2, "name": "Sub-2"},
            ],
        )
        factory = MagicMock(return_value=_make_mock_client())
        callback = MagicMock()

        scan_rbac(policy, client_factory=factory, progress_callback=callback)

        assert callback.call_count == 3  # 1 MG + 2 subs
        # Order may vary due to parallel execution — verify all expected calls present
        calls = {c.args for c in callback.call_args_list}
        assert ("mg", "Test-MG") in calls
        assert ("subscription", "Sub-1") in calls
        assert ("subscription", "Sub-2") in calls

    def test_progress_callback_on_error(self):
        """progress_callback is called even when client factory fails."""
        policy = PolicyModel(
            version="2.0",
            tenant_id=VALID_TENANT_ID,
            subscriptions=[{"id": VALID_SUB_ID, "name": "Sub-1"}],
        )

        def failing_factory(sub_id: str):
            raise RuntimeError("Auth failed")

        callback = MagicMock()
        scan_rbac(policy, client_factory=failing_factory, progress_callback=callback)

        assert callback.call_count == 1
        assert callback.call_args.args == ("subscription", "Sub-1")


# ── resolve_display_names ────────────────────────────────────


class TestResolveDisplayNames:
    def test_nominal_case(self):
        """Display names are populated from Graph API resolution."""
        scan = RbacScanResult(
            subscription_results=[
                SubscriptionScanResult(
                    subscription_id=VALID_SUB_ID,
                    subscription_name="Sub-1",
                    assignments=[
                        ScannedRoleAssignment(
                            id="a1",
                            scope=f"/subscriptions/{VALID_SUB_ID}",
                            role_definition_id="/roleDefinitions/fake",
                            principal_id="p1",
                            principal_type=PrincipalType.GROUP,
                            role_name="Reader",
                        ),
                        ScannedRoleAssignment(
                            id="a2",
                            scope=f"/subscriptions/{VALID_SUB_ID}",
                            role_definition_id="/roleDefinitions/fake",
                            principal_id="p2",
                            principal_type=PrincipalType.USER,
                            role_name="Contributor",
                        ),
                    ],
                )
            ],
        )
        with patch(
            "az_rbac_watch.scanner.rbac_scanner.resolve_principal_names",
            return_value={
                "p1": ("GRP-TEAM-INFRA", "#microsoft.graph.group"),
                "p2": ("John Doe", "#microsoft.graph.user"),
            },
        ):
            result = resolve_display_names(scan)

        enriched = result.all_assignments
        assert enriched[0].principal_display_name == "GRP-TEAM-INFRA"
        assert enriched[1].principal_display_name == "John Doe"

    def test_graph_failure_returns_original(self):
        """When Graph API fails (returns {}), scan_result is returned unchanged."""
        scan = RbacScanResult(
            subscription_results=[
                SubscriptionScanResult(
                    subscription_id=VALID_SUB_ID,
                    subscription_name="Sub-1",
                    assignments=[
                        ScannedRoleAssignment(
                            id="a1",
                            scope=f"/subscriptions/{VALID_SUB_ID}",
                            role_definition_id="/roleDefinitions/fake",
                            principal_id="p1",
                            principal_type=PrincipalType.USER,
                            role_name="Reader",
                        ),
                    ],
                )
            ],
        )
        with patch(
            "az_rbac_watch.scanner.rbac_scanner.resolve_principal_names",
            return_value={},
        ):
            result = resolve_display_names(scan)

        assert result.all_assignments[0].principal_display_name is None
        assert len(result.warnings) == 1
        assert "Graph API" in result.warnings[0]

    def test_empty_scan(self):
        """Empty scan result returns unchanged."""
        scan = RbacScanResult()
        with patch(
            "az_rbac_watch.scanner.rbac_scanner.resolve_principal_names",
        ) as mock_resolve:
            result = resolve_display_names(scan)
            mock_resolve.assert_not_called()

        assert result.all_assignments == []

    def test_mg_assignments_enriched(self):
        """Management group assignments are also enriched."""
        scan = RbacScanResult(
            management_group_results=[
                ManagementGroupScanResult(
                    management_group_id=VALID_MG_ID,
                    management_group_name="MG-1",
                    assignments=[
                        ScannedRoleAssignment(
                            id="a1",
                            scope=f"/providers/Microsoft.Management/managementGroups/{VALID_MG_ID}",
                            role_definition_id="/roleDefinitions/fake",
                            principal_id="p1",
                            principal_type=PrincipalType.GROUP,
                            role_name="Reader",
                        ),
                    ],
                )
            ],
        )
        with patch(
            "az_rbac_watch.scanner.rbac_scanner.resolve_principal_names",
            return_value={"p1": ("GRP-PERM-READERS", "#microsoft.graph.group")},
        ):
            result = resolve_display_names(scan)

        assert result.management_group_results[0].assignments[0].principal_display_name == "GRP-PERM-READERS"


# ── TestTypedExceptions ──────────────────────────────────────


class TestTypedExceptions:
    """Tests for specific Azure SDK exception handling."""

    def test_auth_error_subscription(self):
        """ClientAuthenticationError propagates (auth = prerequisite)."""
        from azure.core.exceptions import ClientAuthenticationError

        client = _make_mock_client()
        client.role_assignments.list_for_subscription.side_effect = ClientAuthenticationError(message="Token expired")

        with pytest.raises(ClientAuthenticationError):
            scan_subscription(client, VALID_SUB_ID, "Bad-Sub")

    def test_http_403_subscription(self):
        """HttpResponseError 403 → permission message."""
        from azure.core.exceptions import HttpResponseError

        exc = HttpResponseError(message="Forbidden")
        exc.status_code = 403
        client = _make_mock_client()
        client.role_assignments.list_for_subscription.side_effect = exc

        result = scan_subscription(client, VALID_SUB_ID)
        assert len(result.errors) == 1
        assert "Access denied" in result.errors[0]

    def test_http_429_subscription(self):
        """HttpResponseError 429 → throttling message."""
        from azure.core.exceptions import HttpResponseError

        exc = HttpResponseError(message="Too Many Requests")
        exc.status_code = 429
        client = _make_mock_client()
        client.role_assignments.list_for_subscription.side_effect = exc

        result = scan_subscription(client, VALID_SUB_ID)
        assert len(result.errors) == 1
        assert "throttling" in result.errors[0].lower()

    def test_auth_error_management_group(self):
        """ClientAuthenticationError on MG scan propagates."""
        from azure.core.exceptions import ClientAuthenticationError

        client = _make_mock_client()
        client.role_assignments.list_for_scope.side_effect = ClientAuthenticationError(message="Token expired")

        with pytest.raises(ClientAuthenticationError):
            scan_management_group(client, VALID_MG_ID, "Test-MG")

    def test_http_403_management_group(self):
        """HttpResponseError 403 on MG scan → permission message."""
        from azure.core.exceptions import HttpResponseError

        exc = HttpResponseError(message="Forbidden")
        exc.status_code = 403
        client = _make_mock_client()
        client.role_assignments.list_for_scope.side_effect = exc

        result = scan_management_group(client, VALID_MG_ID)
        assert len(result.errors) == 1
        assert "Access denied" in result.errors[0]

    def test_generic_exception_fallback(self):
        """Unknown exception → generic message."""
        client = _make_mock_client()
        client.role_assignments.list_for_subscription.side_effect = RuntimeError("Something unexpected")

        result = scan_subscription(client, VALID_SUB_ID)
        assert len(result.errors) == 1
        assert "unexpected" in result.errors[0].lower()

    def test_auth_error_factory_sub_propagates(self, minimal_policy: PolicyModel):
        """ClientAuthenticationError in client_factory propagates for subscriptions."""
        from azure.core.exceptions import ClientAuthenticationError

        def auth_failing_factory(sub_id: str):
            raise ClientAuthenticationError(message="No credential available")

        with pytest.raises(ClientAuthenticationError):
            scan_rbac(minimal_policy, client_factory=auth_failing_factory)

    def test_auth_error_factory_mg_propagates(self):
        """ClientAuthenticationError in client_factory propagates for management groups."""
        from azure.core.exceptions import ClientAuthenticationError

        policy = PolicyModel(
            version="2.0",
            tenant_id=VALID_TENANT_ID,
            management_groups=[{"id": VALID_MG_ID, "name": "Test-MG"}],
        )

        def auth_failing_factory(sub_id: str):
            raise ClientAuthenticationError(message="No credential available")

        with pytest.raises(ClientAuthenticationError):
            scan_rbac(policy, client_factory=auth_failing_factory)
