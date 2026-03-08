"""Unit tests for Graph resolution and auto-discovery.

All HTTP/Graph calls are mocked — no credentials required.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from az_rbac_watch.auth.azure_clients import (
    list_accessible_management_groups,
    list_accessible_subscriptions,
    resolve_principal_names,
)
from az_rbac_watch.scanner.discovery import discover_policy
from az_rbac_watch.scanner.rbac_scanner import PrincipalType

from .conftest import VALID_PRINCIPAL_GROUP, VALID_PRINCIPAL_USER, VALID_SUB_ID, VALID_TENANT_ID
from .factories import make_assignment, make_scan_result

# ── Helpers ───────────────────────────────────────────────────


def _make_credential_mock(token_value: str = "fake-token") -> MagicMock:
    cred = MagicMock()
    cred.get_token.return_value = SimpleNamespace(token=token_value)
    return cred


# ── TestResolvePrincipalNames ─────────────────────────────────


class TestResolvePrincipalNames:
    @patch("az_rbac_watch.auth.azure_clients.httpx.post")
    def test_happy_path(self, mock_post: MagicMock):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "value": [
                {
                    "id": VALID_PRINCIPAL_USER,
                    "displayName": "John Doe",
                    "@odata.type": "#microsoft.graph.user",
                },
                {
                    "id": VALID_PRINCIPAL_GROUP,
                    "displayName": "GRP-INFRA",
                    "@odata.type": "#microsoft.graph.group",
                },
            ]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        cred = _make_credential_mock()
        result = resolve_principal_names([VALID_PRINCIPAL_USER, VALID_PRINCIPAL_GROUP], credential=cred)

        assert result[VALID_PRINCIPAL_USER] == ("John Doe", "#microsoft.graph.user")
        assert result[VALID_PRINCIPAL_GROUP] == ("GRP-INFRA", "#microsoft.graph.group")
        cred.get_token.assert_called_once()

    def test_empty_list(self):
        result = resolve_principal_names([])
        assert result == {}

    @patch("az_rbac_watch.auth.azure_clients.httpx.post")
    def test_graph_error_returns_empty(self, mock_post: MagicMock):
        mock_post.side_effect = Exception("Network error")
        cred = _make_credential_mock()
        result = resolve_principal_names(["some-id"], credential=cred)
        assert result == {}

    def test_token_error_returns_empty(self):
        cred = MagicMock()
        cred.get_token.side_effect = Exception("Auth failed")
        result = resolve_principal_names(["some-id"], credential=cred)
        assert result == {}

    @patch("az_rbac_watch.auth.azure_clients.httpx.post")
    def test_batching_over_1000(self, mock_post: MagicMock):
        """With >1000 IDs, 2 HTTP calls are made."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"value": []}
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        cred = _make_credential_mock()
        ids = [f"id-{i}" for i in range(1500)]
        resolve_principal_names(ids, credential=cred)

        assert mock_post.call_count == 2
        # First batch = 1000, second = 500
        first_batch = mock_post.call_args_list[0].kwargs["json"]["ids"]
        second_batch = mock_post.call_args_list[1].kwargs["json"]["ids"]
        assert len(first_batch) == 1000
        assert len(second_batch) == 500


# ── TestDiscoverPolicy ───────────────────────────────────────


class TestDiscoverPolicy:
    @patch("az_rbac_watch.scanner.discovery.resolve_principal_names")
    def test_happy_path(self, mock_resolve: MagicMock):
        mock_resolve.return_value = {
            VALID_PRINCIPAL_USER: ("John Doe", "#microsoft.graph.user"),
            VALID_PRINCIPAL_GROUP: ("GRP-INFRA", "#microsoft.graph.group"),
        }
        scan = make_scan_result(
            [
                make_assignment(
                    principal_id=VALID_PRINCIPAL_USER,
                    principal_type=PrincipalType.USER,
                    role_name="Reader",
                    scope=f"/subscriptions/{VALID_SUB_ID}",
                ),
                make_assignment(
                    principal_id=VALID_PRINCIPAL_GROUP,
                    principal_type=PrincipalType.GROUP,
                    role_name="Contributor",
                    scope=f"/subscriptions/{VALID_SUB_ID}/resourceGroups/rg-infra",
                    assignment_id="a2",
                ),
            ]
        )
        policy = discover_policy(scan, tenant_id=VALID_TENANT_ID)

        assert str(policy.tenant_id) == VALID_TENANT_ID
        assert len(policy.rules) == 2
        # All rules are baseline
        assert all(r.type == "baseline" for r in policy.rules)
        # Verify rule descriptions contain resolved names
        descriptions = {r.description for r in policy.rules}
        assert any("John Doe" in d for d in descriptions)
        assert any("GRP-INFRA" in d for d in descriptions)

    @patch("az_rbac_watch.scanner.discovery.resolve_principal_names")
    def test_unresolved_names_fallback(self, mock_resolve: MagicMock):
        """If resolution fails, use principal_id as display_name."""
        mock_resolve.return_value = {}
        scan = make_scan_result(
            [
                make_assignment(
                    principal_id=VALID_PRINCIPAL_USER,
                    principal_type=PrincipalType.USER,
                    role_name="Reader",
                ),
            ]
        )
        policy = discover_policy(scan, tenant_id=VALID_TENANT_ID)

        assert len(policy.rules) == 1
        rule = policy.rules[0]
        assert rule.type == "baseline"
        assert rule.match.principal_id == VALID_PRINCIPAL_USER
        assert rule.match.role == "Reader"

    @patch("az_rbac_watch.scanner.discovery.resolve_principal_names")
    def test_role_name_none_skipped(self, mock_resolve: MagicMock):
        """Assignments with role_name=None are ignored."""
        mock_resolve.return_value = {}
        scan = make_scan_result(
            [
                make_assignment(role_name=None),
                make_assignment(role_name="Reader", assignment_id="a2", principal_id=VALID_PRINCIPAL_GROUP),
            ]
        )
        policy = discover_policy(scan, tenant_id=VALID_TENANT_ID)
        assert len(policy.rules) == 1

    @patch("az_rbac_watch.scanner.discovery.resolve_principal_names")
    def test_dedup_by_key(self, mock_resolve: MagicMock):
        """Duplicates (same principal_id, role, scope) are deduplicated."""
        mock_resolve.return_value = {}
        scan = make_scan_result(
            [
                make_assignment(
                    principal_id=VALID_PRINCIPAL_USER,
                    role_name="Reader",
                    scope=f"/subscriptions/{VALID_SUB_ID}",
                    assignment_id="a1",
                ),
                make_assignment(
                    principal_id=VALID_PRINCIPAL_USER,
                    role_name="Reader",
                    scope=f"/subscriptions/{VALID_SUB_ID}",
                    assignment_id="a2",
                ),
            ]
        )
        policy = discover_policy(scan, tenant_id=VALID_TENANT_ID)
        assert len(policy.rules) == 1

    @patch("az_rbac_watch.scanner.discovery.resolve_principal_names")
    def test_sorted_output(self, mock_resolve: MagicMock):
        """Rules are sorted by (scope, role, name)."""
        mock_resolve.return_value = {}
        scan = make_scan_result(
            [
                make_assignment(
                    principal_id="bbb",
                    principal_type=PrincipalType.GROUP,
                    role_name="Owner",
                    scope="/subscriptions/zzz",
                    assignment_id="a1",
                ),
                make_assignment(
                    principal_id="aaa",
                    principal_type=PrincipalType.USER,
                    role_name="Reader",
                    scope="/subscriptions/aaa",
                    assignment_id="a2",
                ),
            ]
        )
        policy = discover_policy(scan, tenant_id=VALID_TENANT_ID)
        scopes = [r.match.scope for r in policy.rules]
        assert scopes == ["/subscriptions/aaa", "/subscriptions/zzz"]

    @patch("az_rbac_watch.scanner.discovery.resolve_principal_names")
    def test_empty_scan(self, mock_resolve: MagicMock):
        mock_resolve.return_value = {}
        scan = make_scan_result([])
        policy = discover_policy(scan, tenant_id=VALID_TENANT_ID)
        assert policy.rules == []

    @patch("az_rbac_watch.scanner.discovery.resolve_principal_names")
    def test_credential_passed_through(self, mock_resolve: MagicMock):
        """Credential is passed to resolve_principal_names when there are IDs to resolve."""
        mock_resolve.return_value = {}
        # Need assignments with no display_name so resolve_principal_names is called
        scan = make_scan_result(
            [
                make_assignment(
                    principal_id=VALID_PRINCIPAL_USER,
                    role_name="Reader",
                ),
            ]
        )
        fake_cred = MagicMock()
        discover_policy(scan, tenant_id=VALID_TENANT_ID, credential=fake_cred)
        mock_resolve.assert_called_once()
        assert mock_resolve.call_args.kwargs["credential"] is fake_cred

    @patch("az_rbac_watch.scanner.discovery.resolve_principal_names")
    def test_version_is_2_0(self, mock_resolve: MagicMock):
        """Discovered policy is version 2.0."""
        mock_resolve.return_value = {}
        scan = make_scan_result([])
        policy = discover_policy(scan, tenant_id=VALID_TENANT_ID)
        assert policy.version == "2.0"


# ── TestListAccessibleSubscriptions ────────────────────────────


class TestListAccessibleSubscriptions:
    @patch("az_rbac_watch.auth.azure_clients.SubscriptionClient")
    def test_happy_path(self, mock_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_client.subscriptions.list.return_value = [
            SimpleNamespace(
                subscription_id=VALID_SUB_ID,
                display_name="Prod",
                tenant_id=VALID_TENANT_ID,
                state=SimpleNamespace(value="Enabled"),
            ),
            SimpleNamespace(
                subscription_id="44444444-4444-4444-4444-444444444444",
                display_name="Dev",
                tenant_id=VALID_TENANT_ID,
                state=SimpleNamespace(value="Enabled"),
            ),
        ]

        cred = _make_credential_mock()
        result = list_accessible_subscriptions(credential=cred)

        assert len(result) == 2
        assert result[0] == (VALID_SUB_ID, "Prod", VALID_TENANT_ID)
        assert result[1][1] == "Dev"

    @patch("az_rbac_watch.auth.azure_clients.SubscriptionClient")
    def test_filters_disabled(self, mock_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_client.subscriptions.list.return_value = [
            SimpleNamespace(
                subscription_id=VALID_SUB_ID,
                display_name="Prod",
                tenant_id=VALID_TENANT_ID,
                state=SimpleNamespace(value="Enabled"),
            ),
            SimpleNamespace(
                subscription_id="55555555-5555-5555-5555-555555555555",
                display_name="Disabled-Sub",
                tenant_id=VALID_TENANT_ID,
                state=SimpleNamespace(value="Disabled"),
            ),
        ]

        result = list_accessible_subscriptions(credential=_make_credential_mock())
        assert len(result) == 1
        assert result[0][1] == "Prod"

    @patch("az_rbac_watch.auth.azure_clients.SubscriptionClient")
    def test_sdk_error_propagates(self, mock_cls: MagicMock) -> None:
        mock_cls.side_effect = Exception("SDK error")
        with pytest.raises(Exception, match="SDK error"):
            list_accessible_subscriptions(credential=_make_credential_mock())

    @patch("az_rbac_watch.auth.azure_clients.SubscriptionClient")
    def test_credential_injected(self, mock_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_client.subscriptions.list.return_value = []

        cred = _make_credential_mock()
        list_accessible_subscriptions(credential=cred)
        mock_cls.assert_called_once_with(cred)


# ── TestListAccessibleManagementGroups ─────────────────────────


class TestListAccessibleManagementGroups:
    @patch("az_rbac_watch.auth.azure_clients.ManagementGroupsAPI")
    def test_happy_path(self, mock_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_client.management_groups.list.return_value = [
            SimpleNamespace(name="mg-prod", display_name="Production"),
            SimpleNamespace(name="mg-dev", display_name="Development"),
        ]

        result = list_accessible_management_groups(credential=_make_credential_mock())

        assert len(result) == 2
        assert result[0] == ("mg-prod", "Production")
        assert result[1] == ("mg-dev", "Development")

    @patch("az_rbac_watch.auth.azure_clients.ManagementGroupsAPI")
    def test_sdk_error_propagates(self, mock_cls: MagicMock) -> None:
        mock_cls.side_effect = Exception("No access")
        with pytest.raises(Exception, match="No access"):
            list_accessible_management_groups(credential=_make_credential_mock())

    @patch("az_rbac_watch.auth.azure_clients.ManagementGroupsAPI")
    def test_credential_injected(self, mock_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_client.management_groups.list.return_value = []

        cred = _make_credential_mock()
        list_accessible_management_groups(credential=cred)
        mock_cls.assert_called_once_with(cred)
