"""Fixtures partagées pour les tests Azure Permissions Watch."""

from __future__ import annotations

import pytest

from az_rbac_watch.config.policy_model import PolicyModel

VALID_TENANT_ID = "11111111-1111-1111-1111-111111111111"
VALID_SUB_ID = "22222222-2222-2222-2222-222222222222"
VALID_SUB_ID_2 = "33333333-3333-3333-3333-333333333333"
VALID_MG_ID = "mg-test-001"

VALID_PRINCIPAL_USER = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
VALID_PRINCIPAL_GROUP = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
VALID_PRINCIPAL_SP = "cccccccc-cccc-cccc-cccc-cccccccccccc"
VALID_PRINCIPAL_GUEST = "dddddddd-dddd-dddd-dddd-dddddddddddd"


@pytest.fixture()
def minimal_policy() -> PolicyModel:
    """Retourne un PolicyModel minimal valide avec une subscription."""
    return PolicyModel(
        version="2.0",
        tenant_id=VALID_TENANT_ID,
        subscriptions=[{"id": VALID_SUB_ID, "name": "Test-Sub"}],
    )
