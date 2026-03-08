"""Shared factories for creating test objects.

Centralizes the helpers make_assignment(), make_scan_result(), make_policy()
used by multiple test files.
"""

from __future__ import annotations

from az_rbac_watch.config.policy_model import PolicyModel
from az_rbac_watch.scanner.rbac_scanner import (
    PrincipalType,
    RbacScanResult,
    RoleType,
    ScannedRoleAssignment,
    SubscriptionScanResult,
)

from .conftest import VALID_PRINCIPAL_USER, VALID_SUB_ID, VALID_TENANT_ID


def make_assignment(
    principal_type: PrincipalType = PrincipalType.USER,
    role_name: str | None = "Reader",
    role_type: RoleType | None = RoleType.BUILT_IN,
    scope: str = f"/subscriptions/{VALID_SUB_ID}",
    principal_id: str = VALID_PRINCIPAL_USER,
    assignment_id: str = "assignment-1",
    principal_display_name: str | None = None,
) -> ScannedRoleAssignment:
    return ScannedRoleAssignment(
        id=assignment_id,
        scope=scope,
        role_definition_id="/providers/Microsoft.Authorization/roleDefinitions/fake-guid",
        principal_id=principal_id,
        principal_type=principal_type,
        role_name=role_name,
        role_type=role_type,
        principal_display_name=principal_display_name,
    )


def make_scan_result(
    assignments: list[ScannedRoleAssignment] | None = None,
    errors: list[str] | None = None,
) -> RbacScanResult:
    return RbacScanResult(
        subscription_results=[
            SubscriptionScanResult(
                subscription_id=VALID_SUB_ID,
                subscription_name="Test-Sub",
                assignments=assignments or [],
                errors=errors or [],
            )
        ]
    )


def make_policy(
    rules: list[dict] | None = None,
) -> PolicyModel:
    return PolicyModel(
        version="2.0",
        tenant_id=VALID_TENANT_ID,
        subscriptions=[{"id": VALID_SUB_ID, "name": "Test-Sub"}],
        rules=rules or [],
    )
