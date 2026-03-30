"""rbac_who_can MCP tool — full permission chain resolution.

Answers: "Who can perform [action] on [scope]?" by resolving the
full Azure RBAC permissions chain: role definitions -> assignments
-> principal names.
"""

from __future__ import annotations

import json
import logging

from az_rbac_watch.mcp.azure_scan import collect_all_definitions, scan_subscription_async
from az_rbac_watch.mcp.permissions import find_roles_granting_action
from az_rbac_watch.scanner.rbac_scanner import (
    ScannedRoleDefinition,
)

__all__ = ["WHO_CAN_TOOL_DEF", "handle_who_can"]

logger = logging.getLogger(__name__)

# ── Tool definition ──────────────────────────────────────────────

WHO_CAN_TOOL_DEF = {
    "name": "rbac_who_can",
    "description": (
        "Answers 'Who can perform [action] on [scope]?' by resolving the full "
        "Azure RBAC permissions chain: finds matching role definitions, "
        "assignments (including inherited from parent scopes), and principal names."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "description": (
                    "Azure RBAC action to check, e.g. "
                    "'Microsoft.Compute/virtualMachines/delete'."
                ),
            },
            "scope": {
                "type": "string",
                "description": (
                    "Azure ARM scope to check, e.g. "
                    "'/subscriptions/{id}/resourceGroups/{name}'."
                ),
            },
            "subscriptionId": {
                "type": "string",
                "description": (
                    "Azure subscription ID. If omitted, extracted from scope."
                ),
            },
        },
        "required": ["action", "scope"],
    },
}

# ── Internal helpers ─────────────────────────────────────────────


def _extract_subscription_id(scope: str) -> str | None:
    """Extract subscription ID from an ARM scope string.

    ``/subscriptions/{id}/...`` -> ``{id}``
    """
    parts = scope.strip("/").split("/")
    # Expected: ["subscriptions", "{id}", ...]
    if len(parts) >= 2 and parts[0].lower() == "subscriptions":
        return parts[1]
    return None


def _scope_covers(assignment_scope: str, target_scope: str) -> bool:
    """Check if an assignment scope covers the target scope (scope inheritance).

    An assignment at ``/subscriptions/sub-1`` covers
    ``/subscriptions/sub-1/resourceGroups/rg-prod/...``.
    """
    return target_scope.lower().startswith(assignment_scope.lower())


def _build_role_def_id_set(definitions: list[ScannedRoleDefinition]) -> set[str]:
    """Build a set of role definition IDs (lowercase) for fast lookup."""
    return {d.id.lower() for d in definitions}


# ── Public handler ───────────────────────────────────────────────


async def handle_who_can(
    action: str,
    scope: str,
    subscription_id: str | None = None,
) -> str:
    """Returns JSON with action, scope, totalPrincipals, matchingRoles, principals."""

    # 1. Resolve subscription ID
    if not subscription_id:
        subscription_id = _extract_subscription_id(scope)

    # 2. Scan Azure RBAC
    scan_result = await scan_subscription_async(subscription_id)

    # 3. Find role definitions that grant the requested action
    all_definitions = collect_all_definitions(scan_result)
    granting_roles = find_roles_granting_action(action, all_definitions)
    granting_role_ids = _build_role_def_id_set(granting_roles)
    granting_role_names = sorted({d.role_name for d in granting_roles})

    # 4. Build a map from role_definition_id -> role_name for granting roles
    role_id_to_name: dict[str, str] = {}
    for d in granting_roles:
        role_id_to_name[d.id.lower()] = d.role_name

    # 5. Find assignments that match: role grants the action AND scope covers target
    all_assignments = scan_result.all_assignments
    principals: list[dict] = []

    for assignment in all_assignments:
        # Check if this assignment's role grants the action
        if assignment.role_definition_id.lower() not in granting_role_ids:
            continue

        # Check scope inheritance: assignment scope must cover the target scope
        if not _scope_covers(assignment.scope, scope):
            continue

        inherited = assignment.scope.lower() != scope.lower()
        role_name = role_id_to_name.get(
            assignment.role_definition_id.lower(),
            assignment.role_name or "(unknown)",
        )

        principals.append({
            "name": assignment.principal_display_name or assignment.principal_id,
            "principalId": assignment.principal_id,
            "principalType": str(assignment.principal_type),
            "via": {
                "role": role_name,
                "assignmentScope": assignment.scope,
                "inherited": inherited,
            },
        })

    output = {
        "action": action,
        "scope": scope,
        "totalPrincipals": len(principals),
        "matchingRoles": granting_role_names,
        "principals": principals,
    }

    return json.dumps(output, indent=2)
