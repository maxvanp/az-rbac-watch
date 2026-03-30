"""rbac_blast_radius MCP tool — impact scoring and permission categorization.

Answers: "If this principal (user/SP/group) is compromised, what's the damage?"

For a given principal, finds all role assignments, resolves effective
permissions, categorizes them, flags critical access, computes an impact
score, and generates recommendations.
"""

from __future__ import annotations

import json
import logging

from az_rbac_watch.mcp.azure_scan import collect_all_definitions, scan_subscription_async
from az_rbac_watch.mcp.categorize import CRITICAL_PATTERNS, categorize_permissions
from az_rbac_watch.scanner.rbac_scanner import (
    ScannedRoleAssignment,
    ScannedRoleDefinition,
)

__all__ = ["BLAST_RADIUS_TOOL_DEF", "handle_blast_radius"]

logger = logging.getLogger(__name__)

# ── Tool definition ──────────────────────────────────────────────

BLAST_RADIUS_TOOL_DEF = {
    "name": "rbac_blast_radius",
    "description": (
        "Analyzes the blast radius of a compromised principal. "
        "Returns impact score, effective permissions by category, "
        "critical access flags, and remediation recommendations."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "principal": {
                "type": "string",
                "description": (
                    "Display name (case-insensitive substring match) or "
                    "principal ID (exact match) of the principal to analyze."
                ),
            },
            "subscriptionId": {
                "type": "string",
                "description": (
                    "Azure subscription ID to scan. Omit to scan all accessible subscriptions."
                ),
            },
        },
        "required": ["principal"],
    },
}

# ── Internal helpers ─────────────────────────────────────────────


def _find_principal_assignments(
    principal: str,
    assignments: list[ScannedRoleAssignment],
) -> list[ScannedRoleAssignment]:
    """Find all assignments for a principal by display name (case-insensitive substring) or ID (exact)."""
    matches: list[ScannedRoleAssignment] = []
    principal_lower = principal.lower()
    for a in assignments:
        # Exact match on principal_id
        if a.principal_id == principal:
            matches.append(a)
            continue
        # Case-insensitive substring match on display name
        if a.principal_display_name and principal_lower in a.principal_display_name.lower():
            matches.append(a)
    return matches


def _resolve_effective_actions(
    assignments: list[ScannedRoleAssignment],
    definitions: list[ScannedRoleDefinition],
) -> list[str]:
    """Resolve the effective set of actions from all assignments."""
    # Build a lookup from role definition ID (lowercase) -> definition
    def_lookup: dict[str, ScannedRoleDefinition] = {}
    for d in definitions:
        def_lookup[d.id.lower()] = d

    actions: set[str] = set()
    for assignment in assignments:
        defn = def_lookup.get(assignment.role_definition_id.lower())
        if not defn:
            continue
        for perm in defn.permissions:
            for action in perm.get("actions", []):
                if action == "*":
                    # Wildcard: add all critical patterns plus the marker
                    actions.add("*")
                    actions.update(CRITICAL_PATTERNS)
                else:
                    actions.add(action)
    return sorted(actions)


def _is_subscription_scope(scope: str) -> bool:
    """A subscription scope has <= 2 path segments: /subscriptions/{id}."""
    parts = [p for p in scope.strip("/").split("/") if p]
    return len(parts) <= 2


def _compute_impact_score(
    assignments: list[ScannedRoleAssignment],
    critical_access: list[str],
    categorized: dict[str, list[str]],
) -> str:
    """Compute impact score based on assignments and permissions."""
    if not assignments:
        return "none"

    has_owner_at_sub = any(
        a.role_name == "Owner" and _is_subscription_scope(a.scope)
        for a in assignments
    )
    if has_owner_at_sub:
        return "critical"

    has_iam_access = len(categorized.get("iam", [])) > 0
    has_critical_at_sub = any(
        _is_subscription_scope(a.scope) for a in assignments
    ) and len(critical_access) > 0

    if has_iam_access or has_critical_at_sub:
        return "high"

    if critical_access:
        return "medium"

    return "low"


def _generate_recommendations(
    assignments: list[ScannedRoleAssignment],
    categorized: dict[str, list[str]],
) -> list[str]:
    """Generate recommendations based on findings."""
    recommendations: list[str] = []

    has_owner = any(a.role_name == "Owner" for a in assignments)
    if has_owner:
        recommendations.append("Remove Owner role or scope to specific resource groups")

    has_iam = len(categorized.get("iam", [])) > 0
    if has_iam:
        recommendations.append(
            "IAM write access detected \u2014 consider using PIM for just-in-time elevation"
        )

    has_keyvault = len(categorized.get("keyVault", [])) > 0
    if has_keyvault:
        recommendations.append(
            "Key Vault access detected \u2014 audit recent secret reads/writes"
        )

    return recommendations


# ── Public handler ───────────────────────────────────────────────


async def handle_blast_radius(
    principal: str,
    subscription_id: str | None = None,
) -> str:
    """Returns JSON with principal info, impactScore, roles, effectivePermissions, criticalAccess, recommendations."""

    # 1. Scan Azure RBAC
    scan_result = await scan_subscription_async(subscription_id)

    # 2. Find all assignments for the principal
    all_assignments = scan_result.all_assignments
    principal_assignments = _find_principal_assignments(principal, all_assignments)

    # 3. Resolve effective actions
    all_definitions = collect_all_definitions(scan_result)
    effective_actions = _resolve_effective_actions(principal_assignments, all_definitions)

    # 4. Categorize permissions
    categorized = categorize_permissions(effective_actions)
    critical_access = categorized.pop("critical", [])

    # 5. Compute impact score
    impact_score = _compute_impact_score(principal_assignments, critical_access, categorized)

    # 6. Generate recommendations
    recommendations = _generate_recommendations(principal_assignments, categorized)

    # 7. Build roles list
    roles = [
        {
            "roleName": a.role_name or "(unknown)",
            "scope": a.scope,
            "assignmentId": a.id,
        }
        for a in principal_assignments
    ]

    # 8. Determine principal info from first match
    principal_display = principal
    principal_type = "Unknown"
    principal_id = ""
    if principal_assignments:
        first = principal_assignments[0]
        principal_display = first.principal_display_name or first.principal_id
        principal_type = str(first.principal_type)
        principal_id = first.principal_id

    output = {
        "principal": principal_display,
        "principalType": principal_type,
        "principalId": principal_id,
        "impactScore": impact_score,
        "roles": roles,
        "effectivePermissions": categorized,
        "criticalAccess": critical_access,
        "recommendations": recommendations,
    }

    return json.dumps(output, indent=2)
