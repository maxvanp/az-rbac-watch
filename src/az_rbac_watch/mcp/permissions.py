"""Azure action wildcard matching and role reverse lookup."""

from __future__ import annotations

from fnmatch import fnmatch

from az_rbac_watch.scanner.rbac_scanner import ScannedRoleDefinition

__all__ = ["action_matches", "find_roles_granting_action"]


def action_matches(action: str, pattern: str, not_actions: list[str] | None = None) -> bool:
    """Check if an Azure action matches a permission pattern.

    Azure uses fnmatch-style wildcards (case-insensitive):
    - ``*`` matches everything
    - ``Microsoft.Compute/*`` matches ``Microsoft.Compute/virtualMachines/delete``

    If *not_actions* is provided, returns False when the action matches any
    notAction pattern, even if it matches the main pattern.
    """
    action_lower = action.lower()
    pattern_lower = pattern.lower()

    if not fnmatch(action_lower, pattern_lower):
        return False

    if not_actions:
        for na in not_actions:
            if fnmatch(action_lower, na.lower()):
                return False

    return True


def find_roles_granting_action(action: str, definitions: list[ScannedRoleDefinition]) -> list[ScannedRoleDefinition]:
    """Find all role definitions that grant the given Azure action.

    For each role definition, checks every permission block's ``actions`` list.
    A role grants the action if any action pattern matches AND no
    ``not_actions`` pattern excludes it.
    """
    result: list[ScannedRoleDefinition] = []
    for defn in definitions:
        if _role_grants_action(action, defn):
            result.append(defn)
    return result


def _role_grants_action(action: str, defn: ScannedRoleDefinition) -> bool:
    """Return True if the role definition grants the given action."""
    for perm in defn.permissions:
        actions = perm.get("actions", [])
        not_actions = perm.get("not_actions", [])
        for pattern in actions:
            if action_matches(action, pattern, not_actions or None):
                return True
    return False
