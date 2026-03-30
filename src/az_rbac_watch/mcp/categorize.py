"""Group Azure permissions into human-readable categories."""

from __future__ import annotations

__all__ = ["CATEGORY_PREFIXES", "CRITICAL_PATTERNS", "categorize_permissions"]

CATEGORY_PREFIXES: dict[str, list[str]] = {
    "compute": ["Microsoft.Compute/", "Microsoft.ContainerService/", "Microsoft.App/"],
    "network": ["Microsoft.Network/"],
    "storage": ["Microsoft.Storage/", "Microsoft.Sql/", "Microsoft.DocumentDB/", "Microsoft.DBforPostgreSQL/"],
    "keyVault": ["Microsoft.KeyVault/"],
    "iam": ["Microsoft.Authorization/", "Microsoft.ManagedIdentity/"],
    "web": ["Microsoft.Web/"],
    "monitor": ["Microsoft.Insights/", "Microsoft.OperationalInsights/"],
}

CRITICAL_PATTERNS: list[str] = [
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Authorization/roleAssignments/delete",
    "Microsoft.Authorization/elevateAccess/action",
    "Microsoft.KeyVault/vaults/delete",
    "Microsoft.KeyVault/vaults/secrets/write",
    "Microsoft.KeyVault/vaults/secrets/delete",
    "Microsoft.Storage/storageAccounts/delete",
    "Microsoft.Sql/servers/delete",
    "Microsoft.Compute/virtualMachines/delete",
]


def categorize_permissions(actions: list[str]) -> dict[str, list[str]]:
    """Group a list of Azure actions into categories.

    Returns a dict with all category keys (always present, empty list if none),
    plus ``"other"`` for unmatched actions and ``"critical"`` for dangerous actions.
    """
    result: dict[str, list[str]] = {cat: [] for cat in CATEGORY_PREFIXES}
    result["other"] = []
    result["critical"] = []

    critical_lower = {p.lower() for p in CRITICAL_PATTERNS}

    for action in actions:
        action_lower = action.lower()

        # Check critical
        if action_lower in critical_lower:
            result["critical"].append(action)

        # Categorize
        matched = False
        for category, prefixes in CATEGORY_PREFIXES.items():
            for prefix in prefixes:
                if action_lower.startswith(prefix.lower()):
                    result[category].append(action)
                    matched = True
                    break
            if matched:
                break

        if not matched:
            result["other"].append(action)

    return result
