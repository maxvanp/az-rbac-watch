"""Auto-discovery : génère un PolicyModel draft depuis un scan RBAC.

Scanne les assignations RBAC existantes et résout les noms de principals
via Microsoft Graph pour produire un YAML lisible que l'utilisateur revoit.
Les assignations sont converties en baseline rules.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING
from uuid import UUID

from az_rbac_watch.auth.azure_clients import resolve_principal_names
from az_rbac_watch.config.policy_model import (
    ManagementGroup,
    PolicyModel,
    Rule,
    RuleMatch,
    Subscription,
)
from az_rbac_watch.scanner.rbac_scanner import RbacScanResult

__all__ = ["discover_policy"]

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential

logger = logging.getLogger(__name__)

# Mapping odata.type → principal_type lisible
_ODATA_TYPE_MAP: dict[str, str] = {
    "#microsoft.graph.user": "User",
    "#microsoft.graph.group": "Group",
    "#microsoft.graph.servicePrincipal": "ServicePrincipal",
    "#microsoft.graph.device": "Device",
}


def _slugify_rule_name(display_name: str, role: str, scope: str) -> str:
    """Generate a human-readable rule name from assignment details."""
    # Use display name if available, otherwise extract last part of scope
    base = display_name or scope.rsplit("/", 1)[-1]
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", base).strip("-").lower()
    role_slug = re.sub(r"[^a-zA-Z0-9]+", "-", role).strip("-").lower()
    return f"{slug}-{role_slug}"


def discover_policy(
    scan_result: RbacScanResult,
    tenant_id: str,
    subscriptions: list[Subscription] | None = None,
    management_groups: list[ManagementGroup] | None = None,
    credential: TokenCredential | None = None,
) -> PolicyModel:
    """Génère un PolicyModel draft depuis un scan RBAC existant.

    Args:
        scan_result: Résultat d'un scan RBAC.
        tenant_id: Identifiant du tenant Azure.
        subscriptions: Subscriptions scannées (pour les inclure dans le YAML).
        management_groups: Management groups scannés.
        credential: Credential pour la résolution Graph (optionnel).

    Returns:
        Un PolicyModel v2.0 avec des baseline rules pour chaque assignation découverte.
    """
    assignments = scan_result.all_assignments

    # 1. Réutiliser les noms déjà résolus dans les assignments (évite un appel Graph redondant)
    names: dict[str, tuple[str, str]] = {}
    for a in assignments:
        if a.principal_display_name and a.principal_id and a.principal_id not in names:
            names[a.principal_id] = (a.principal_display_name, str(a.principal_type))

    # 2. Résoudre uniquement les principals non encore résolus
    unresolved_ids = list({a.principal_id for a in assignments if a.principal_id and a.principal_id not in names})
    if unresolved_ids:
        fresh = resolve_principal_names(unresolved_ids, credential=credential)
        names.update(fresh)

    # 3. Construire les baseline rules (dédupliquées par clé)
    seen_keys: set[tuple[str, str, str]] = set()
    baseline_rules: list[Rule] = []
    name_counter: dict[str, int] = {}

    for a in assignments:
        if a.role_name is None:
            continue

        key = (a.principal_id.lower(), a.role_name.lower(), a.scope.lower().rstrip("/"))
        if key in seen_keys:
            continue
        seen_keys.add(key)

        # Résolution du nom
        resolved = names.get(a.principal_id)
        display_name = resolved[0] if resolved else (a.principal_display_name or a.principal_id)

        # Generate unique rule name
        rule_name = _slugify_rule_name(display_name, a.role_name, a.scope)
        name_counter[rule_name] = name_counter.get(rule_name, 0) + 1
        if name_counter[rule_name] > 1:
            rule_name = f"{rule_name}-{name_counter[rule_name]}"

        baseline_rules.append(
            Rule(
                name=rule_name,
                type="baseline",
                description=f"{display_name} — {a.role_name}",
                match=RuleMatch(
                    principal_id=a.principal_id,
                    role=a.role_name,
                    scope=a.scope,
                ),
            )
        )

    # 4. Trier pour la lisibilité
    baseline_rules.sort(key=lambda r: (
        (r.match.scope or "").lower(),
        (r.match.role or "").lower(),
        r.name.lower(),
    ))

    return PolicyModel(
        version="2.0",
        tenant_id=UUID(tenant_id),
        subscriptions=subscriptions or [],
        management_groups=management_groups or [],
        rules=baseline_rules,
    )
