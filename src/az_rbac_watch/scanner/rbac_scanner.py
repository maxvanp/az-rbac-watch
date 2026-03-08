"""Scanner RBAC Azure ARM.

Récupère les role assignments et role definitions depuis l'API Azure ARM
pour une ou plusieurs subscriptions, puis enrichit les assignments
avec le nom et le type du rôle (jointure par GUID).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
from pydantic import BaseModel

from az_rbac_watch.auth.azure_clients import get_authorization_client, resolve_principal_names

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential
    from azure.mgmt.authorization import AuthorizationManagementClient

    from az_rbac_watch.config.policy_model import PolicyModel

__all__ = [
    "ClientFactory",
    "ManagementGroupScanResult",
    "PrincipalType",
    "ProgressCallback",
    "RbacScanResult",
    "RbacScanner",
    "RoleType",
    "ScannedRoleAssignment",
    "ScannedRoleDefinition",
    "SubscriptionScanResult",
    "extract_role_def_guid",
    "resolve_display_names",
    "resolve_role_names",
    "scan_management_group",
    "scan_rbac",
    "scan_role_assignments",
    "scan_role_assignments_for_scope",
    "scan_role_definitions",
    "scan_role_definitions_for_scope",
    "scan_subscription",
]

logger = logging.getLogger(__name__)

# Regex pour extraire le GUID d'un role definition ID ARM
# Ex: "/subscriptions/.../providers/Microsoft.Authorization/roleDefinitions/acdd72a7-..."
_ROLE_DEF_GUID_RE = re.compile(r"/roleDefinitions/([0-9a-fA-F-]+)$")


# ── Enums ─────────────────────────────────────────────────────


class PrincipalType(StrEnum):
    USER = "User"
    GROUP = "Group"
    SERVICE_PRINCIPAL = "ServicePrincipal"
    FOREIGN_GROUP = "ForeignGroup"
    DEVICE = "Device"
    UNKNOWN = "Unknown"

    @classmethod
    def from_azure(cls, value: str | None) -> PrincipalType:
        """Convertit la valeur retournée par le SDK Azure en PrincipalType."""
        if value is None:
            return cls.UNKNOWN
        try:
            return cls(value)
        except ValueError:
            logger.warning("PrincipalType inconnu reçu du SDK : %r", value)
            return cls.UNKNOWN


class RoleType(StrEnum):
    BUILT_IN = "BuiltInRole"
    CUSTOM = "CustomRole"


# ── Modèles Pydantic ──────────────────────────────────────────


class ScannedRoleAssignment(BaseModel):
    """Une assignation de rôle telle que retournée par l'API ARM, enrichie."""

    id: str
    scope: str
    role_definition_id: str
    principal_id: str
    principal_type: PrincipalType
    # Champs résolus après jointure avec les definitions
    role_name: str | None = None
    role_type: RoleType | None = None
    # Champ résolu via Graph API (resolve_display_names)
    principal_display_name: str | None = None


class ScannedRoleDefinition(BaseModel):
    """Une définition de rôle Azure."""

    id: str
    role_name: str
    role_type: RoleType
    assignable_scopes: list[str] = []


class SubscriptionScanResult(BaseModel):
    """Résultat du scan d'une subscription."""

    subscription_id: str
    subscription_name: str
    assignments: list[ScannedRoleAssignment] = []
    definitions: list[ScannedRoleDefinition] = []
    errors: list[str] = []


class ManagementGroupScanResult(BaseModel):
    """Résultat du scan d'un management group."""

    management_group_id: str
    management_group_name: str
    assignments: list[ScannedRoleAssignment] = []
    definitions: list[ScannedRoleDefinition] = []
    errors: list[str] = []


class RbacScanResult(BaseModel):
    """Résultat agrégé du scan RBAC de tous les management groups et subscriptions."""

    management_group_results: list[ManagementGroupScanResult] = []
    subscription_results: list[SubscriptionScanResult] = []
    warnings: list[str] = []

    @property
    def all_assignments(self) -> list[ScannedRoleAssignment]:
        """Retourne toutes les assignations dédupliquées (MG prioritaire sur sub)."""
        seen: set[str] = set()
        result: list[ScannedRoleAssignment] = []
        for mg in self.management_group_results:
            for a in mg.assignments:
                if a.id not in seen:
                    seen.add(a.id)
                    result.append(a)
        for sub in self.subscription_results:
            for a in sub.assignments:
                if a.id not in seen:
                    seen.add(a.id)
                    result.append(a)
        return result

    @property
    def all_errors(self) -> list[str]:
        """Retourne toutes les erreurs de tous les scans."""
        errors: list[str] = []
        for mg in self.management_group_results:
            errors.extend(mg.errors)
        for sub in self.subscription_results:
            errors.extend(sub.errors)
        return errors


# ── Fonctions utilitaires ─────────────────────────────────────


def extract_role_def_guid(role_definition_id: str) -> str | None:
    """Extrait le GUID d'un role definition ID ARM complet.

    Retourne None si le format n'est pas reconnu.
    """
    match = _ROLE_DEF_GUID_RE.search(role_definition_id)
    return match.group(1) if match else None


# ── Fonctions de scan ─────────────────────────────────────────


def scan_role_assignments(client: AuthorizationManagementClient) -> list[ScannedRoleAssignment]:
    """Liste toutes les role assignments de la subscription via le SDK."""
    assignments: list[ScannedRoleAssignment] = []
    for ra in client.role_assignments.list_for_subscription():
        assignments.append(
            ScannedRoleAssignment(
                id=ra.id or "",
                scope=ra.scope or "",
                role_definition_id=ra.role_definition_id or "",
                principal_id=ra.principal_id or "",
                principal_type=PrincipalType.from_azure(ra.principal_type),
            )
        )
    return assignments


def scan_role_definitions(
    client: AuthorizationManagementClient,
    subscription_id: str,
) -> list[ScannedRoleDefinition]:
    """Liste toutes les role definitions visibles pour la subscription."""
    scope = f"/subscriptions/{subscription_id}"
    definitions: list[ScannedRoleDefinition] = []
    for rd in client.role_definitions.list(scope=scope):
        role_type = RoleType.CUSTOM if rd.role_type == "CustomRole" else RoleType.BUILT_IN
        definitions.append(
            ScannedRoleDefinition(
                id=rd.id or "",
                role_name=rd.role_name or "",
                role_type=role_type,
                assignable_scopes=list(rd.assignable_scopes or []),
            )
        )
    return definitions


def resolve_role_names(
    assignments: list[ScannedRoleAssignment],
    definitions: list[ScannedRoleDefinition],
) -> list[ScannedRoleAssignment]:
    """Enrichit les assignments avec le nom et le type du rôle.

    La jointure se fait par GUID extrait du role_definition_id ARM.
    """
    # Index : GUID (lowercase) → definition
    guid_to_def: dict[str, ScannedRoleDefinition] = {}
    for d in definitions:
        guid = extract_role_def_guid(d.id)
        if guid:
            guid_to_def[guid.lower()] = d

    resolved: list[ScannedRoleAssignment] = []
    for a in assignments:
        guid = extract_role_def_guid(a.role_definition_id)
        if guid and guid.lower() in guid_to_def:
            defn = guid_to_def[guid.lower()]
            a = a.model_copy(update={"role_name": defn.role_name, "role_type": defn.role_type})
        resolved.append(a)
    return resolved


# ── Résolution des noms via Graph API ────────────────────────


def resolve_display_names(
    scan_result: RbacScanResult,
    credential: TokenCredential | None = None,
) -> RbacScanResult:
    """Enrichit les assignments avec les display names résolus via Graph API.

    Collecte les principal_ids uniques, appelle resolve_principal_names(),
    et retourne un nouveau RbacScanResult avec les display names peuplés.
    Si la résolution échoue ou retourne un dict vide, retourne le scan_result tel quel.
    """
    all_assignments = scan_result.all_assignments
    if not all_assignments:
        return scan_result

    unique_ids = list({a.principal_id for a in all_assignments if a.principal_id})
    if not unique_ids:
        return scan_result

    resolved = resolve_principal_names(unique_ids, credential=credential)
    if not resolved:
        return scan_result.model_copy(
            update={
                "warnings": [
                    *scan_result.warnings,
                    "Résolution des noms Graph API indisponible — les findings afficheront des IDs au lieu de noms",
                ],
            }
        )

    id_to_name: dict[str, str] = {pid: info[0] for pid, info in resolved.items()}

    def _enrich_assignments(
        assignments: list[ScannedRoleAssignment],
    ) -> list[ScannedRoleAssignment]:
        return [
            a.model_copy(update={"principal_display_name": id_to_name[a.principal_id]})
            if a.principal_id in id_to_name
            else a
            for a in assignments
        ]

    new_mg_results = [
        mg.model_copy(update={"assignments": _enrich_assignments(mg.assignments)})
        for mg in scan_result.management_group_results
    ]
    new_sub_results = [
        sub.model_copy(update={"assignments": _enrich_assignments(sub.assignments)})
        for sub in scan_result.subscription_results
    ]

    return scan_result.model_copy(
        update={
            "management_group_results": new_mg_results,
            "subscription_results": new_sub_results,
        }
    )


# ── Fonctions de scan par scope (management groups) ──────────


def scan_role_assignments_for_scope(
    client: AuthorizationManagementClient,
    scope: str,
) -> list[ScannedRoleAssignment]:
    """Liste toutes les role assignments pour un scope donné via list_for_scope()."""
    assignments: list[ScannedRoleAssignment] = []
    for ra in client.role_assignments.list_for_scope(scope=scope):
        assignments.append(
            ScannedRoleAssignment(
                id=ra.id or "",
                scope=ra.scope or "",
                role_definition_id=ra.role_definition_id or "",
                principal_id=ra.principal_id or "",
                principal_type=PrincipalType.from_azure(ra.principal_type),
            )
        )
    return assignments


def scan_role_definitions_for_scope(
    client: AuthorizationManagementClient,
    scope: str,
) -> list[ScannedRoleDefinition]:
    """Liste toutes les role definitions visibles pour un scope donné."""
    definitions: list[ScannedRoleDefinition] = []
    for rd in client.role_definitions.list(scope=scope):
        role_type = RoleType.CUSTOM if rd.role_type == "CustomRole" else RoleType.BUILT_IN
        definitions.append(
            ScannedRoleDefinition(
                id=rd.id or "",
                role_name=rd.role_name or "",
                role_type=role_type,
                assignable_scopes=list(rd.assignable_scopes or []),
            )
        )
    return definitions


# ── Orchestration ─────────────────────────────────────────────


def scan_subscription(
    client: AuthorizationManagementClient,
    subscription_id: str,
    subscription_name: str = "",
) -> SubscriptionScanResult:
    """Scanne une subscription : assignments + definitions + résolution."""
    result = SubscriptionScanResult(
        subscription_id=subscription_id,
        subscription_name=subscription_name,
    )
    try:
        assignments = scan_role_assignments(client)
        definitions = scan_role_definitions(client, subscription_id)
        resolved = resolve_role_names(assignments, definitions)
        result.assignments = resolved
        result.definitions = definitions
    except ClientAuthenticationError:
        raise  # Auth = prérequis, pas géré par l'outil
    except HttpResponseError as exc:
        if exc.status_code == 403:
            error_msg = f"Accès refusé sur {subscription_id} — le principal n'a pas les droits de lecture RBAC"
        elif exc.status_code == 429:
            error_msg = f"Throttling Azure sur {subscription_id} — trop de requêtes, réessayez plus tard"
        else:
            error_msg = f"Erreur API Azure ({exc.status_code}) sur {subscription_id} : {exc.message}"
        logger.error(error_msg)
        result.errors.append(error_msg)
    except Exception as exc:
        error_msg = f"Erreur inattendue lors du scan de {subscription_id} : {exc}"
        logger.error(error_msg)
        result.errors.append(error_msg)
    return result


def scan_management_group(
    client: AuthorizationManagementClient,
    management_group_id: str,
    management_group_name: str = "",
) -> ManagementGroupScanResult:
    """Scanne un management group : assignments + definitions + résolution."""
    result = ManagementGroupScanResult(
        management_group_id=management_group_id,
        management_group_name=management_group_name,
    )
    scope = f"/providers/Microsoft.Management/managementGroups/{management_group_id}"
    try:
        assignments = scan_role_assignments_for_scope(client, scope)
        definitions = scan_role_definitions_for_scope(client, scope)
        resolved = resolve_role_names(assignments, definitions)
        result.assignments = resolved
        result.definitions = definitions
    except ClientAuthenticationError:
        raise  # Auth = prérequis, pas géré par l'outil
    except HttpResponseError as exc:
        mg = management_group_id
        if exc.status_code == 403:
            error_msg = f"Accès refusé sur le management group {mg} — droits de lecture RBAC manquants"
        elif exc.status_code == 429:
            error_msg = f"Throttling Azure sur le management group {mg} — trop de requêtes, réessayez"
        else:
            error_msg = f"Erreur API Azure ({exc.status_code}) sur le management group {mg} : {exc.message}"
        logger.error(error_msg)
        result.errors.append(error_msg)
    except Exception as exc:
        error_msg = f"Erreur inattendue lors du scan du management group {management_group_id} : {exc}"
        logger.error(error_msg)
        result.errors.append(error_msg)
    return result


ProgressCallback = Callable[[str, str], None]
"""Callback signature: (scope_type, scope_name) — called after each scope is scanned."""


@runtime_checkable
class ClientFactory(Protocol):
    """Protocol for creating AuthorizationManagementClient instances."""

    def __call__(self, subscription_id: str) -> AuthorizationManagementClient: ...


class RbacScanner:
    """Scans Azure RBAC role assignments across management groups and subscriptions.

    Encapsulates the parallel scanning logic with configurable client factory,
    progress callback, and worker pool size.
    """

    def __init__(
        self,
        client_factory: ClientFactory | None = None,
        progress_callback: ProgressCallback | None = None,
        max_workers: int = 4,
    ) -> None:
        self._factory: ClientFactory = client_factory or get_authorization_client
        self._progress_callback = progress_callback
        self._max_workers = max_workers

    def scan(self, policy: PolicyModel) -> RbacScanResult:
        """Scanne tous les MG et subscriptions du policy model.

        Les scopes sont scannés en parallèle via ThreadPoolExecutor.
        """
        result = RbacScanResult()

        if not policy.subscriptions and not policy.management_groups:
            logger.warning("Aucune subscription ni management group définis dans le policy model")
            return result

        # Le subscription_id pour créer le client MG n'est pas utilisé par list_for_scope()
        dummy_sub_id = (
            str(policy.subscriptions[0].id)
            if policy.subscriptions
            else "00000000-0000-0000-0000-000000000000"
        )

        # Collecter les tâches dans l'ordre (MG d'abord, puis subs)
        tasks: list[tuple[str, str, str]] = []  # (type, id, name)
        for mg in policy.management_groups:
            tasks.append(("mg", mg.id, mg.name or mg.id))
        for sub in policy.subscriptions:
            tasks.append(("sub", str(sub.id), sub.name or str(sub.id)))

        # Exécuter en parallèle
        mg_results: list[ManagementGroupScanResult] = []
        sub_results: list[SubscriptionScanResult] = []

        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            future_to_idx = {}
            for idx, (scope_type, scope_id, scope_name) in enumerate(tasks):
                client_sub_id = dummy_sub_id if scope_type == "mg" else scope_id
                future = executor.submit(self._scan_scope, scope_type, scope_id, scope_name, client_sub_id)
                future_to_idx[future] = idx

            # Collecter dans l'ordre d'achèvement pour le progress callback
            ordered: dict[int, tuple[str, ManagementGroupScanResult | SubscriptionScanResult]] = {}
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                scope_type_result, scope_result = future.result()
                ordered[idx] = (scope_type_result, scope_result)
                if self._progress_callback:
                    scope_type, _, scope_name = tasks[idx]
                    self._progress_callback(
                        scope_type if scope_type == "mg" else "subscription",
                        scope_name,
                    )

        # Remettre dans l'ordre de soumission pour un résultat déterministe
        for idx in sorted(ordered):
            scope_type, scope_result = ordered[idx]
            if scope_type == "mg":
                mg_results.append(scope_result)  # type: ignore[arg-type]
            else:
                sub_results.append(scope_result)  # type: ignore[arg-type]

        result.management_group_results = mg_results
        result.subscription_results = sub_results
        return result

    def _scan_scope(
        self,
        scope_type: str,
        scope_id: str,
        scope_name: str,
        client_sub_id: str,
    ) -> tuple[str, ManagementGroupScanResult | SubscriptionScanResult]:
        """Scan a single scope (management group or subscription)."""
        logger.info("Scan RBAC %s %s (%s)", scope_type, scope_name, scope_id)
        try:
            client = self._factory(client_sub_id)
        except ClientAuthenticationError:
            raise  # Auth = prérequis, pas géré par l'outil
        except Exception as exc:
            error_msg = f"Impossible de créer le client pour {scope_type} {scope_id} : {exc}"
            logger.error(error_msg)
            if scope_type == "mg":
                return ("mg", ManagementGroupScanResult(
                    management_group_id=scope_id,
                    management_group_name=scope_name,
                    errors=[error_msg],
                ))
            return ("sub", SubscriptionScanResult(
                subscription_id=scope_id,
                subscription_name=scope_name,
                errors=[error_msg],
            ))

        if scope_type == "mg":
            return ("mg", scan_management_group(client, scope_id, scope_name))
        return ("sub", scan_subscription(client, scope_id, scope_name))


def scan_rbac(
    policy: PolicyModel,
    client_factory: ClientFactory | None = None,
    progress_callback: ProgressCallback | None = None,
    max_workers: int = 4,
) -> RbacScanResult:
    """Point d'entrée principal : scanne tous les MG et subscriptions du policy model.

    Thin wrapper autour de RbacScanner pour compatibilité ascendante.

    Args:
        policy: Le policy model contenant les scopes à scanner.
        client_factory: Fonction (subscription_id) -> AuthorizationManagementClient.
                        Par défaut utilise get_authorization_client.
        progress_callback: Optionnel, appelé après chaque scope scanné.
        max_workers: Nombre maximum de threads parallèles (défaut 4).
    """
    return RbacScanner(client_factory, progress_callback, max_workers).scan(policy)
