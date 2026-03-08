"""Factory pour les clients Azure (ARM) et utilitaires Graph API.

Fournit des fonctions utilitaires pour obtenir les credentials
et les clients Azure SDK nécessaires au scan RBAC, ainsi que
la résolution des noms de principals via Microsoft Graph.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx
from azure.core.exceptions import ClientAuthenticationError
from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.managementgroups import ManagementGroupsAPI
from azure.mgmt.subscription import SubscriptionClient

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential

__all__ = [
    "check_credentials",
    "get_authorization_client",
    "get_credential",
    "list_accessible_management_groups",
    "list_accessible_subscriptions",
    "resolve_principal_names",
]

logger = logging.getLogger(__name__)

_GRAPH_SCOPE = "https://graph.microsoft.com/.default"
_GRAPH_GET_BY_IDS_URL = "https://graph.microsoft.com/v1.0/directoryObjects/getByIds"
_BATCH_SIZE = 1000  # Limite max de l'API getByIds


_credential: DefaultAzureCredential | None = None


def get_credential() -> DefaultAzureCredential:
    """Retourne un credential Azure (lazy singleton, sans lru_cache).

    Utilise un singleton module-level plutôt que lru_cache pour éviter
    qu'un credential cassé reste en cache sans possibilité de retry.
    """
    global _credential
    if _credential is None:
        _credential = DefaultAzureCredential()
    return _credential


def check_credentials() -> bool:
    """Vérifie si les credentials Azure sont disponibles."""
    try:
        cred = get_credential()
        cred.get_token("https://management.azure.com/.default")
        return True
    except Exception:
        return False


def get_authorization_client(subscription_id: str) -> AuthorizationManagementClient:
    """Crée un AuthorizationManagementClient pour la subscription donnée."""
    return AuthorizationManagementClient(
        credential=get_credential(),
        subscription_id=subscription_id,
    )


def resolve_principal_names(
    principal_ids: list[str],
    credential: TokenCredential | None = None,
) -> dict[str, tuple[str, str]]:
    """Résout les noms d'affichage des principals via Microsoft Graph.

    Appelle POST /directoryObjects/getByIds par batches de 1000 max.

    Args:
        principal_ids: Liste de principal IDs à résoudre.
        credential: Credential Azure (par défaut : DefaultAzureCredential).

    Returns:
        Mapping {principal_id: (display_name, odata_type)}.
        En cas d'erreur, retourne un dict vide (dégradation gracieuse).
    """
    if not principal_ids:
        return {}

    cred = credential or get_credential()
    try:
        token = cred.get_token(_GRAPH_SCOPE)
    except ClientAuthenticationError:
        logger.warning("Token Graph API indisponible — résolution des noms ignorée")
        return {}
    except Exception:
        logger.warning("Token Graph API indisponible — résolution des noms ignorée")
        return {}

    headers = {"Authorization": f"Bearer {token.token}", "Content-Type": "application/json"}
    result: dict[str, tuple[str, str]] = {}

    for i in range(0, len(principal_ids), _BATCH_SIZE):
        batch = principal_ids[i : i + _BATCH_SIZE]
        try:
            resp = httpx.post(
                _GRAPH_GET_BY_IDS_URL,
                headers=headers,
                json={"ids": batch},
                timeout=30.0,
            )
            resp.raise_for_status()
            data = resp.json()
            for obj in data.get("value", []):
                obj_id = obj.get("id", "")
                display_name = obj.get("displayName", obj_id)
                odata_type = obj.get("@odata.type", "")
                result[obj_id] = (display_name, odata_type)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 403:
                logger.warning(
                    "Accès refusé Graph API (batch %d-%d) — vérifiez la permission Directory.Read.All",
                    i,
                    i + len(batch),
                )
            else:
                logger.warning(
                    "Erreur HTTP Graph API %d (batch %d-%d)", exc.response.status_code, i, i + len(batch)
                )
        except Exception:
            logger.warning("Erreur lors de la résolution des noms Graph (batch %d-%d)", i, i + len(batch))

    return result


def list_accessible_subscriptions(
    credential: TokenCredential | None = None,
) -> list[tuple[str, str, str]]:
    """Liste les subscriptions accessibles (Enabled uniquement).

    Returns:
        Liste de tuples (subscription_id, display_name, tenant_id).

    Raises:
        ClientAuthenticationError: Si l'authentification Azure échoue.
    """
    cred = credential or get_credential()
    client = SubscriptionClient(cred)
    result: list[tuple[str, str, str]] = []
    for sub in client.subscriptions.list():
        raw_state = sub.state
        state: str | None = raw_state.value if raw_state is not None and hasattr(raw_state, "value") else raw_state
        if state and state != "Enabled":
            continue
        result.append(
            (
                sub.subscription_id or "",
                sub.display_name or "",
                getattr(sub, "tenant_id", None) or "",
            )
        )
    return result


def list_accessible_management_groups(
    credential: TokenCredential | None = None,
) -> list[tuple[str, str]]:
    """Liste les management groups accessibles.

    Returns:
        Liste de tuples (mg_id, display_name).

    Raises:
        ClientAuthenticationError: Si l'authentification Azure échoue.
    """
    cred = credential or get_credential()
    client = ManagementGroupsAPI(cred)
    result: list[tuple[str, str]] = []
    for mg in client.management_groups.list():
        result.append(
            (
                mg.name or "",
                mg.display_name or "",
            )
        )
    return result
