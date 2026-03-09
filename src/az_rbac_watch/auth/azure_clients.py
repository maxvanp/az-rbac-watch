"""Factory for Azure (ARM) clients and Graph API utilities.

Provides utility functions to obtain credentials and Azure SDK
clients needed for RBAC scanning, as well as principal name
resolution via Microsoft Graph.
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
_BATCH_SIZE = 1000  # Max limit of getByIds API


_credential: DefaultAzureCredential | None = None


def get_credential() -> DefaultAzureCredential:
    """Return an Azure credential (lazy singleton, without lru_cache).

    Uses a module-level singleton instead of lru_cache to avoid
    a broken credential remaining cached without retry capability.
    """
    global _credential
    if _credential is None:
        _credential = DefaultAzureCredential()
    return _credential


def check_credentials() -> bool:
    """Check if Azure credentials are available."""
    try:
        cred = get_credential()
        cred.get_token("https://management.azure.com/.default")
        return True
    except Exception:
        return False


def get_authorization_client(subscription_id: str) -> AuthorizationManagementClient:
    """Create an AuthorizationManagementClient for the given subscription."""
    return AuthorizationManagementClient(
        credential=get_credential(),
        subscription_id=subscription_id,
    )


def resolve_principal_names(
    principal_ids: list[str],
    credential: TokenCredential | None = None,
) -> dict[str, tuple[str, str]]:
    """Resolve principal display names via Microsoft Graph.

    Calls POST /directoryObjects/getByIds in batches of max 1000.

    Args:
        principal_ids: List of principal IDs to resolve.
        credential: Azure credential (default: DefaultAzureCredential).

    Returns:
        Mapping {principal_id: (display_name, odata_type)}.
        On error, returns an empty dict (graceful degradation).
    """
    if not principal_ids:
        return {}

    cred = credential or get_credential()
    try:
        token = cred.get_token(_GRAPH_SCOPE)
    except ClientAuthenticationError:
        logger.warning("Graph API token unavailable — name resolution skipped")
        return {}
    except Exception:
        logger.warning("Graph API token unavailable — name resolution skipped")
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
                    "Graph API access denied (batch %d-%d) — check Directory.Read.All permission",
                    i,
                    i + len(batch),
                )
            else:
                logger.warning("Graph API HTTP error %d (batch %d-%d)", exc.response.status_code, i, i + len(batch))
        except Exception:
            logger.warning("Error resolving Graph names (batch %d-%d)", i, i + len(batch))

    return result


def list_accessible_subscriptions(
    credential: TokenCredential | None = None,
) -> list[tuple[str, str, str]]:
    """List accessible subscriptions (Enabled only).

    Returns:
        List of tuples (subscription_id, display_name, tenant_id).

    Raises:
        ClientAuthenticationError: If Azure authentication fails.
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
    """List accessible management groups.

    Returns:
        List of tuples (mg_id, display_name).

    Raises:
        ClientAuthenticationError: If Azure authentication fails.
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
