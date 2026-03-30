"""Shared Azure RBAC scanning helpers for MCP tools.

Centralizes the async scan wrapper and role definition collection
that were previously duplicated across every MCP tool module.
"""

from __future__ import annotations

import asyncio

from az_rbac_watch.auth.azure_clients import (
    get_authorization_client,
    list_accessible_subscriptions,
)
from az_rbac_watch.scanner.rbac_scanner import (
    RbacScanResult,
    ScannedRoleDefinition,
    resolve_display_names,
    scan_subscription,
)

__all__ = ["collect_all_definitions", "scan_subscription_async"]


async def scan_subscription_async(
    subscription_id: str | None,
) -> RbacScanResult:
    """Scan Azure RBAC for one or all subscriptions.

    Wraps the synchronous scanner in asyncio.to_thread.
    """

    def _sync_scan() -> RbacScanResult:
        if subscription_id:
            client = get_authorization_client(subscription_id)
            sub_result = scan_subscription(client, subscription_id)
            result = RbacScanResult(subscription_results=[sub_result])
        else:
            subs = list_accessible_subscriptions()
            sub_results = []
            for sid, name, _tenant in subs:
                client = get_authorization_client(sid)
                sub_results.append(scan_subscription(client, sid, name))
            result = RbacScanResult(subscription_results=sub_results)
        return resolve_display_names(result)

    return await asyncio.to_thread(_sync_scan)


def collect_all_definitions(
    scan_result: RbacScanResult,
) -> list[ScannedRoleDefinition]:
    """Collect all unique role definitions from all subscription/MG results."""
    definitions: list[ScannedRoleDefinition] = []
    seen: set[str] = set()
    for sub in scan_result.subscription_results:
        for d in sub.definitions:
            if d.id not in seen:
                seen.add(d.id)
                definitions.append(d)
    for mg in scan_result.management_group_results:
        for d in mg.definitions:
            if d.id not in seen:
                seen.add(d.id)
                definitions.append(d)
    return definitions
