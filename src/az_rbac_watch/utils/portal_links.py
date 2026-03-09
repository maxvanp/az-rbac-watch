"""Azure Portal URL builders for scopes and principals."""

from __future__ import annotations

import re

__all__ = ["build_principal_url", "build_scope_url"]

_PORTAL = "https://portal.azure.com"

_SUB_RE = re.compile(r"^/subscriptions/([^/]+)(/.*)?$", re.IGNORECASE)
_MG_RE = re.compile(
    r"^/providers/Microsoft\.Management/managementGroups/([^/]+)$",
    re.IGNORECASE,
)


def build_scope_url(scope: str, tenant_id: str) -> str | None:
    """Build an Azure Portal URL for an ARM scope.

    Supports subscriptions, resource groups, deep resource paths,
    and management groups. Returns None for unrecognized formats.
    """
    if not scope:
        return None

    mg = _MG_RE.match(scope)
    if mg:
        mg_id = mg.group(1)
        return (
            f"{_PORTAL}/#view/Microsoft_Azure_ManagementGroups"
            f"/ManagmentGroupDrilldownMenuBlade/~/overview"
            f"/tenantId/{tenant_id}/mgId/{mg_id}"
        )

    sub = _SUB_RE.match(scope)
    if sub:
        clean = scope.rstrip("/")
        return f"{_PORTAL}/#@{tenant_id}/resource{clean}/overview"

    return None


def build_principal_url(principal_id: str) -> str | None:
    """Build an Azure Portal URL for an Entra ID principal.

    Returns None if principal_id is empty.
    """
    if not principal_id:
        return None
    return f"{_PORTAL}/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/{principal_id}"
