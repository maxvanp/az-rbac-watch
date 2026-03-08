"""Utilities for grouping by Azure scope (subscription, management group)."""

from __future__ import annotations

import re

__all__ = ["MG_RE", "SUB_RE", "scope_group_key"]

SUB_RE = re.compile(r"^/subscriptions/([^/]+)", re.IGNORECASE)
MG_RE = re.compile(r"^/providers/Microsoft\.Management/managementGroups/([^/]+)", re.IGNORECASE)


def scope_group_key(scope: str) -> tuple[int, str]:
    """Extract a grouping key from an Azure scope.

    Returns:
        (sort_order, group_id_lower) — 0=MG, 1=subscription, 2=other.
    """
    mg = MG_RE.match(scope)
    if mg:
        return (0, mg.group(1).lower())
    sub = SUB_RE.match(scope)
    if sub:
        return (1, sub.group(1).lower())
    return (2, "")
