"""Snapshot model — captures tenant RBAC state at a point in time.

A snapshot contains all role assignments and definitions for a set of scopes,
with metadata for provenance. Snapshots are serialized as JSON files and
can be compared with the diff module.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel

from az_rbac_watch.scanner.rbac_scanner import RbacScanResult

__all__ = [
    "Snapshot",
    "SnapshotAssignment",
    "SnapshotMetadata",
    "SnapshotRoleDefinition",
    "SnapshotScope",
    "build_snapshot",
    "load_snapshot",
    "save_snapshot",
]


class SnapshotMetadata(BaseModel):
    """Provenance metadata for a snapshot."""

    timestamp: datetime
    tenant_id: str
    tool_version: str


class SnapshotScope(BaseModel):
    """Scopes included in the snapshot."""

    subscriptions: list[dict[str, str]] = []
    management_groups: list[dict[str, str]] = []


class SnapshotAssignment(BaseModel):
    """A role assignment captured in the snapshot."""

    id: str
    scope: str
    role_name: str | None = None
    role_type: str | None = None
    principal_id: str
    principal_type: str
    principal_display_name: str | None = None


class SnapshotRoleDefinition(BaseModel):
    """A role definition captured in the snapshot."""

    id: str
    role_name: str
    role_type: str


class Snapshot(BaseModel):
    """Complete tenant RBAC state at a point in time."""

    version: str = "1.0"
    metadata: SnapshotMetadata
    scopes: SnapshotScope = SnapshotScope()
    assignments: list[SnapshotAssignment] = []
    role_definitions: list[SnapshotRoleDefinition] = []


def build_snapshot(
    *,
    scan_result: RbacScanResult,
    tenant_id: str,
    subscriptions: list[dict[str, str]],
    management_groups: list[dict[str, str]],
) -> Snapshot:
    """Build a Snapshot from an RbacScanResult."""
    from az_rbac_watch import __version__

    assignments = [
        SnapshotAssignment(
            id=a.id,
            scope=a.scope,
            role_name=a.role_name,
            role_type=str(a.role_type) if a.role_type else None,
            principal_id=a.principal_id,
            principal_type=str(a.principal_type),
            principal_display_name=a.principal_display_name,
        )
        for a in scan_result.all_assignments
    ]

    # Deduplicate role definitions across all scopes
    seen_defs: set[str] = set()
    role_definitions: list[SnapshotRoleDefinition] = []
    for sub in scan_result.subscription_results:
        for d in sub.definitions:
            if d.id not in seen_defs:
                seen_defs.add(d.id)
                role_definitions.append(
                    SnapshotRoleDefinition(
                        id=d.id,
                        role_name=d.role_name,
                        role_type=str(d.role_type),
                    )
                )
    for mg in scan_result.management_group_results:
        for d in mg.definitions:
            if d.id not in seen_defs:
                seen_defs.add(d.id)
                role_definitions.append(
                    SnapshotRoleDefinition(
                        id=d.id,
                        role_name=d.role_name,
                        role_type=str(d.role_type),
                    )
                )

    return Snapshot(
        metadata=SnapshotMetadata(
            timestamp=datetime.now(tz=UTC),
            tenant_id=tenant_id,
            tool_version=__version__,
        ),
        scopes=SnapshotScope(
            subscriptions=subscriptions,
            management_groups=management_groups,
        ),
        assignments=assignments,
        role_definitions=role_definitions,
    )


def save_snapshot(snapshot: Snapshot, path: str | Path) -> None:
    """Serialize a Snapshot to a JSON file."""
    path = Path(path)
    data = snapshot.model_dump(mode="json")
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def load_snapshot(path: str | Path) -> Snapshot:
    """Load a Snapshot from a JSON file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Snapshot file not found: {path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    return Snapshot.model_validate(raw)
