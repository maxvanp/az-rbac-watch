"""Diff engine — compare two snapshots to detect RBAC changes.

Compares assignment lists by ID. Detects added, removed, and modified
assignments. Modified means the same assignment ID exists in both
but with different field values.
"""

from __future__ import annotations

from pydantic import BaseModel

from az_rbac_watch.scanner.snapshot import SnapshotAssignment

__all__ = [
    "DiffChange",
    "DiffResult",
    "compute_diff",
]

# Fields to compare for modification detection
_COMPARED_FIELDS = ("scope", "role_name", "role_type", "principal_id", "principal_type", "principal_display_name")


class DiffChange(BaseModel):
    """A single field change on an assignment."""

    assignment_id: str
    field: str
    old_value: str | None
    new_value: str | None


class DiffResult(BaseModel):
    """Result of comparing two sets of assignments."""

    added: list[SnapshotAssignment] = []
    removed: list[SnapshotAssignment] = []
    modified: list[DiffChange] = []

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.modified)

    @property
    def added_count(self) -> int:
        return len(self.added)

    @property
    def removed_count(self) -> int:
        return len(self.removed)

    @property
    def modified_count(self) -> int:
        """Count of unique assignments that were modified."""
        return len({c.assignment_id for c in self.modified})


def compute_diff(
    old: list[SnapshotAssignment],
    new: list[SnapshotAssignment],
) -> DiffResult:
    """Compare two lists of assignments and return the differences."""
    old_by_id = {a.id: a for a in old}
    new_by_id = {a.id: a for a in new}

    old_ids = set(old_by_id.keys())
    new_ids = set(new_by_id.keys())

    added = [new_by_id[aid] for aid in sorted(new_ids - old_ids)]
    removed = [old_by_id[aid] for aid in sorted(old_ids - new_ids)]

    modified: list[DiffChange] = []
    for aid in sorted(old_ids & new_ids):
        old_a = old_by_id[aid]
        new_a = new_by_id[aid]
        for field in _COMPARED_FIELDS:
            old_val = getattr(old_a, field)
            new_val = getattr(new_a, field)
            if old_val != new_val:
                modified.append(
                    DiffChange(
                        assignment_id=aid,
                        field=field,
                        old_value=str(old_val) if old_val is not None else None,
                        new_value=str(new_val) if new_val is not None else None,
                    )
                )

    return DiffResult(added=added, removed=removed, modified=modified)
