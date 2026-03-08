# v0.4.0 Change Tracking — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `snapshot` and `diff` commands to capture tenant RBAC state and compare snapshots over time.

**Architecture:** A new `snapshot` module handles serialization/deserialization of tenant state. A new `diff` module computes added/removed/modified assignments between two snapshots. Two new CLI commands (`snapshot`, `diff`) expose the functionality. Console and JSON output for diff results.

**Tech Stack:** Python 3.12, Pydantic v2, Typer, Rich, pytest, ruff, mypy.

---

## Task 1: Create the `Snapshot` Pydantic model

**Files:**
- Create: `src/az_rbac_watch/scanner/snapshot.py`
- Create: `tests/test_snapshot.py`

**Step 1: Write the failing tests**

Create `tests/test_snapshot.py`:

```python
"""Unit tests for the snapshot model."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from az_rbac_watch.scanner.snapshot import (
    Snapshot,
    SnapshotAssignment,
    SnapshotMetadata,
    SnapshotRoleDefinition,
    SnapshotScope,
    save_snapshot,
    load_snapshot,
)


class TestSnapshotModel:
    def test_snapshot_metadata(self):
        meta = SnapshotMetadata(
            timestamp=datetime(2026, 3, 8, 12, 0, 0, tzinfo=UTC),
            tenant_id="11111111-1111-1111-1111-111111111111",
            tool_version="0.4.0",
        )
        assert meta.tenant_id == "11111111-1111-1111-1111-111111111111"
        assert meta.tool_version == "0.4.0"

    def test_snapshot_assignment(self):
        a = SnapshotAssignment(
            id="assignment-1",
            scope="/subscriptions/sub-1",
            role_name="Reader",
            role_type="BuiltInRole",
            principal_id="principal-1",
            principal_type="User",
            principal_display_name="Alice",
        )
        assert a.role_name == "Reader"

    def test_snapshot_roundtrip(self, tmp_path):
        """Save and load a snapshot — data must be identical."""
        snapshot = Snapshot(
            metadata=SnapshotMetadata(
                timestamp=datetime(2026, 3, 8, 12, 0, 0, tzinfo=UTC),
                tenant_id="11111111-1111-1111-1111-111111111111",
                tool_version="0.4.0",
            ),
            scopes=SnapshotScope(
                subscriptions=[{"id": "sub-1", "name": "Sub 1"}],
                management_groups=[{"id": "mg-1", "name": "MG 1"}],
            ),
            assignments=[
                SnapshotAssignment(
                    id="a-1",
                    scope="/subscriptions/sub-1",
                    role_name="Reader",
                    role_type="BuiltInRole",
                    principal_id="p-1",
                    principal_type="User",
                    principal_display_name="Alice",
                ),
            ],
            role_definitions=[
                SnapshotRoleDefinition(
                    id="rd-1",
                    role_name="Reader",
                    role_type="BuiltInRole",
                ),
            ],
        )
        path = tmp_path / "snapshot.json"
        save_snapshot(snapshot, path)
        loaded = load_snapshot(path)
        assert loaded.metadata.tenant_id == snapshot.metadata.tenant_id
        assert len(loaded.assignments) == 1
        assert loaded.assignments[0].role_name == "Reader"
        assert len(loaded.role_definitions) == 1

    def test_snapshot_file_not_found(self, tmp_path):
        import pytest
        with pytest.raises(FileNotFoundError):
            load_snapshot(tmp_path / "nonexistent.json")

    def test_snapshot_version(self):
        """Snapshot schema version should be '1.0'."""
        snapshot = Snapshot(
            metadata=SnapshotMetadata(
                timestamp=datetime(2026, 3, 8, tzinfo=UTC),
                tenant_id="11111111-1111-1111-1111-111111111111",
                tool_version="0.4.0",
            ),
        )
        assert snapshot.version == "1.0"
```

**Step 2:** Run tests to verify they fail:

```bash
.venv/bin/python -m pytest tests/test_snapshot.py -v
```

Expected: FAIL — module not found.

**Step 3: Implement the snapshot model**

Create `src/az_rbac_watch/scanner/snapshot.py`:

```python
"""Snapshot model — captures tenant RBAC state at a point in time.

A snapshot contains all role assignments and definitions for a set of scopes,
with metadata for provenance. Snapshots are serialized as JSON files and
can be compared with the diff module.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel

__all__ = [
    "Snapshot",
    "SnapshotAssignment",
    "SnapshotMetadata",
    "SnapshotRoleDefinition",
    "SnapshotScope",
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
```

**Step 4:** Run tests:

```bash
.venv/bin/python -m pytest tests/test_snapshot.py -v
```

Expected: all pass.

**Step 5:** Run lint:

```bash
.venv/bin/ruff check src/az_rbac_watch/scanner/snapshot.py tests/test_snapshot.py && .venv/bin/mypy src/az_rbac_watch/scanner/snapshot.py tests/test_snapshot.py
```

**Step 6:** Commit:

```bash
git add src/az_rbac_watch/scanner/snapshot.py tests/test_snapshot.py
git commit -m "feat: add Snapshot model with save/load serialization"
```

---

## Task 2: Create the `build_snapshot` function to convert scan results to snapshots

**Files:**
- Modify: `src/az_rbac_watch/scanner/snapshot.py`
- Modify: `tests/test_snapshot.py`

**Step 1: Write the failing tests**

Add to `tests/test_snapshot.py`:

```python
from az_rbac_watch.scanner.snapshot import build_snapshot
from az_rbac_watch.scanner.rbac_scanner import (
    PrincipalType,
    RbacScanResult,
    RoleType,
    ScannedRoleAssignment,
    ScannedRoleDefinition,
    SubscriptionScanResult,
    ManagementGroupScanResult,
)

VALID_TENANT_ID = "11111111-1111-1111-1111-111111111111"
VALID_SUB_ID = "22222222-2222-2222-2222-222222222222"


class TestBuildSnapshot:
    def test_build_from_scan_result(self):
        assignment = ScannedRoleAssignment(
            id="a-1",
            scope=f"/subscriptions/{VALID_SUB_ID}",
            role_definition_id="/providers/Microsoft.Authorization/roleDefinitions/fake",
            principal_id="p-1",
            principal_type=PrincipalType.USER,
            role_name="Reader",
            role_type=RoleType.BUILT_IN,
            principal_display_name="Alice",
        )
        definition = ScannedRoleDefinition(
            id="rd-1",
            role_name="Reader",
            role_type=RoleType.BUILT_IN,
        )
        scan_result = RbacScanResult(
            subscription_results=[
                SubscriptionScanResult(
                    subscription_id=VALID_SUB_ID,
                    subscription_name="Test-Sub",
                    assignments=[assignment],
                    definitions=[definition],
                )
            ]
        )
        snapshot = build_snapshot(
            scan_result=scan_result,
            tenant_id=VALID_TENANT_ID,
            subscriptions=[{"id": VALID_SUB_ID, "name": "Test-Sub"}],
            management_groups=[],
        )
        assert snapshot.metadata.tenant_id == VALID_TENANT_ID
        assert len(snapshot.assignments) == 1
        assert snapshot.assignments[0].id == "a-1"
        assert snapshot.assignments[0].role_name == "Reader"
        assert snapshot.assignments[0].principal_display_name == "Alice"
        assert len(snapshot.role_definitions) == 1
        assert len(snapshot.scopes.subscriptions) == 1

    def test_build_snapshot_deduplicates(self):
        """Assignments should be deduplicated (same behavior as all_assignments)."""
        assignment = ScannedRoleAssignment(
            id="a-1",
            scope=f"/subscriptions/{VALID_SUB_ID}",
            role_definition_id="/providers/Microsoft.Authorization/roleDefinitions/fake",
            principal_id="p-1",
            principal_type=PrincipalType.USER,
            role_name="Reader",
            role_type=RoleType.BUILT_IN,
        )
        scan_result = RbacScanResult(
            subscription_results=[
                SubscriptionScanResult(
                    subscription_id=VALID_SUB_ID,
                    subscription_name="Test-Sub",
                    assignments=[assignment, assignment],
                )
            ]
        )
        snapshot = build_snapshot(
            scan_result=scan_result,
            tenant_id=VALID_TENANT_ID,
            subscriptions=[],
            management_groups=[],
        )
        assert len(snapshot.assignments) == 1

    def test_build_snapshot_has_tool_version(self):
        scan_result = RbacScanResult()
        snapshot = build_snapshot(
            scan_result=scan_result,
            tenant_id=VALID_TENANT_ID,
            subscriptions=[],
            management_groups=[],
        )
        assert snapshot.metadata.tool_version != ""
```

**Step 2:** Run tests to verify they fail:

```bash
.venv/bin/python -m pytest tests/test_snapshot.py::TestBuildSnapshot -v
```

**Step 3: Implement `build_snapshot`**

Add to `src/az_rbac_watch/scanner/snapshot.py`:

```python
from datetime import UTC

from az_rbac_watch.scanner.rbac_scanner import RbacScanResult


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
```

Add `"build_snapshot"` to `__all__`.

**Step 4:** Run tests:

```bash
.venv/bin/python -m pytest tests/test_snapshot.py -v
```

**Step 5:** Run lint:

```bash
.venv/bin/ruff check src/az_rbac_watch/scanner/snapshot.py tests/test_snapshot.py && .venv/bin/mypy src/az_rbac_watch/scanner/snapshot.py tests/test_snapshot.py
```

**Step 6:** Commit:

```bash
git add src/az_rbac_watch/scanner/snapshot.py tests/test_snapshot.py
git commit -m "feat: add build_snapshot to convert scan results to snapshots"
```

---

## Task 3: Create the diff engine

**Files:**
- Create: `src/az_rbac_watch/analyzers/diff.py`
- Create: `tests/test_diff.py`

**Step 1: Write the failing tests**

Create `tests/test_diff.py`:

```python
"""Unit tests for the snapshot diff engine."""

from __future__ import annotations

from az_rbac_watch.analyzers.diff import (
    DiffChange,
    DiffResult,
    compute_diff,
)
from az_rbac_watch.scanner.snapshot import SnapshotAssignment


def _make_sa(**overrides: object) -> SnapshotAssignment:
    defaults = {
        "id": "a-1",
        "scope": "/subscriptions/sub-1",
        "role_name": "Reader",
        "role_type": "BuiltInRole",
        "principal_id": "p-1",
        "principal_type": "User",
        "principal_display_name": "Alice",
    }
    defaults.update(overrides)
    return SnapshotAssignment(**defaults)


class TestComputeDiff:
    def test_no_changes(self):
        a = _make_sa()
        result = compute_diff([a], [a])
        assert len(result.added) == 0
        assert len(result.removed) == 0
        assert len(result.modified) == 0

    def test_added_assignment(self):
        old: list[SnapshotAssignment] = []
        new = [_make_sa()]
        result = compute_diff(old, new)
        assert len(result.added) == 1
        assert result.added[0].id == "a-1"

    def test_removed_assignment(self):
        old = [_make_sa()]
        new: list[SnapshotAssignment] = []
        result = compute_diff(old, new)
        assert len(result.removed) == 1
        assert result.removed[0].id == "a-1"

    def test_modified_role(self):
        old = [_make_sa(role_name="Reader")]
        new = [_make_sa(role_name="Contributor")]
        result = compute_diff(old, new)
        assert len(result.modified) == 1
        assert result.modified[0].field == "role_name"
        assert result.modified[0].old_value == "Reader"
        assert result.modified[0].new_value == "Contributor"

    def test_modified_scope(self):
        old = [_make_sa(scope="/subscriptions/sub-1")]
        new = [_make_sa(scope="/subscriptions/sub-2")]
        result = compute_diff(old, new)
        assert len(result.modified) == 1
        assert result.modified[0].field == "scope"

    def test_modified_principal_display_name(self):
        old = [_make_sa(principal_display_name="Alice")]
        new = [_make_sa(principal_display_name="Alice Smith")]
        result = compute_diff(old, new)
        assert len(result.modified) == 1
        assert result.modified[0].field == "principal_display_name"

    def test_multiple_changes_on_same_assignment(self):
        old = [_make_sa(role_name="Reader", scope="/subscriptions/sub-1")]
        new = [_make_sa(role_name="Contributor", scope="/subscriptions/sub-2")]
        result = compute_diff(old, new)
        assert len(result.modified) == 2

    def test_mixed_changes(self):
        a1 = _make_sa(id="a-1")
        a2 = _make_sa(id="a-2", principal_id="p-2")
        a3 = _make_sa(id="a-3", principal_id="p-3")
        a2_modified = _make_sa(id="a-2", principal_id="p-2", role_name="Contributor")

        result = compute_diff(old=[a1, a2], new=[a2_modified, a3])
        assert len(result.removed) == 1  # a-1 removed
        assert len(result.added) == 1    # a-3 added
        assert len(result.modified) == 1 # a-2 role changed

    def test_has_changes(self):
        assert not compute_diff([], []).has_changes
        assert compute_diff([], [_make_sa()]).has_changes

    def test_summary_counts(self):
        result = compute_diff(
            old=[_make_sa(id="a-1"), _make_sa(id="a-2", principal_id="p-2")],
            new=[_make_sa(id="a-2", principal_id="p-2", role_name="Contributor")],
        )
        assert result.added_count == 0
        assert result.removed_count == 1
        assert result.modified_count == 1
```

**Step 2:** Run tests to verify they fail:

```bash
.venv/bin/python -m pytest tests/test_diff.py -v
```

**Step 3: Implement the diff engine**

Create `src/az_rbac_watch/analyzers/diff.py`:

```python
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
```

**Step 4:** Run tests:

```bash
.venv/bin/python -m pytest tests/test_diff.py -v
```

**Step 5:** Run lint:

```bash
.venv/bin/ruff check src/az_rbac_watch/analyzers/diff.py tests/test_diff.py && .venv/bin/mypy src/az_rbac_watch/analyzers/diff.py tests/test_diff.py
```

**Step 6:** Commit:

```bash
git add src/az_rbac_watch/analyzers/diff.py tests/test_diff.py
git commit -m "feat: add diff engine to compare snapshot assignments"
```

---

## Task 4: Add diff console and JSON reporters

**Files:**
- Create: `src/az_rbac_watch/reporters/diff_report.py`
- Create: `tests/test_diff_report.py`

**Step 1: Write the failing tests**

Create `tests/test_diff_report.py`:

```python
"""Unit tests for the diff reporter."""

from __future__ import annotations

from az_rbac_watch.analyzers.diff import DiffChange, DiffResult
from az_rbac_watch.reporters.diff_report import format_diff_json, format_diff_console
from az_rbac_watch.scanner.snapshot import SnapshotAssignment


def _make_sa(**overrides: object) -> SnapshotAssignment:
    defaults = {
        "id": "a-1",
        "scope": "/subscriptions/sub-1",
        "role_name": "Reader",
        "role_type": "BuiltInRole",
        "principal_id": "p-1",
        "principal_type": "User",
        "principal_display_name": "Alice",
    }
    defaults.update(overrides)
    return SnapshotAssignment(**defaults)


class TestDiffJsonReport:
    def test_empty_diff(self):
        result = DiffResult()
        output = format_diff_json(result)
        assert '"added": []' in output
        assert '"removed": []' in output
        assert '"modified": []' in output

    def test_json_contains_added(self):
        result = DiffResult(added=[_make_sa()])
        output = format_diff_json(result)
        assert '"a-1"' in output
        assert '"Reader"' in output

    def test_json_contains_summary(self):
        result = DiffResult(
            added=[_make_sa()],
            removed=[_make_sa(id="a-2", principal_id="p-2")],
        )
        output = format_diff_json(result)
        assert '"added_count": 1' in output
        assert '"removed_count": 1' in output


class TestDiffConsoleReport:
    def test_no_changes(self):
        result = DiffResult()
        output = format_diff_console(result)
        assert "No changes" in output

    def test_added_shown(self):
        result = DiffResult(added=[_make_sa()])
        output = format_diff_console(result)
        assert "Added" in output or "added" in output
        assert "Reader" in output

    def test_removed_shown(self):
        result = DiffResult(removed=[_make_sa()])
        output = format_diff_console(result)
        assert "Removed" in output or "removed" in output

    def test_modified_shown(self):
        result = DiffResult(modified=[
            DiffChange(assignment_id="a-1", field="role_name", old_value="Reader", new_value="Contributor"),
        ])
        output = format_diff_console(result)
        assert "Reader" in output
        assert "Contributor" in output
```

**Step 2:** Run tests to verify they fail:

```bash
.venv/bin/python -m pytest tests/test_diff_report.py -v
```

**Step 3: Implement the diff reporter**

Create `src/az_rbac_watch/reporters/diff_report.py`:

```python
"""Reporters for snapshot diff results — console (plain text) and JSON."""

from __future__ import annotations

import json

from az_rbac_watch.analyzers.diff import DiffResult

__all__ = ["format_diff_console", "format_diff_json"]


def format_diff_json(result: DiffResult) -> str:
    """Format diff result as JSON."""
    data = {
        "summary": {
            "added_count": result.added_count,
            "removed_count": result.removed_count,
            "modified_count": result.modified_count,
            "has_changes": result.has_changes,
        },
        "added": [a.model_dump(mode="json") for a in result.added],
        "removed": [a.model_dump(mode="json") for a in result.removed],
        "modified": [c.model_dump(mode="json") for c in result.modified],
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


def format_diff_console(result: DiffResult) -> str:
    """Format diff result as human-readable text."""
    if not result.has_changes:
        return "No changes detected between snapshots."

    lines: list[str] = []
    lines.append(
        f"Changes: +{result.added_count} added, "
        f"-{result.removed_count} removed, "
        f"~{result.modified_count} modified"
    )
    lines.append("")

    if result.added:
        lines.append("Added assignments:")
        for a in result.added:
            name = a.principal_display_name or a.principal_id
            lines.append(f"  + {name} — {a.role_name or '?'} at {a.scope}")
        lines.append("")

    if result.removed:
        lines.append("Removed assignments:")
        for a in result.removed:
            name = a.principal_display_name or a.principal_id
            lines.append(f"  - {name} — {a.role_name or '?'} at {a.scope}")
        lines.append("")

    if result.modified:
        lines.append("Modified assignments:")
        current_id = ""
        for c in result.modified:
            if c.assignment_id != current_id:
                current_id = c.assignment_id
                lines.append(f"  ~ {c.assignment_id}:")
            lines.append(f"      {c.field}: {c.old_value} → {c.new_value}")
        lines.append("")

    return "\n".join(lines)
```

**Step 4:** Run tests:

```bash
.venv/bin/python -m pytest tests/test_diff_report.py -v
```

**Step 5:** Run lint:

```bash
.venv/bin/ruff check src/az_rbac_watch/reporters/diff_report.py tests/test_diff_report.py && .venv/bin/mypy src/az_rbac_watch/reporters/diff_report.py tests/test_diff_report.py
```

**Step 6:** Commit:

```bash
git add src/az_rbac_watch/reporters/diff_report.py tests/test_diff_report.py
git commit -m "feat: add console and JSON reporters for snapshot diffs"
```

---

## Task 5: Add `snapshot` CLI command

**Files:**
- Modify: `src/az_rbac_watch/cli.py`
- Modify: `tests/test_cli.py`

**Step 1: Write the failing tests**

Add to `tests/test_cli.py`:

```python
class TestSnapshotCommand:
    def test_snapshot_requires_output(self):
        """snapshot without -o should error."""
        result = runner.invoke(app, ["snapshot", "-t", VALID_TENANT_ID])
        assert result.exit_code == 2

    def test_snapshot_requires_tenant_id(self):
        """snapshot without -t should error (when no policy)."""
        result = runner.invoke(app, ["snapshot"])
        assert result.exit_code == 2

    @patch("az_rbac_watch.cli.check_credentials", return_value=True)
    @patch("az_rbac_watch.cli.list_accessible_subscriptions")
    @patch("az_rbac_watch.cli.scan_rbac")
    @patch("az_rbac_watch.cli.resolve_display_names")
    def test_snapshot_creates_file(
        self, mock_resolve, mock_scan, mock_list_subs, mock_creds, runner, tmp_path
    ):
        mock_list_subs.return_value = [(VALID_SUB_ID, "Test-Sub", VALID_TENANT_ID)]
        mock_scan.return_value = RbacScanResult(
            subscription_results=[
                SubscriptionScanResult(
                    subscription_id=VALID_SUB_ID,
                    subscription_name="Test-Sub",
                    assignments=[],
                )
            ]
        )
        mock_resolve.return_value = mock_scan.return_value

        output = tmp_path / "snapshot.json"
        result = runner.invoke(app, [
            "snapshot", "-t", VALID_TENANT_ID, "-o", str(output),
        ])
        assert result.exit_code == 0
        assert output.exists()
        import json
        data = json.loads(output.read_text())
        assert data["metadata"]["tenant_id"] == VALID_TENANT_ID
```

Use the same `runner` pattern as other tests (check if it's a fixture or module-level).

**Step 2:** Run tests to verify they fail:

```bash
.venv/bin/python -m pytest tests/test_cli.py::TestSnapshotCommand -v
```

**Step 3: Add `snapshot` command to CLI**

Add to `src/az_rbac_watch/cli.py`:

```python
@app.command()
def snapshot(
    policy: Annotated[
        Path | None,
        typer.Option("--policy", "-p", help="Policy YAML file (uses its scopes)."),
    ] = None,
    tenant_id: Annotated[
        str | None,
        typer.Option("--tenant-id", "-t", help="Tenant ID (auto-detected if omitted)."),
    ] = None,
    subscription: Annotated[
        list[str] | None,
        typer.Option("--subscription", "-s", help="Subscription ID (repeatable)."),
    ] = None,
    management_group: Annotated[
        list[str] | None,
        typer.Option("--management-group", "-m", help="Management group ID (repeatable)."),
    ] = None,
    exclude_subscription: Annotated[
        list[str] | None,
        typer.Option("--exclude-subscription", help="Subscription ID to exclude."),
    ] = None,
    exclude_management_group: Annotated[
        list[str] | None,
        typer.Option("--exclude-management-group", help="Management group ID to exclude."),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output JSON file path."),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable verbose logging."),
    ] = False,
    debug: Annotated[
        bool,
        typer.Option("--debug", help="Show full traceback on error."),
    ] = False,
) -> None:
    """Capture a snapshot of the current RBAC state for later comparison."""
    _debug_callback(debug)
    _setup_logging(verbose)

    if output is None:
        console.print("[bold red]Error[/bold red]: --output / -o is required.")
        raise typer.Exit(code=2)

    if policy is None and tenant_id is None and not subscription and not management_group:
        console.print(
            "[bold red]Error[/bold red]: provide --tenant-id / -t, "
            "--subscription / -s, or --policy / -p."
        )
        raise typer.Exit(code=2)

    _check_credentials_or_exit()

    if policy is not None:
        model = _load_policy_or_exit(policy)
        if model.scope == "all":
            console.print("[dim]Auto-discovering accessible scopes (scope: all)...[/dim]")
            model = resolve_scopes(model)
    else:
        model = _build_model_from_args(tenant_id, subscription, management_group)

    if exclude_subscription or exclude_management_group:
        model = filter_scopes(model, exclude_subscription, exclude_management_group)

    _validate_scopes_or_exit(model)

    # Scan
    try:
        scan_result = _run_scan(model, fmt="console")
    except Exception as e:
        logger.debug("Traceback scan", exc_info=True)
        console.print(f"[bold red]Scan error[/bold red]: {e}")
        if _debug_mode:
            import traceback as tb
            console.print(f"[dim]{tb.format_exc()}[/dim]")
        raise typer.Exit(code=2) from None

    scan_result = _resolve_names(scan_result, fmt="console")

    # Build and save snapshot
    from az_rbac_watch.scanner.snapshot import build_snapshot, save_snapshot

    snap = build_snapshot(
        scan_result=scan_result,
        tenant_id=str(model.tenant_id),
        subscriptions=[{"id": str(s.id), "name": s.name} for s in model.subscriptions],
        management_groups=[{"id": m.id, "name": m.name} for m in model.management_groups],
    )
    save_snapshot(snap, output)

    n_assignments = len(snap.assignments)
    n_defs = len(snap.role_definitions)
    console.print(
        f"\n[bold green]Snapshot saved[/bold green]: {output}\n"
        f"  {n_assignments} assignment(s), {n_defs} role definition(s)\n"
        f"  Tenant: {snap.metadata.tenant_id}\n"
        f"  Timestamp: {snap.metadata.timestamp.isoformat()}"
    )
    raise typer.Exit(code=0)
```

**Step 4:** Run tests:

```bash
.venv/bin/python -m pytest tests/test_cli.py::TestSnapshotCommand -v
```

**Step 5:** Run full suite + lint:

```bash
.venv/bin/python -m pytest -q && .venv/bin/ruff check src/az_rbac_watch/cli.py tests/test_cli.py && .venv/bin/mypy src/az_rbac_watch/cli.py tests/test_cli.py
```

**Step 6:** Commit:

```bash
git add src/az_rbac_watch/cli.py tests/test_cli.py
git commit -m "feat: add snapshot CLI command"
```

---

## Task 6: Add `diff` CLI command

**Files:**
- Modify: `src/az_rbac_watch/cli.py`
- Modify: `tests/test_cli.py`

**Step 1: Write the failing tests**

Add to `tests/test_cli.py`:

```python
class TestDiffCommand:
    def test_diff_requires_two_files(self):
        result = runner.invoke(app, ["diff", "one.json"])
        assert result.exit_code == 2

    def test_diff_file_not_found(self):
        result = runner.invoke(app, ["diff", "nonexistent1.json", "nonexistent2.json"])
        assert result.exit_code == 2

    def test_diff_no_changes(self, tmp_path):
        import json
        snapshot_data = {
            "version": "1.0",
            "metadata": {
                "timestamp": "2026-03-08T12:00:00Z",
                "tenant_id": VALID_TENANT_ID,
                "tool_version": "0.4.0",
            },
            "scopes": {"subscriptions": [], "management_groups": []},
            "assignments": [
                {
                    "id": "a-1",
                    "scope": "/subscriptions/sub-1",
                    "role_name": "Reader",
                    "role_type": "BuiltInRole",
                    "principal_id": "p-1",
                    "principal_type": "User",
                    "principal_display_name": "Alice",
                }
            ],
            "role_definitions": [],
        }
        f1 = tmp_path / "old.json"
        f2 = tmp_path / "new.json"
        f1.write_text(json.dumps(snapshot_data))
        f2.write_text(json.dumps(snapshot_data))
        result = runner.invoke(app, ["diff", str(f1), str(f2)])
        assert result.exit_code == 0
        assert "No changes" in result.output

    def test_diff_with_changes(self, tmp_path):
        import json
        old_data = {
            "version": "1.0",
            "metadata": {
                "timestamp": "2026-03-08T12:00:00Z",
                "tenant_id": VALID_TENANT_ID,
                "tool_version": "0.4.0",
            },
            "scopes": {"subscriptions": [], "management_groups": []},
            "assignments": [
                {
                    "id": "a-1",
                    "scope": "/subscriptions/sub-1",
                    "role_name": "Reader",
                    "role_type": "BuiltInRole",
                    "principal_id": "p-1",
                    "principal_type": "User",
                    "principal_display_name": "Alice",
                }
            ],
            "role_definitions": [],
        }
        new_data = {
            "version": "1.0",
            "metadata": {
                "timestamp": "2026-03-09T12:00:00Z",
                "tenant_id": VALID_TENANT_ID,
                "tool_version": "0.4.0",
            },
            "scopes": {"subscriptions": [], "management_groups": []},
            "assignments": [],
            "role_definitions": [],
        }
        f1 = tmp_path / "old.json"
        f2 = tmp_path / "new.json"
        f1.write_text(json.dumps(old_data))
        f2.write_text(json.dumps(new_data))
        result = runner.invoke(app, ["diff", str(f1), str(f2)])
        assert result.exit_code == 1
        assert "Removed" in result.output or "removed" in result.output

    def test_diff_json_format(self, tmp_path):
        import json
        snapshot_data = {
            "version": "1.0",
            "metadata": {
                "timestamp": "2026-03-08T12:00:00Z",
                "tenant_id": VALID_TENANT_ID,
                "tool_version": "0.4.0",
            },
            "scopes": {"subscriptions": [], "management_groups": []},
            "assignments": [],
            "role_definitions": [],
        }
        f1 = tmp_path / "old.json"
        f2 = tmp_path / "new.json"
        f1.write_text(json.dumps(snapshot_data))
        f2.write_text(json.dumps(snapshot_data))
        result = runner.invoke(app, ["diff", str(f1), str(f2), "--format", "json"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["summary"]["has_changes"] is False
```

**Step 2:** Run tests to verify they fail:

```bash
.venv/bin/python -m pytest tests/test_cli.py::TestDiffCommand -v
```

**Step 3: Add `diff` command to CLI**

Add to `src/az_rbac_watch/cli.py`:

```python
@app.command(name="diff")
def diff_snapshots(
    old_snapshot: Annotated[
        Path,
        typer.Argument(help="Path to the older snapshot JSON file."),
    ],
    new_snapshot: Annotated[
        Path,
        typer.Argument(help="Path to the newer snapshot JSON file."),
    ],
    fmt: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: console, json."),
    ] = "console",
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file path."),
    ] = None,
) -> None:
    """Compare two snapshots and show RBAC changes."""
    if fmt not in ("console", "json"):
        console.print(f"[bold red]Error[/bold red]: Unknown format '{fmt}'. Use 'console' or 'json'.")
        raise typer.Exit(code=2)

    from az_rbac_watch.analyzers.diff import compute_diff
    from az_rbac_watch.reporters.diff_report import format_diff_console, format_diff_json
    from az_rbac_watch.scanner.snapshot import load_snapshot

    try:
        old = load_snapshot(old_snapshot)
        new = load_snapshot(new_snapshot)
    except FileNotFoundError as e:
        console.print(f"[bold red]Error[/bold red]: {e}")
        raise typer.Exit(code=2) from None
    except Exception as e:
        console.print(f"[bold red]Error[/bold red]: Failed to load snapshot: {e}")
        raise typer.Exit(code=2) from None

    result = compute_diff(old.assignments, new.assignments)

    if fmt == "json":
        text = format_diff_json(result)
    else:
        text = format_diff_console(result)

    if output is not None:
        output.write_text(text, encoding="utf-8")
        console.print(f"Diff report written to: [bold]{output}[/bold]")
    else:
        output_console = Console(no_color=_no_color_mode)
        output_console.print(text)

    raise typer.Exit(code=1 if result.has_changes else 0)
```

Note: the function is named `diff_snapshots` to avoid shadowing Python's built-in `diff`, but the Typer command name is `"diff"`.

**Step 4:** Run tests:

```bash
.venv/bin/python -m pytest tests/test_cli.py::TestDiffCommand -v
```

**Step 5:** Run full suite + lint:

```bash
.venv/bin/python -m pytest -q && .venv/bin/ruff check . && .venv/bin/mypy src/ tests/
```

**Step 6:** Commit:

```bash
git add src/az_rbac_watch/cli.py tests/test_cli.py
git commit -m "feat: add diff CLI command to compare snapshots"
```

---

## Task 7: Final verification

**Step 1:** Run all validations:

```bash
.venv/bin/python -m pytest -q && .venv/bin/ruff check . && .venv/bin/mypy src/ tests/
```

**Step 2:** Verify new commands appear in help:

```bash
.venv/bin/az-rbac-watch --help | grep -E "snapshot|diff"
.venv/bin/az-rbac-watch snapshot --help
.venv/bin/az-rbac-watch diff --help
```

**Step 3:** Smoke test — create and compare snapshots offline:

```bash
# Create two test snapshot files and diff them
.venv/bin/python -c "
import json
base = {
    'version': '1.0',
    'metadata': {'timestamp': '2026-03-08T12:00:00Z', 'tenant_id': 'test', 'tool_version': '0.4.0'},
    'scopes': {'subscriptions': [], 'management_groups': []},
    'assignments': [
        {'id': 'a-1', 'scope': '/sub/1', 'role_name': 'Reader', 'role_type': 'BuiltInRole',
         'principal_id': 'p-1', 'principal_type': 'User', 'principal_display_name': 'Alice'}
    ],
    'role_definitions': []
}
open('/tmp/snap-old.json', 'w').write(json.dumps(base))
base['assignments'][0]['role_name'] = 'Contributor'
base['metadata']['timestamp'] = '2026-03-09T12:00:00Z'
open('/tmp/snap-new.json', 'w').write(json.dumps(base))
"
.venv/bin/az-rbac-watch diff /tmp/snap-old.json /tmp/snap-new.json
```

Expected: shows modification (Reader → Contributor), exit code 1.

---

## Execution order summary

| Task | Component | Depends on |
|------|-----------|------------|
| 1 | Snapshot model (save/load) | — |
| 2 | build_snapshot (scan result → snapshot) | 1 |
| 3 | Diff engine (compute_diff) | 1 |
| 4 | Diff reporters (console + JSON) | 3 |
| 5 | `snapshot` CLI command | 1, 2 |
| 6 | `diff` CLI command | 3, 4 |
| 7 | Final verification | 1-6 |

Tasks 1 is the foundation. Tasks 2 and 3 can be parallelized. Tasks 4 and 5 can be parallelized. Task 6 depends on 3-4. Task 7 is last.
