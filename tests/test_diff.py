"""Unit tests for the snapshot diff engine."""

from __future__ import annotations

from az_rbac_watch.analyzers.diff import compute_diff
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
    def test_no_changes(self) -> None:
        a = _make_sa()
        result = compute_diff([a], [a])
        assert len(result.added) == 0
        assert len(result.removed) == 0
        assert len(result.modified) == 0

    def test_added_assignment(self) -> None:
        old: list[SnapshotAssignment] = []
        new = [_make_sa()]
        result = compute_diff(old, new)
        assert len(result.added) == 1
        assert result.added[0].id == "a-1"

    def test_removed_assignment(self) -> None:
        old = [_make_sa()]
        new: list[SnapshotAssignment] = []
        result = compute_diff(old, new)
        assert len(result.removed) == 1
        assert result.removed[0].id == "a-1"

    def test_modified_role(self) -> None:
        old = [_make_sa(role_name="Reader")]
        new = [_make_sa(role_name="Contributor")]
        result = compute_diff(old, new)
        assert len(result.modified) == 1
        assert result.modified[0].field == "role_name"
        assert result.modified[0].old_value == "Reader"
        assert result.modified[0].new_value == "Contributor"

    def test_modified_scope(self) -> None:
        old = [_make_sa(scope="/subscriptions/sub-1")]
        new = [_make_sa(scope="/subscriptions/sub-2")]
        result = compute_diff(old, new)
        assert len(result.modified) == 1
        assert result.modified[0].field == "scope"

    def test_modified_principal_display_name(self) -> None:
        old = [_make_sa(principal_display_name="Alice")]
        new = [_make_sa(principal_display_name="Alice Smith")]
        result = compute_diff(old, new)
        assert len(result.modified) == 1
        assert result.modified[0].field == "principal_display_name"

    def test_multiple_changes_on_same_assignment(self) -> None:
        old = [_make_sa(role_name="Reader", scope="/subscriptions/sub-1")]
        new = [_make_sa(role_name="Contributor", scope="/subscriptions/sub-2")]
        result = compute_diff(old, new)
        assert len(result.modified) == 2

    def test_mixed_changes(self) -> None:
        a1 = _make_sa(id="a-1")
        a2 = _make_sa(id="a-2", principal_id="p-2")
        a3 = _make_sa(id="a-3", principal_id="p-3")
        a2_modified = _make_sa(id="a-2", principal_id="p-2", role_name="Contributor")

        result = compute_diff(old=[a1, a2], new=[a2_modified, a3])
        assert len(result.removed) == 1  # a-1 removed
        assert len(result.added) == 1  # a-3 added
        assert len(result.modified) == 1  # a-2 role changed

    def test_has_changes(self) -> None:
        assert not compute_diff([], []).has_changes
        assert compute_diff([], [_make_sa()]).has_changes

    def test_summary_counts(self) -> None:
        result = compute_diff(
            old=[_make_sa(id="a-1"), _make_sa(id="a-2", principal_id="p-2")],
            new=[_make_sa(id="a-2", principal_id="p-2", role_name="Contributor")],
        )
        assert result.added_count == 0
        assert result.removed_count == 1
        assert result.modified_count == 1
