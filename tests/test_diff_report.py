"""Unit tests for the diff reporter."""

from __future__ import annotations

from az_rbac_watch.analyzers.diff import DiffChange, DiffResult
from az_rbac_watch.reporters.diff_report import format_diff_console, format_diff_json
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
    def test_empty_diff(self) -> None:
        result = DiffResult()
        output = format_diff_json(result)
        assert '"added": []' in output
        assert '"removed": []' in output
        assert '"modified": []' in output

    def test_json_contains_added(self) -> None:
        result = DiffResult(added=[_make_sa()])
        output = format_diff_json(result)
        assert '"a-1"' in output
        assert '"Reader"' in output

    def test_json_contains_summary(self) -> None:
        result = DiffResult(
            added=[_make_sa()],
            removed=[_make_sa(id="a-2", principal_id="p-2")],
        )
        output = format_diff_json(result)
        assert '"added_count": 1' in output
        assert '"removed_count": 1' in output


class TestDiffConsoleReport:
    def test_no_changes(self) -> None:
        result = DiffResult()
        output = format_diff_console(result)
        assert "No changes" in output

    def test_added_shown(self) -> None:
        result = DiffResult(added=[_make_sa()])
        output = format_diff_console(result)
        assert "Added" in output or "added" in output
        assert "Reader" in output

    def test_removed_shown(self) -> None:
        result = DiffResult(removed=[_make_sa()])
        output = format_diff_console(result)
        assert "Removed" in output or "removed" in output

    def test_modified_shown(self) -> None:
        result = DiffResult(
            modified=[
                DiffChange(assignment_id="a-1", field="role_name", old_value="Reader", new_value="Contributor"),
            ]
        )
        output = format_diff_console(result)
        assert "Reader" in output
        assert "Contributor" in output
