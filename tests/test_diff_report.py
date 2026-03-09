"""Unit tests for the diff reporter."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from az_rbac_watch.analyzers.diff import DiffChange, DiffResult
from az_rbac_watch.reporters.diff_report import format_diff_console, format_diff_html, format_diff_json
from az_rbac_watch.scanner.snapshot import Snapshot, SnapshotAssignment, SnapshotMetadata, SnapshotScope


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


def _make_snapshot(ts: datetime | None = None) -> Snapshot:
    return Snapshot(
        metadata=SnapshotMetadata(
            timestamp=ts or datetime(2026, 3, 1, 10, 0, 0, tzinfo=UTC),
            tenant_id="aaaa-bbbb-cccc",
            tool_version="0.7.0",
        ),
        scopes=SnapshotScope(),
    )


class TestDiffHtmlReport:
    def test_generates_valid_html(self, tmp_path: Path) -> None:
        out = tmp_path / "diff.html"
        format_diff_html(DiffResult(), _make_snapshot(), _make_snapshot(), out)
        html = out.read_text(encoding="utf-8")
        assert html.startswith("<!DOCTYPE html>")

    def test_no_changes_verdict(self, tmp_path: Path) -> None:
        out = tmp_path / "diff.html"
        format_diff_html(DiffResult(), _make_snapshot(), _make_snapshot(), out)
        html = out.read_text(encoding="utf-8")
        assert "No changes" in html
        assert "verdict-ok" in html

    def test_changes_verdict(self, tmp_path: Path) -> None:
        result = DiffResult(added=[_make_sa()])
        out = tmp_path / "diff.html"
        format_diff_html(result, _make_snapshot(), _make_snapshot(), out)
        html = out.read_text(encoding="utf-8")
        assert "1 change(s)" in html
        assert "verdict-ko" in html

    def test_stat_cards(self, tmp_path: Path) -> None:
        result = DiffResult(
            added=[_make_sa(id="a-1")],
            removed=[_make_sa(id="a-2", principal_id="p-2")],
        )
        out = tmp_path / "diff.html"
        format_diff_html(result, _make_snapshot(), _make_snapshot(), out)
        html = out.read_text(encoding="utf-8")
        assert "Added" in html
        assert "Removed" in html
        assert "Modified" in html

    def test_added_badge(self, tmp_path: Path) -> None:
        result = DiffResult(added=[_make_sa()])
        out = tmp_path / "diff.html"
        format_diff_html(result, _make_snapshot(), _make_snapshot(), out)
        html = out.read_text(encoding="utf-8")
        assert "ADDED" in html
        assert "Reader" in html
        assert "Alice" in html

    def test_removed_badge(self, tmp_path: Path) -> None:
        result = DiffResult(removed=[_make_sa()])
        out = tmp_path / "diff.html"
        format_diff_html(result, _make_snapshot(), _make_snapshot(), out)
        html = out.read_text(encoding="utf-8")
        assert "REMOVED" in html

    def test_modified_details(self, tmp_path: Path) -> None:
        result = DiffResult(
            modified=[DiffChange(assignment_id="a-1", field="role_name", old_value="Reader", new_value="Contributor")]
        )
        out = tmp_path / "diff.html"
        format_diff_html(result, _make_snapshot(), _make_snapshot(), out)
        html = out.read_text(encoding="utf-8")
        assert "MODIFIED" in html
        assert "Reader" in html
        assert "Contributor" in html

    def test_header_timestamps(self, tmp_path: Path) -> None:
        old_snap = _make_snapshot(datetime(2026, 3, 1, 10, 0, 0, tzinfo=UTC))
        new_snap = _make_snapshot(datetime(2026, 3, 8, 10, 0, 0, tzinfo=UTC))
        out = tmp_path / "diff.html"
        format_diff_html(DiffResult(), old_snap, new_snap, out)
        html = out.read_text(encoding="utf-8")
        assert "2026-03-01" in html
        assert "2026-03-08" in html

    def test_xss_escaped(self, tmp_path: Path) -> None:
        result = DiffResult(added=[_make_sa(principal_display_name='<script>alert("x")</script>')])
        out = tmp_path / "diff.html"
        format_diff_html(result, _make_snapshot(), _make_snapshot(), out)
        html = out.read_text(encoding="utf-8")
        assert "<script>" not in html
        assert "&lt;script&gt;" in html
