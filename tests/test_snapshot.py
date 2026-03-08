"""Unit tests for the snapshot model."""

from __future__ import annotations

from datetime import UTC, datetime

from az_rbac_watch.scanner.snapshot import (
    Snapshot,
    SnapshotAssignment,
    SnapshotMetadata,
    SnapshotRoleDefinition,
    SnapshotScope,
    load_snapshot,
    save_snapshot,
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
