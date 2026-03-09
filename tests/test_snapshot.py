"""Unit tests for the snapshot model."""

from __future__ import annotations

from datetime import UTC, datetime

from az_rbac_watch.scanner.rbac_scanner import (
    PrincipalType,
    RbacScanResult,
    RoleType,
    ScannedRoleAssignment,
    ScannedRoleDefinition,
    SubscriptionScanResult,
)
from az_rbac_watch.scanner.snapshot import (
    Snapshot,
    SnapshotAssignment,
    SnapshotMetadata,
    SnapshotRoleDefinition,
    SnapshotScope,
    build_snapshot,
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


VALID_TENANT_ID = "11111111-1111-1111-1111-111111111111"
VALID_SUB_ID = "22222222-2222-2222-2222-222222222222"


class TestBuildSnapshot:
    def test_build_from_scan_result(self) -> None:
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

    def test_build_snapshot_deduplicates(self) -> None:
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

    def test_build_snapshot_has_tool_version(self) -> None:
        scan_result = RbacScanResult()
        snapshot = build_snapshot(
            scan_result=scan_result,
            tenant_id=VALID_TENANT_ID,
            subscriptions=[],
            management_groups=[],
        )
        assert snapshot.metadata.tool_version != ""
