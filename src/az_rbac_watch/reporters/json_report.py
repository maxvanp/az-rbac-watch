"""JSON reporter for compliance scan results — machine-readable output for CI/CD."""

from __future__ import annotations

import json

from az_rbac_watch.analyzers.compliance import ComplianceReport

__all__ = ["generate_json_report"]


def generate_json_report(report: ComplianceReport) -> str:
    """Serialize a ComplianceReport to a JSON string.

    Uses Pydantic's model_dump with mode="json" so that enums, datetimes, and
    UUIDs are properly serialized as plain JSON types.
    """
    data = report.model_dump(mode="json")
    return json.dumps(data, indent=2, ensure_ascii=False)
