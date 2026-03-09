"""JSON reporter for compliance scan results — machine-readable output for CI/CD."""

from __future__ import annotations

import json

from az_rbac_watch.analyzers.compliance import ComplianceReport
from az_rbac_watch.utils.portal_links import build_principal_url, build_scope_url

__all__ = ["generate_json_report"]


def generate_json_report(report: ComplianceReport) -> str:
    """Serialize a ComplianceReport to a JSON string.

    Uses Pydantic's model_dump with mode="json" so that enums, datetimes, and
    UUIDs are properly serialized as plain JSON types.
    """
    data = report.model_dump(mode="json")
    tenant_id = report.tenant_id
    for finding in data.get("findings", []):
        finding["scope_url"] = build_scope_url(finding.get("scope", ""), tenant_id)
        finding["principal_url"] = build_principal_url(finding.get("principal_id", ""))
    return json.dumps(data, indent=2, ensure_ascii=False)
