"""Data models for compliance framework mapping.

Defines the structures used to represent compliance frameworks (e.g. CIS Azure
Benchmark), their controls, and the results of mapping findings to controls.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from az_rbac_watch.analyzers.compliance import ComplianceFinding

__all__ = [
    "ControlResult",
    "FrameworkComplianceReport",
    "FrameworkControl",
    "FrameworkDefinition",
]


class FrameworkControl(BaseModel):
    """A single control within a compliance framework."""

    id: str
    title: str
    description: str = ""
    severity: str = "medium"
    rule_names: list[str] = Field(default_factory=list)
    remediation: str = ""


class FrameworkDefinition(BaseModel):
    """A compliance framework with its controls."""

    name: str
    version: str
    section: str
    controls: list[FrameworkControl] = Field(default_factory=list)


class ControlResult(BaseModel):
    """Result of evaluating a single control."""

    control: FrameworkControl
    status: str  # "pass", "fail", or "manual"
    findings: list[ComplianceFinding] = Field(default_factory=list)
    finding_count: int = 0


class FrameworkComplianceReport(BaseModel):
    """Complete framework compliance report."""

    framework: FrameworkDefinition
    tenant_id: str
    scan_timestamp: datetime
    control_results: list[ControlResult] = Field(default_factory=list)
    total_controls: int = 0
    passing_controls: int = 0
    failing_controls: int = 0
    compliance_score: int = 0  # 0-100 (% passing controls)
    total_findings: int = 0
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
