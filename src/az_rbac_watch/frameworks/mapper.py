"""Framework mapper — maps ComplianceReport findings to framework controls.

Groups findings by control, computes pass/fail per control, and produces
an aggregate compliance score.
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from az_rbac_watch.analyzers.compliance import ComplianceFinding, ComplianceReport
from az_rbac_watch.frameworks.models import (
    ControlResult,
    FrameworkComplianceReport,
    FrameworkControl,
    FrameworkDefinition,
)

__all__ = [
    "FrameworkMapper",
    "load_framework_definition",
]

logger = logging.getLogger(__name__)

# Built-in framework registry: short name → YAML filename
_BUILTIN_FRAMEWORKS: dict[str, str] = {
    "CIS": "cis_azure_1_4_0.yaml",
}


class FrameworkMapper:
    """Maps a ComplianceReport to framework controls."""

    def __init__(self, framework: FrameworkDefinition) -> None:
        self.framework = framework

    def map_report(self, report: ComplianceReport) -> FrameworkComplianceReport:
        """Map a ComplianceReport to framework controls."""
        results: list[ControlResult] = []
        for control in self.framework.controls:
            matched = [f for f in report.findings if f.rule_id in control.rule_names]
            if not control.rule_names:
                # No automatable rules — mark as manual review
                results.append(
                    ControlResult(control=control, status="manual", findings=[], finding_count=0)
                )
            else:
                status = "pass" if len(matched) == 0 else "fail"
                results.append(
                    ControlResult(control=control, status=status, findings=matched, finding_count=len(matched))
                )

        auto_results = [r for r in results if r.status != "manual"]
        passing = sum(1 for r in auto_results if r.status == "pass")
        total_auto = len(auto_results)
        score = round(passing / total_auto * 100) if total_auto > 0 else 100

        # Aggregate severity counts across all findings
        severity_counts: dict[str, int] = {}
        all_findings: list[ComplianceFinding] = []
        for r in results:
            all_findings.extend(r.findings)
        for f in all_findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        return FrameworkComplianceReport(
            framework=self.framework,
            tenant_id=report.tenant_id,
            scan_timestamp=report.scan_timestamp,
            control_results=results,
            total_controls=len(results),
            passing_controls=passing,
            failing_controls=sum(1 for r in auto_results if r.status == "fail"),
            compliance_score=score,
            total_findings=len(all_findings),
            findings_by_severity=severity_counts,
        )


def load_framework_definition(name_or_path: str) -> FrameworkDefinition:
    """Load a framework definition from a built-in name or YAML file path.

    Args:
        name_or_path: Either a built-in short name (e.g. "CIS") or a path to a YAML file.

    Returns:
        The parsed FrameworkDefinition.

    Raises:
        FileNotFoundError: If the file or built-in framework is not found.
        ValueError: If the YAML structure is invalid.
    """
    # Check built-in frameworks first
    upper = name_or_path.upper()
    if upper in _BUILTIN_FRAMEWORKS:
        yaml_path = Path(__file__).parent / _BUILTIN_FRAMEWORKS[upper]
    else:
        yaml_path = Path(name_or_path)

    if not yaml_path.exists():
        available = ", ".join(sorted(_BUILTIN_FRAMEWORKS.keys()))
        raise FileNotFoundError(
            f"Framework '{name_or_path}' not found. Built-in frameworks: {available}"
        )

    raw = yaml_path.read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        raise ValueError(f"YAML parsing error in framework file: {e}") from e

    if not isinstance(data, dict):
        raise ValueError("Framework YAML must contain a mapping at the root")

    framework_data = data.get("framework", {})
    controls_data = data.get("controls", [])

    controls = [FrameworkControl.model_validate(c) for c in controls_data]

    return FrameworkDefinition(
        name=framework_data.get("name", "Unknown"),
        version=framework_data.get("version", "0.0"),
        section=framework_data.get("section", ""),
        controls=controls,
    )
