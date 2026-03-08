"""Rich console output for scan (drift) and audit (violations) results."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from az_rbac_watch.analyzers.compliance import SEVERITY_ORDER, ComplianceReport, Severity
from az_rbac_watch.config.policy_model import PolicyModel

__all__ = ["print_audit_report", "print_compliance_report", "print_discover_summary", "print_drift_report"]

# ── Severity → Rich style mapping ────────────────────────────

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def _print_report(
    report: ComplianceReport,
    *,
    title: str,
    drift_label: str,
    violation_label: str,
    ok_message: str,
    ko_message_template: str,
    console: Console | None = None,
) -> None:
    """Print a report to the console with configurable vocabulary."""
    console = console or Console()

    # 1. Header
    console.print()
    console.print(
        Panel(
            f"[bold]Tenant[/bold] : {report.tenant_id}\n"
            f"[bold]Policy version[/bold] : {report.policy_version}\n"
            f"[bold]Scan[/bold] : {report.scan_timestamp:%Y-%m-%d %H:%M:%S UTC}",
            title=title,
            border_style="blue",
        )
    )

    # 2. Warnings
    if report.warnings:
        warning_lines = "\n".join(f"  - {w}" for w in report.warnings)
        console.print(
            Panel(
                warning_lines,
                title="Warnings",
                border_style="yellow",
            )
        )

    # 3. Summary
    s = report.summary
    summary_lines = f"Assignments scanned    : [bold]{s.total_assignments_checked}[/bold]\n"
    if s.drift_count or s.violation_count:
        summary_lines += f"Findings               : [bold]{s.total_findings}[/bold]\n"
        if drift_label and s.drift_count:
            summary_lines += f"  {drift_label:27s}: {s.drift_count}\n"
        if violation_label and s.violation_count:
            summary_lines += f"  {violation_label:27s}: {s.violation_count}"
    else:
        summary_lines += f"Findings               : [bold]{s.total_findings}[/bold]"

    console.print(
        Panel(
            summary_lines.rstrip(),
            title="Summary",
            border_style="cyan",
        )
    )

    # 4. Table des findings
    if report.findings:
        sorted_findings = sorted(
            report.findings,
            key=lambda f: SEVERITY_ORDER.get(f.severity, 99),
        )

        table = Table(title="Findings", show_lines=True)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Rule", width=24)
        table.add_column("Principal", width=38)
        table.add_column("Role", width=20)
        table.add_column("Scope", max_width=60)

        for f in sorted_findings:
            style = _SEVERITY_STYLE.get(f.severity, "")
            severity_text = Text(f.severity.value.upper(), style=style)
            principal_cell = (
                f"{f.principal_display_name}\n({f.principal_id})" if f.principal_display_name else f.principal_id
            )
            remediation = f.details.get("remediation", "")
            scope_cell = f.scope
            if remediation:
                scope_cell = f"{f.scope}\n[dim]Remediation : {remediation}[/dim]"
            table.add_row(
                severity_text,
                f.rule_id,
                principal_cell,
                f.role_name,
                scope_cell,
            )

        console.print(table)

    # 5. Scan errors
    if report.scan_errors:
        error_lines = "\n".join(f"  - {e}" for e in report.scan_errors)
        console.print(
            Panel(
                error_lines,
                title="Scan errors",
                border_style="red",
            )
        )

    # 6. Final summary line
    console.print()
    if report.summary.total_findings == 0:
        console.print(f"[bold green]{ok_message}[/bold green]")
    else:
        n = report.summary.total_findings
        console.print(f"[bold red]{ko_message_template.format(n=n)}[/bold red]")
    console.print()


def print_drift_report(
    report: ComplianceReport,
    console: Console | None = None,
) -> None:
    """Print a drift (scan) report — undeclared assignments."""
    _print_report(
        report,
        title="Azure Permissions Watch — Drift Report",
        drift_label="Undeclared assignments",
        violation_label="",
        ok_message="No drift — actual state matches desired state.",
        ko_message_template="{n} undeclared assignment(s) detected",
        console=console,
    )


def print_audit_report(
    report: ComplianceReport,
    console: Console | None = None,
) -> None:
    """Print an audit report — guardrail violations."""
    _print_report(
        report,
        title="Azure Permissions Watch — Audit Report",
        drift_label="",
        violation_label="Guardrail violations",
        ok_message="No violations — all guardrails passed.",
        ko_message_template="{n} guardrail violation(s) detected",
        console=console,
    )


def print_compliance_report(
    report: ComplianceReport,
    console: Console | None = None,
) -> None:
    """Print a combined report (drift + violations)."""
    _print_report(
        report,
        title="Azure Permissions Watch — Report",
        drift_label="Undeclared assignments",
        violation_label="Guardrail violations",
        ok_message="Compliant — no findings.",
        ko_message_template="{n} finding(s) detected",
        console=console,
    )


def print_discover_summary(
    policy: PolicyModel,
    output_path: Path,
    console: Console | None = None,
) -> None:
    """Print a summary after generating a policy model via discovery.

    Args:
        policy: The generated PolicyModel.
        output_path: Path to the created YAML file.
        console: Rich Console (injected for tests).
    """
    console = console or Console()
    n_baseline = sum(1 for r in policy.rules if r.type == "baseline")

    console.print()
    console.print(
        Panel(
            f"[bold]{n_baseline}[/bold] baseline rule(s) discovered\n"
            f"Output file : [bold]{output_path}[/bold]\n\n"
            "[dim]Review and adjust the file before using it as a reference.[/dim]",
            title="Azure Permissions Watch — Discovery",
            border_style="green",
        )
    )
    console.print()
