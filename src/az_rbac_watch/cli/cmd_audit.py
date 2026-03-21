"""CLI audit command."""

from __future__ import annotations

import traceback
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

import az_rbac_watch.cli._helpers as _h
from az_rbac_watch.cli import app


@app.command()
def audit(
    policy: Annotated[
        Path | None,
        typer.Option("--policy", "-p", help="Path to policy model YAML file."),
    ] = None,
    subscription: Annotated[
        list[str] | None,
        typer.Option("--subscription", "-s", help="Subscription ID to scan (repeatable, ad-hoc mode)."),
    ] = None,
    management_group: Annotated[
        list[str] | None,
        typer.Option("--management-group", "-m", help="Management group ID to scan (repeatable, ad-hoc mode)."),
    ] = None,
    tenant_id: Annotated[
        str | None,
        typer.Option("--tenant-id", "-t", help="Tenant ID (auto-detected if omitted)."),
    ] = None,
    exclude_subscription: Annotated[
        list[str] | None,
        typer.Option("--exclude-subscription", help="Subscription ID to exclude (repeatable)."),
    ] = None,
    exclude_management_group: Annotated[
        list[str] | None,
        typer.Option("--exclude-management-group", help="Management group ID to exclude (repeatable)."),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file path."),
    ] = None,
    fmt: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: console, json."),
    ] = "console",
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable verbose logging."),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Show scan plan without making API calls."),
    ] = False,
    debug: Annotated[
        bool,
        typer.Option("--debug", help="Show full traceback on error."),
    ] = False,
    framework: Annotated[
        str | None,
        typer.Option("--framework", help="Map findings to a compliance framework (e.g. 'CIS' or path to YAML)."),
    ] = None,
) -> None:
    """Audit guardrails — check governance rules (forbidden patterns).

    Classic mode: --policy <file.yaml>
    Ad-hoc mode:  --subscription <id> (uses default rules)
    """
    _h._debug_callback(debug)
    _h._setup_logging(verbose)

    # Apply default values from configuration
    if policy is None and _h._settings.policy is not None:
        policy = Path(_h._settings.policy)
    if fmt == "console" and _h._settings.format != "console":
        fmt = _h._settings.format

    if fmt not in ("console", "json"):
        _h.console.print(f"[bold red]Error[/bold red]: Unknown format '{fmt}'. Use 'console' or 'json'.")
        raise typer.Exit(code=2)

    # Load framework definition early to fail fast
    fw_definition = None
    if framework is not None:
        from az_rbac_watch.frameworks.mapper import load_framework_definition

        try:
            fw_definition = load_framework_definition(framework)
            _h.console.print(
                f"[dim]Framework: {fw_definition.name} v{fw_definition.version} "
                f"({len(fw_definition.controls)} controls)[/dim]"
            )
        except (FileNotFoundError, ValueError) as e:
            _h.console.print(f"[bold red]Error[/bold red]: {e}")
            raise typer.Exit(code=2) from None

    if not dry_run:
        _h._check_credentials_or_exit()

    model = _h._load_or_build_model(
        policy=policy,
        subscription=subscription,
        management_group=management_group,
        tenant_id=tenant_id,
        inject_default_governance=True,
    )

    # When using a framework, inject the framework's governance rules into the model
    if fw_definition is not None:
        model = _h._inject_framework_rules(model, framework)

    model = _h._resolve_and_filter_model(model, exclude_subscription, exclude_management_group)
    _h._validate_scopes_or_exit(model)

    if dry_run:
        _h._print_dry_run_plan(model)
        raise typer.Exit(code=0)

    # Check governance rules exist
    n_governance = sum(1 for r in model.rules if r.type == "governance")
    if n_governance == 0:
        _h.console.print("[yellow]No governance rules in policy model — nothing to audit.[/yellow]")
        raise typer.Exit(code=0)

    # RBAC scanner
    try:
        scan_result = _h._run_scan(model, fmt=fmt)
    except Exception as e:
        _h.logger.debug("Traceback scan", exc_info=True)
        _h.console.print(f"[bold red]Scan error[/bold red]: {e}")
        if _h._debug_mode:
            _h.console.print(f"[dim]{traceback.format_exc()}[/dim]")
        else:
            _h.console.print("[dim]Rerun with --debug for full traceback.[/dim]")
        raise typer.Exit(code=2) from None

    scan_result = _h._resolve_names(scan_result, fmt=fmt)

    # Audit violations
    report = _h.check_violations(model, scan_result)

    # Framework mapping (if requested)
    if fw_definition is not None and output is not None:
        from az_rbac_watch.frameworks.mapper import FrameworkMapper

        mapper = FrameworkMapper(fw_definition)
        fw_report = mapper.map_report(report)
        _h.generate_framework_html_report(fw_report, output)
        _h.console.print(f"Framework compliance report generated: [bold]{output}[/bold]")

        # Also print console summary
        output_console = Console(no_color=_h._no_color_mode)
        _h.print_audit_report(report, console=output_console)

        _h.console.print(
            f"\n[dim]Framework: {fw_definition.name} v{fw_definition.version}\n"
            f"  Score: {fw_report.compliance_score}% "
            f"({fw_report.passing_controls}/{fw_report.passing_controls + fw_report.failing_controls} "
            f"controls passing)[/dim]"
        )
    elif fw_definition is not None:
        # Framework requested but no output file — print console report + framework summary
        from az_rbac_watch.frameworks.mapper import FrameworkMapper

        mapper = FrameworkMapper(fw_definition)
        fw_report = mapper.map_report(report)

        output_console = Console(no_color=_h._no_color_mode)
        _h.print_audit_report(report, console=output_console)

        _h.console.print(
            f"\n[dim]Framework: {fw_definition.name} v{fw_definition.version}\n"
            f"  Score: {fw_report.compliance_score}% "
            f"({fw_report.passing_controls}/{fw_report.passing_controls + fw_report.failing_controls} "
            f"controls passing)\n"
            f"  Use --output report.html to generate the full framework compliance report.[/dim]"
        )
    else:
        _h._output_report(
            report,
            fmt=fmt,
            output=output,
            model=model,
            console_printer=_h.print_audit_report,
            html_mode="audit",
        )

    # Next steps footer (console only)
    if fmt == "console" and policy is None and framework is None:
        _h.console.print(
            "\n[dim]Next steps:\n"
            "  az-rbac-watch discover -o policy.yaml  # capture current state\n"
            "  az-rbac-watch scan -p policy.yaml       # detect drift[/dim]"
        )

    raise typer.Exit(code=_h._exit_code(report))
