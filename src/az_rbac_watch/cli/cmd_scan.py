"""CLI scan command."""

from __future__ import annotations

import traceback
from pathlib import Path
from typing import Annotated

import typer

import az_rbac_watch.cli._helpers as _h
from az_rbac_watch.cli import app


@app.command()
def scan(
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
    orphans_only: Annotated[
        bool,
        typer.Option("--orphans-only", help="Scan for orphaned assignments only (no policy file needed)."),
    ] = False,
) -> None:
    """Detect RBAC drift — compare actual state to desired state (baseline rules).

    Classic mode: --policy <file.yaml>
    Ad-hoc mode:  --subscription <id> (no policy, every assignment = drift)
    """
    _h._debug_callback(debug)
    _h._setup_logging(verbose)

    if orphans_only and policy is not None:
        _h.console.print("[bold red]Error[/bold red]: --orphans-only and --policy are mutually exclusive.")
        raise typer.Exit(code=2)

    if orphans_only and not tenant_id:
        _h.console.print("[bold red]Error[/bold red]: --orphans-only requires --tenant-id / -t.")
        raise typer.Exit(code=2)

    if orphans_only:
        # Apply default values from configuration
        if fmt == "console" and _h._settings.format != "console":
            fmt = _h._settings.format

        if fmt not in ("console", "json"):
            _h.console.print(f"[bold red]Error[/bold red]: Unknown format '{fmt}'. Use 'console' or 'json'.")
            raise typer.Exit(code=2)

        if not dry_run:
            _h._check_credentials_or_exit()

        model = _h._build_model_from_args(tenant_id, subscription, management_group)
        model = _h._resolve_and_filter_model(model, exclude_subscription, exclude_management_group)
        _h._validate_scopes_or_exit(model)

        if dry_run:
            _h._print_dry_run_plan(model)
            raise typer.Exit(code=0)

        scan_result = _h._run_scan(model, fmt=fmt)
        scan_result = _h._resolve_names(scan_result, fmt=fmt)

        from az_rbac_watch.analyzers.compliance import _build_report, _check_orphans

        orphan_findings = _check_orphans(scan_result.all_assignments)
        report = _build_report(model, scan_result, orphan_findings)

        _h._output_report(
            report,
            fmt=fmt,
            output=output,
            model=model,
            console_printer=_h.print_drift_report,
            html_mode="scan",
        )

        if fmt == "console":
            code = _h._exit_code(report)
            if code == 1:
                n = report.summary.total_findings
                _h.console.print(
                    f"\n[dim]{n} orphaned assignment(s) found. Remove them with:\n"
                    "  az role assignment delete --ids <assignment-id>[/dim]"
                )
            elif code == 0:
                _h.console.print("\n[dim]No orphaned assignments found.[/dim]")

        raise typer.Exit(code=_h._exit_code(report))

    # Apply default values from configuration
    if policy is None and _h._settings.policy is not None:
        policy = Path(_h._settings.policy)
    if fmt == "console" and _h._settings.format != "console":
        fmt = _h._settings.format

    if fmt not in ("console", "json"):
        _h.console.print(f"[bold red]Error[/bold red]: Unknown format '{fmt}'. Use 'console' or 'json'.")
        raise typer.Exit(code=2)

    if not dry_run:
        _h._check_credentials_or_exit()

    model = _h._load_or_build_model(
        policy=policy,
        subscription=subscription,
        management_group=management_group,
        tenant_id=tenant_id,
    )
    model = _h._resolve_and_filter_model(model, exclude_subscription, exclude_management_group)
    _h._validate_scopes_or_exit(model)

    if dry_run:
        _h._print_dry_run_plan(model)
        raise typer.Exit(code=0)

    # Check baseline rules exist — warn user in ad-hoc mode
    n_baseline = sum(1 for r in model.rules if r.type == "baseline")
    if n_baseline == 0 and policy is not None:
        _h.console.print(
            "No baseline rules in policy model. To create a baseline:\n  az-rbac-watch discover -o policy.yaml"
        )
        raise typer.Exit(code=0)
    if n_baseline == 0 and policy is None:
        _h.console.print(
            "[bold yellow]Ad-hoc mode: no baseline rules — every assignment will be reported as drift.[/bold yellow]"
        )
        # Inject a dummy baseline that matches nothing → all assignments become drift
        from az_rbac_watch.config.policy_model import Rule, RuleMatch

        _sentinel = Rule(
            name="_adhoc-empty-baseline",
            type="baseline",
            match=RuleMatch(principal_id="00000000-0000-0000-0000-000000000000"),
        )
        model = model.model_copy(update={"rules": [*list(model.rules), _sentinel]})

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

    # Drift detection
    report = _h.check_drift(model, scan_result)

    _h._output_report(
        report,
        fmt=fmt,
        output=output,
        model=model,
        console_printer=_h.print_drift_report,
        html_mode="scan",
    )

    # Next steps footer (console only)
    if fmt == "console":
        code = _h._exit_code(report)
        if code == 1:
            _h.console.print("\n[dim]Next steps:\n  Review findings and update policy.yaml[/dim]")
        elif code == 0:
            _h.console.print(
                "\n[dim]All clear! Integrate in CI:\n  az-rbac-watch scan -p policy.yaml --format json[/dim]"
            )

    raise typer.Exit(code=_h._exit_code(report))
