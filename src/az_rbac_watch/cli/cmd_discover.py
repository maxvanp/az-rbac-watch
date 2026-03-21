"""CLI discover command."""

from __future__ import annotations

import traceback
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn

import az_rbac_watch.cli._helpers as _h
from az_rbac_watch.cli import app


@app.command()
def discover(
    policy: Annotated[
        Path | None,
        typer.Option("--policy", "-p", help="Policy YAML file (optional)."),
    ] = None,
    tenant_id: Annotated[
        str | None,
        typer.Option("--tenant-id", "-t", help="Tenant ID (auto-detected if omitted)."),
    ] = None,
    subscription: Annotated[
        list[str] | None,
        typer.Option("--subscription", "-s", help="Subscription ID (repeatable)."),
    ] = None,
    management_group: Annotated[
        list[str] | None,
        typer.Option("--management-group", "-m", help="Management group ID (repeatable)."),
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
        Path,
        typer.Option("--output", "-o", help="Output YAML file path."),
    ] = Path("discovered_policy.yaml"),
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
) -> None:
    """Discover existing RBAC assignments and generate a draft policy model."""
    _h._debug_callback(debug)
    _h._setup_logging(verbose)

    if not dry_run:
        _h._check_credentials_or_exit()

    # 1. Build the PolicyModel
    if policy is not None:
        model = _h._load_policy_or_exit(policy)
        if model.scope == "all":
            _h.console.print("[dim]Auto-discovering accessible scopes (scope: all)...[/dim]")
            model = _h.resolve_scopes(model)
    else:
        model = _h._build_model_from_args(tenant_id, subscription, management_group)

    # 2. Apply exclusions
    if exclude_subscription or exclude_management_group:
        model = _h.filter_scopes(model, exclude_subscription, exclude_management_group)

    _h._validate_scopes_or_exit(model)

    if dry_run:
        _h._print_dry_run_plan(model)
        raise typer.Exit(code=0)

    # 3. Scan RBAC
    total_scopes = len(model.subscriptions) + len(model.management_groups)
    try:
        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            console=_h.console,
        ) as progress:
            task = progress.add_task("Scan RBAC", total=total_scopes)

            def _on_progress(scope_type: str, scope_name: str) -> None:
                progress.update(task, description=f"Scanning {scope_type}: {scope_name}")
                progress.advance(task)

            scan_result = _h.scan_rbac(model, progress_callback=_on_progress)
    except Exception as e:
        _h.logger.debug("Traceback scan", exc_info=True)
        _h.console.print(f"[bold red]Scan error[/bold red]: {e}")
        if _h._debug_mode:
            _h.console.print(f"[dim]{traceback.format_exc()}[/dim]")
        else:
            _h.console.print("[dim]Rerun with --debug for full traceback.[/dim]")
        raise typer.Exit(code=2) from None

    # 4. Discovery
    with _h.console.status("Resolving names via Graph API..."):
        discovered = _h.discover_policy(
            scan_result,
            tenant_id=str(model.tenant_id),
            subscriptions=model.subscriptions,
            management_groups=model.management_groups,
        )

    # 5. Save
    _h.save_policy_model(discovered, output)

    # 6. Summary
    output_console = Console(no_color=_h._no_color_mode)
    _h.print_discover_summary(discovered, output, console=output_console)
