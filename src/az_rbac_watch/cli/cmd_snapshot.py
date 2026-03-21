"""CLI snapshot command."""

from __future__ import annotations

import traceback
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

import az_rbac_watch.cli._helpers as _h
from az_rbac_watch.cli import app


@app.command()
def snapshot(
    policy: Annotated[Path | None, typer.Option("--policy", "-p", help="Policy YAML file (uses its scopes).")] = None,
    tenant_id: Annotated[str | None, typer.Option("--tenant-id", "-t", help="Tenant ID.")] = None,
    subscription: Annotated[
        list[str] | None, typer.Option("--subscription", "-s", help="Subscription ID (repeatable).")
    ] = None,
    management_group: Annotated[
        list[str] | None, typer.Option("--management-group", "-m", help="Management group ID (repeatable).")
    ] = None,
    exclude_subscription: Annotated[
        list[str] | None, typer.Option("--exclude-subscription", help="Subscription ID to exclude.")
    ] = None,
    exclude_management_group: Annotated[
        list[str] | None, typer.Option("--exclude-management-group", help="Management group ID to exclude.")
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Output JSON file path.")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable verbose logging.")] = False,
    debug: Annotated[bool, typer.Option("--debug", help="Show full traceback on error.")] = False,
) -> None:
    """Capture a full RBAC snapshot (assignments + role definitions) as JSON."""
    _h._debug_callback(debug)
    _h._setup_logging(verbose)

    if output is None:
        _h.console.print("[bold red]Error[/bold red]: --output / -o is required.")
        raise typer.Exit(code=2)

    _h._check_credentials_or_exit()

    # Build model from policy or CLI args
    if policy is not None:
        if subscription or management_group:
            _h.console.print(
                "[bold red]Error[/bold red]: --policy and --subscription/--management-group are mutually exclusive."
            )
            raise typer.Exit(code=2)
        model = _h._load_policy_or_exit(policy)
    else:
        model = _h._build_model_from_args(tenant_id, subscription, management_group)

    model = _h._resolve_and_filter_model(model, exclude_subscription, exclude_management_group)
    _h._validate_scopes_or_exit(model)

    # Scan RBAC
    try:
        scan_result = _h._run_scan(model, fmt="console")
    except Exception as e:
        _h.logger.debug("Traceback scan", exc_info=True)
        _h.console.print(f"[bold red]Scan error[/bold red]: {e}")
        if _h._debug_mode:
            _h.console.print(f"[dim]{traceback.format_exc()}[/dim]")
        else:
            _h.console.print("[dim]Rerun with --debug for full traceback.[/dim]")
        raise typer.Exit(code=2) from None

    scan_result = _h._resolve_names(scan_result, fmt="console")

    # Build and save snapshot
    from az_rbac_watch.scanner.snapshot import build_snapshot, save_snapshot

    subs_meta = [{"id": str(s.id), "name": s.name or ""} for s in model.subscriptions]
    mgs_meta = [{"id": m.id, "name": m.name or ""} for m in model.management_groups]

    snap = build_snapshot(
        scan_result=scan_result,
        tenant_id=str(model.tenant_id),
        subscriptions=subs_meta,
        management_groups=mgs_meta,
    )
    save_snapshot(snap, output)

    # Summary
    n_assignments = len(snap.assignments)
    n_definitions = len(snap.role_definitions)
    output_console = Console(no_color=_h._no_color_mode)
    output_console.print()
    output_console.print(
        f"[bold green]Snapshot saved[/bold green]: {output}\n"
        f"  Tenant     : {snap.metadata.tenant_id}\n"
        f"  Timestamp  : {snap.metadata.timestamp.isoformat()}\n"
        f"  Assignments: {n_assignments}\n"
        f"  Role defs  : {n_definitions}"
    )
    output_console.print()

    raise typer.Exit(code=0)
