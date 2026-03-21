"""CLI validate command."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

import az_rbac_watch.cli._helpers as _h
from az_rbac_watch.cli import app


@app.command()
def validate(
    policy: Annotated[
        Path,
        typer.Option("--policy", "-p", help="Path to policy model YAML file."),
    ],
) -> None:
    """Validate a policy model YAML file (offline, no Azure credentials needed)."""
    model = _h._load_policy_or_exit(policy)

    n_subs = len(model.subscriptions)
    n_mgs = len(model.management_groups)
    n_rules = len(model.rules)
    n_baseline = sum(1 for r in model.rules if r.type == "baseline")
    n_governance = sum(1 for r in model.rules if r.type == "governance")

    output_console = Console(no_color=_h._no_color_mode)
    output_console.print()
    output_console.print(
        f"[bold green]Policy model valid[/bold green] — version {model.version}\n"
        f"  Scope                : {model.scope}\n"
        f"  Subscriptions        : {n_subs}\n"
        f"  Management groups    : {n_mgs}\n"
        f"  Rules                : {n_rules} ({n_baseline} baseline, {n_governance} governance)"
    )
    if model.exclude_subscriptions:
        output_console.print(f"  Exclude subscriptions: {len(model.exclude_subscriptions)}")
    if model.exclude_management_groups:
        output_console.print(f"  Exclude MGs          : {len(model.exclude_management_groups)}")
    output_console.print()
    raise typer.Exit(code=0)
