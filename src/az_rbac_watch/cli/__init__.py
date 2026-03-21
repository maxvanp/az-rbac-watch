"""CLI package for Azure Permissions Watch."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console

from az_rbac_watch.cli._helpers import _detect_policy_file

__all__ = ["_detect_policy_file", "app"]

app = typer.Typer(
    name="az-rbac-watch",
    invoke_without_command=True,
    epilog="Quick start: az-rbac-watch (scans all accessible subscriptions with default rules)",
)


@app.callback()
def main(
    ctx: typer.Context,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress all output except findings and exit code."),
    ] = False,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable colored output."),
    ] = False,
) -> None:
    """Azure RBAC as Code — drift detection and guardrails."""
    import os

    import az_rbac_watch.cli._helpers as _h

    # Load settings (file + env vars) and use as fallback
    from az_rbac_watch.config.settings import load_settings

    _h._settings = load_settings()

    _h._quiet_mode = quiet or _h._settings.quiet
    _h._no_color_mode = no_color or _h._settings.no_color or os.environ.get("NO_COLOR", "") != ""
    if _h._quiet_mode:
        _h.console = Console(stderr=True, quiet=True)
    elif _h._no_color_mode:
        _h.console = Console(stderr=True, no_color=True)

    # Zero-args → run audit by default
    if ctx.invoked_subcommand is None:
        from az_rbac_watch.cli.cmd_audit import audit

        ctx.invoke(audit)


# Command modules imported LAST to register on app (avoids circular imports)
from az_rbac_watch.cli import (  # noqa: E402, F401
    cmd_audit,
    cmd_diff,
    cmd_discover,
    cmd_scan,
    cmd_snapshot,
    cmd_validate,
)
