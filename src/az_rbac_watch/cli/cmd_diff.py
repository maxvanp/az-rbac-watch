"""CLI diff command."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

import az_rbac_watch.cli._helpers as _h
from az_rbac_watch.cli import app


@app.command(name="diff")
def diff_snapshots(
    old_snapshot: Annotated[
        Path,
        typer.Argument(help="Path to the older snapshot JSON file."),
    ],
    new_snapshot: Annotated[
        Path,
        typer.Argument(help="Path to the newer snapshot JSON file."),
    ],
    fmt: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: console, json, html."),
    ] = "console",
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file path."),
    ] = None,
) -> None:
    """Compare two snapshots and show RBAC changes."""
    if fmt not in ("console", "json", "html"):
        _h.console.print(f"[bold red]Error[/bold red]: Unknown format '{fmt}'. Use 'console', 'json', or 'html'.")
        raise typer.Exit(code=2)

    from az_rbac_watch.analyzers.diff import compute_diff
    from az_rbac_watch.reporters.diff_report import format_diff_console, format_diff_json
    from az_rbac_watch.scanner.snapshot import load_snapshot

    try:
        old = load_snapshot(old_snapshot)
        new = load_snapshot(new_snapshot)
    except FileNotFoundError as e:
        _h.console.print(f"[bold red]Error[/bold red]: {e}")
        raise typer.Exit(code=2) from None
    except Exception as e:
        _h.console.print(f"[bold red]Error[/bold red]: Failed to load snapshot: {e}")
        raise typer.Exit(code=2) from None

    result = compute_diff(old.assignments, new.assignments)

    # Auto-detect HTML from output extension
    effective_fmt = fmt
    if output is not None and fmt == "console" and output.suffix.lower() == ".html":
        effective_fmt = "html"

    if effective_fmt == "html":
        if output is None:
            _h.console.print("[bold red]Error[/bold red]: HTML format requires --output.")
            raise typer.Exit(code=2)
        from az_rbac_watch.reporters.diff_report import format_diff_html

        format_diff_html(result, old, new, output)
        _h.console.print(f"Diff report written to: [bold]{output}[/bold]")
    elif effective_fmt == "json":
        text = format_diff_json(result)
        if output is not None:
            output.write_text(text, encoding="utf-8")
            _h.console.print(f"Diff report written to: [bold]{output}[/bold]")
        else:
            print(text)  # noqa: T201 — raw stdout for test capture and clean JSON
    else:
        text = format_diff_console(result)
        if output is not None:
            output.write_text(text, encoding="utf-8")
            _h.console.print(f"Diff report written to: [bold]{output}[/bold]")
        else:
            print(text)  # noqa: T201 — raw stdout for test capture and clean JSON

    raise typer.Exit(code=1 if result.has_changes else 0)
