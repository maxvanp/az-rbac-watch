"""CLI mcp sub-command — start the MCP server."""

from __future__ import annotations

from az_rbac_watch.cli import app


@app.command()
def mcp() -> None:
    """Start the MCP server (stdio transport for Claude Desktop / Claude Code)."""
    from az_rbac_watch.mcp.server import main

    main()
