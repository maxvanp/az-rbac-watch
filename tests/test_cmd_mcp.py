"""Tests for the mcp sub-command."""

from __future__ import annotations

from unittest.mock import patch

from typer.testing import CliRunner

from az_rbac_watch.cli import app

runner = CliRunner()


def test_mcp_command_exists():
    """The mcp sub-command should be registered."""
    result = runner.invoke(app, ["mcp", "--help"])
    assert result.exit_code == 0
    assert "MCP" in result.output or "mcp" in result.output.lower()


def test_mcp_invokes_server():
    """The mcp sub-command should call the MCP server main()."""
    with patch("az_rbac_watch.mcp.server.main") as mock_main:
        runner.invoke(app, ["mcp"])
    mock_main.assert_called_once()
