"""Integration tests for the MCP server entry point."""

from __future__ import annotations

import pytest

from az_rbac_watch.mcp.server import _validate_args, call_tool, list_tools


# ---------------------------------------------------------------------------
# list_tools
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_tools_returns_four_tools():
    tools = await list_tools()
    assert len(tools) == 4
    names = {t.name for t in tools}
    assert names == {"rbac_scan", "rbac_who_can", "rbac_blast_radius", "rbac_discover"}


# ---------------------------------------------------------------------------
# _validate_args
# ---------------------------------------------------------------------------


def test_validate_args_rejects_bad_subscription():
    with pytest.raises(ValueError, match="Invalid subscription_id"):
        _validate_args("rbac_scan", {"subscriptionId": "bad"})


def test_validate_args_passes_valid_subscription():
    result = _validate_args(
        "rbac_scan",
        {"subscriptionId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
    )
    assert result["subscriptionId"] == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def test_validate_args_validates_action_and_scope():
    result = _validate_args(
        "rbac_who_can",
        {
            "action": "Microsoft.Compute/virtualMachines/delete",
            "scope": "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        },
    )
    assert result["action"] == "Microsoft.Compute/virtualMachines/delete"
    assert result["scope"] == "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def test_validate_args_rejects_bad_action():
    with pytest.raises(ValueError, match="Invalid action"):
        _validate_args("rbac_who_can", {"action": "bad!", "scope": "/subscriptions/x"})


def test_validate_args_rejects_bad_scope():
    with pytest.raises(ValueError, match="Invalid scope"):
        _validate_args(
            "rbac_who_can",
            {"action": "Microsoft.Compute/virtualMachines/delete", "scope": "no-leading-slash"},
        )


# ---------------------------------------------------------------------------
# call_tool — unknown tool
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_call_tool_unknown_returns_error():
    result = await call_tool("nonexistent_tool", {})
    assert len(result) == 1
    assert "Unknown tool: nonexistent_tool" in result[0].text
