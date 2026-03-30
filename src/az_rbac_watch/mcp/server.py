"""CloudSight MCP server — natural language interface for Azure RBAC auditing.

Every tool call passes through security validation and audit logging.
"""

from __future__ import annotations

import asyncio
import time

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from az_rbac_watch.mcp.security import (
    audit_log,
    safe_error,
    validate_action,
    validate_path,
    validate_principal,
    validate_scope,
    validate_subscription_id,
)
from az_rbac_watch.mcp.tools.blast_radius import BLAST_RADIUS_TOOL_DEF, handle_blast_radius
from az_rbac_watch.mcp.tools.discover import DISCOVER_TOOL_DEF, handle_discover
from az_rbac_watch.mcp.tools.scan import SCAN_TOOL_DEF, handle_scan
from az_rbac_watch.mcp.tools.who_can import WHO_CAN_TOOL_DEF, handle_who_can

TOOLS = [SCAN_TOOL_DEF, WHO_CAN_TOOL_DEF, BLAST_RADIUS_TOOL_DEF, DISCOVER_TOOL_DEF]

app = Server("cloudsight-rbac")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(name=t["name"], description=t["description"], inputSchema=t["inputSchema"])
        for t in TOOLS
    ]


def _validate_args(name: str, arguments: dict) -> dict:
    """Validate and sanitize all tool arguments before execution."""
    validated = dict(arguments)

    if sub_id := validated.get("subscriptionId"):
        validated["subscriptionId"] = validate_subscription_id(sub_id)

    if policy_path := validated.get("policyPath"):
        validated["policyPath"] = str(validate_path(policy_path, must_exist=True))
    if output_path := validated.get("outputPath"):
        validated["outputPath"] = str(validate_path(output_path))
    if snapshot_path := validated.get("snapshotPath"):
        validated["snapshotPath"] = str(validate_path(snapshot_path, must_exist=True))

    if name == "rbac_who_can":
        validated["action"] = validate_action(validated["action"])
        validated["scope"] = validate_scope(validated["scope"])
    elif name == "rbac_blast_radius":
        validated["principal"] = validate_principal(validated["principal"])

    return validated


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    start = time.monotonic()
    status = "success"

    try:
        args = _validate_args(name, arguments)

        match name:
            case "rbac_scan":
                result = await handle_scan(
                    subscription_id=args.get("subscriptionId"),
                    policy_path=args.get("policyPath"),
                )
            case "rbac_who_can":
                result = await handle_who_can(
                    action=args["action"],
                    scope=args["scope"],
                    subscription_id=args.get("subscriptionId"),
                )
            case "rbac_blast_radius":
                result = await handle_blast_radius(
                    principal=args["principal"],
                    subscription_id=args.get("subscriptionId"),
                )
            case "rbac_discover":
                result = await handle_discover(
                    subscription_id=args.get("subscriptionId"),
                    output_path=args.get("outputPath", "./cloudsight.yaml"),
                )
            case _:
                status = "unknown_tool"
                return [TextContent(type="text", text=f"Unknown tool: {name}")]

        return [TextContent(type="text", text=result)]

    except ValueError as e:
        status = "validation_error"
        return [TextContent(type="text", text=f"Validation error: {e}")]

    except Exception as e:
        status = "error"
        return [TextContent(type="text", text=f"Error: {safe_error(e)}")]

    finally:
        duration_ms = int((time.monotonic() - start) * 1000)
        audit_log(tool=name, args=arguments, status=status, duration_ms=duration_ms)


def main() -> None:
    """Entry point for 'csight' command. Starts the MCP server on stdio."""
    async def _run() -> None:
        async with stdio_server() as (read_stream, write_stream):
            await app.run(read_stream, write_stream, app.create_initialization_options())

    asyncio.run(_run())


if __name__ == "__main__":
    main()
