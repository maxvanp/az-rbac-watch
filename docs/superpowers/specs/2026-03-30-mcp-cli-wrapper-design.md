# MCP Server as CLI Wrapper — Design Spec

**Date:** 2026-03-30
**Status:** Approved
**Scope:** Refactor MCP server to wrap CLI logic, add `az-rbac-watch mcp` sub-command

## Problem

The current MCP server (`csight`) has its own scanner/analysis logic, duplicating what the CLI already does. This creates two codepaths to maintain and inevitably diverge.

## Solution

Refactor the MCP server so each tool calls the same core functions as the CLI commands. Replace the separate `csight` entry point with an `az-rbac-watch mcp` sub-command.

## Architecture

```
az-rbac-watch mcp serve    <- Typer sub-command, starts stdio MCP server
  |
  mcp/server.py            <- MCP Server (mcp SDK), routes tool calls
  |  security middleware    <- input validation + audit logging (existing)
  |
  +-- tool: rbac_scan       -> scanner.rbac_scanner (shared with cmd_scan)
  +-- tool: rbac_audit      -> compliance.auditor   (shared with cmd_audit)
  +-- tool: rbac_diff       -> diff logic            (shared with cmd_diff)
  +-- tool: rbac_snapshot   -> snapshot logic         (shared with cmd_snapshot)
  +-- tool: rbac_who_can    -> mcp.permissions        (MCP-specific, no CLI equivalent)
  +-- tool: rbac_blast_radius -> mcp.tools.blast_radius (MCP-specific)
  +-- tool: rbac_discover   -> discover logic         (shared with cmd_discover)
```

## Changes

### 1. Refactor core logic out of CLI commands

Each `cmd_*.py` currently does:
- Parse CLI args (Typer)
- Call core logic (scanner, compliance, etc.)
- Format output (Rich)

The core logic calls must be extractable as standalone functions that return data (not print). Where they already are (e.g., `rbac_scanner.scan()`), no change needed. Where logic is embedded in the CLI command, extract it.

### 2. Refactor MCP tools to call core logic

Replace the independent scanner/analysis code in `mcp/tools/*.py` with calls to the same core functions the CLI uses.

**Files to change:**
- `mcp/tools/scan.py` — call `scanner.rbac_scanner` instead of reimplementing scan
- `mcp/tools/discover.py` — call the same logic as `cmd_discover`
- `mcp/tools/blast_radius.py` — keep as MCP-specific (no CLI equivalent yet)
- `mcp/tools/who_can.py` — keep as MCP-specific (no CLI equivalent yet)

**New tools to add:**
- `mcp/tools/audit.py` — wraps `compliance.auditor`
- `mcp/tools/diff.py` — wraps diff logic from `cmd_diff`
- `mcp/tools/snapshot.py` — wraps snapshot logic from `cmd_snapshot`

### 3. Add `az-rbac-watch mcp` sub-command

New file: `cli/cmd_mcp.py`

```python
@app.command()
def mcp():
    """Start the MCP server (stdio transport)."""
    from az_rbac_watch.mcp.server import main
    main()
```

### 4. Remove `csight` entry point

Remove from `pyproject.toml`:
```toml
# Remove this line:
csight = "az_rbac_watch.mcp.server:main"
```

The server is now started via `az-rbac-watch mcp`.

### 5. Keep security middleware

`mcp/security.py` stays as-is:
- Input validation (subscription IDs, paths, actions, scopes, principals)
- Audit logging
- Safe error messages

### 6. Output separation

Core functions return structured data (dicts/dataclasses). Two presentation layers:
- CLI: Rich tables/panels (existing)
- MCP: JSON or formatted text for LLM consumption

## MCP Tools Reference

| Tool | Required Input | Optional Input | Core Function | Description |
|------|---------------|----------------|---------------|-------------|
| `rbac_scan` | — | subscriptionId, policyPath | `scanner.rbac_scanner.scan()` | Scan assignments, risk scoring |
| `rbac_audit` | — | subscriptionId, policyPath | `compliance.auditor` | Compliance audit with findings |
| `rbac_diff` | snapshotPath | subscriptionId | diff logic | Compare current state vs snapshot |
| `rbac_snapshot` | — | subscriptionId, outputPath | snapshot logic | Capture current RBAC state |
| `rbac_who_can` | action, scope | subscriptionId | `mcp.permissions` | Reverse lookup: who can do X on Y |
| `rbac_blast_radius` | principal | subscriptionId | `mcp.tools.blast_radius` | Impact analysis for a principal |
| `rbac_discover` | — | subscriptionId, outputPath | discover logic | Generate starter policy YAML |

## What Does NOT Change

- CLI commands and their interfaces
- Scanner core (`scanner/`)
- Compliance engine (`compliance/`)
- Mapper (`mapper/`)
- Config/settings system
- Existing CLI tests

## Testing

- Existing MCP tests in `tests/mcp/` are updated to reflect the new wiring
- Core logic tests remain unchanged
- Integration test: start MCP server, call each tool, verify output matches CLI output

## Claude Desktop / Claude Code Configuration

After install:
```json
{
  "mcpServers": {
    "az-rbac-watch": {
      "command": "az-rbac-watch",
      "args": ["mcp"]
    }
  }
}
```
