# MCP CLI Wrapper Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor the MCP server to eliminate code duplication, add `az-rbac-watch mcp` sub-command, and remove the separate `csight` entry point.

**Architecture:** Extract the duplicated `_scan_subscription()` helper into a shared module. Refactor all 4 MCP tools to use it. Add a Typer sub-command `mcp` that starts the stdio server. Remove the `csight` script entry point.

**Tech Stack:** Python 3.12, mcp SDK, Typer, pytest, pytest-asyncio

---

### Task 1: Extract shared MCP scanning helper

The function `_scan_subscription()` is copy-pasted identically in `mcp/tools/scan.py`, `mcp/tools/who_can.py`, `mcp/tools/blast_radius.py`, and `mcp/tools/discover.py`. Same for `_collect_all_definitions()` (in `who_can.py` and `blast_radius.py`).

**Files:**
- Create: `src/az_rbac_watch/mcp/azure_scan.py`
- Test: `tests/mcp/test_azure_scan.py`

- [ ] **Step 1: Write failing test for shared scan helper**

```python
# tests/mcp/test_azure_scan.py
"""Tests for the shared MCP scanning helper."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from az_rbac_watch.scanner.rbac_scanner import (
    RbacScanResult,
    ScannedRoleAssignment,
    ScannedRoleDefinition,
    SubscriptionScanResult,
)


@pytest.fixture
def mock_scan_result():
    assignment = ScannedRoleAssignment(
        id="/sub/123/assignment/1",
        principal_id="p-1",
        principal_type="User",
        role_definition_id="role-def-1",
        role_name="Reader",
        scope="/subscriptions/sub-123",
    )
    definition = ScannedRoleDefinition(
        id="role-def-1",
        role_name="Reader",
        role_type="BuiltInRole",
        permissions=[{"actions": ["*/read"], "notActions": []}],
    )
    sub_result = SubscriptionScanResult(
        subscription_id="sub-123",
        subscription_name="Test Sub",
        assignments=[assignment],
        definitions=[definition],
    )
    return RbacScanResult(subscription_results=[sub_result])


@pytest.mark.asyncio
async def test_scan_subscription_specific(mock_scan_result):
    from az_rbac_watch.mcp.azure_scan import scan_subscription_async

    with (
        patch(
            "az_rbac_watch.mcp.azure_scan.get_authorization_client"
        ) as mock_client,
        patch(
            "az_rbac_watch.mcp.azure_scan.scan_subscription"
        ) as mock_scan,
        patch(
            "az_rbac_watch.mcp.azure_scan.resolve_display_names",
            side_effect=lambda r: r,
        ),
    ):
        mock_scan.return_value = mock_scan_result.subscription_results[0]
        result = await scan_subscription_async("sub-123")

    assert len(result.subscription_results) == 1
    assert result.subscription_results[0].subscription_id == "sub-123"
    mock_client.assert_called_once_with("sub-123")


@pytest.mark.asyncio
async def test_scan_subscription_all(mock_scan_result):
    from az_rbac_watch.mcp.azure_scan import scan_subscription_async

    with (
        patch(
            "az_rbac_watch.mcp.azure_scan.list_accessible_subscriptions",
            return_value=[("sub-123", "Test Sub", "tenant-1")],
        ),
        patch(
            "az_rbac_watch.mcp.azure_scan.get_authorization_client"
        ) as mock_client,
        patch(
            "az_rbac_watch.mcp.azure_scan.scan_subscription"
        ) as mock_scan,
        patch(
            "az_rbac_watch.mcp.azure_scan.resolve_display_names",
            side_effect=lambda r: r,
        ),
    ):
        mock_scan.return_value = mock_scan_result.subscription_results[0]
        result = await scan_subscription_async(None)

    assert len(result.subscription_results) == 1


def test_collect_all_definitions(mock_scan_result):
    from az_rbac_watch.mcp.azure_scan import collect_all_definitions

    definitions = collect_all_definitions(mock_scan_result)
    assert len(definitions) == 1
    assert definitions[0].role_name == "Reader"


def test_collect_all_definitions_deduplicates():
    from az_rbac_watch.mcp.azure_scan import collect_all_definitions

    defn = ScannedRoleDefinition(
        id="role-def-1",
        role_name="Reader",
        role_type="BuiltInRole",
        permissions=[],
    )
    result = RbacScanResult(
        subscription_results=[
            SubscriptionScanResult(
                subscription_id="sub-1",
                subscription_name="Sub 1",
                assignments=[],
                definitions=[defn],
            ),
            SubscriptionScanResult(
                subscription_id="sub-2",
                subscription_name="Sub 2",
                assignments=[],
                definitions=[defn],
            ),
        ]
    )
    definitions = collect_all_definitions(result)
    assert len(definitions) == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/max/projects/az-rbac-watch && python -m pytest tests/mcp/test_azure_scan.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'az_rbac_watch.mcp.azure_scan'`

- [ ] **Step 3: Implement shared scanning module**

```python
# src/az_rbac_watch/mcp/azure_scan.py
"""Shared Azure RBAC scanning helpers for MCP tools.

Centralizes the async scan wrapper and role definition collection
that were previously duplicated across every MCP tool module.
"""

from __future__ import annotations

import asyncio

from az_rbac_watch.auth.azure_clients import (
    get_authorization_client,
    list_accessible_subscriptions,
)
from az_rbac_watch.scanner.rbac_scanner import (
    RbacScanResult,
    ScannedRoleDefinition,
    resolve_display_names,
    scan_subscription,
)

__all__ = ["collect_all_definitions", "scan_subscription_async"]


async def scan_subscription_async(
    subscription_id: str | None,
) -> RbacScanResult:
    """Scan Azure RBAC for one or all subscriptions.

    Wraps the synchronous scanner in asyncio.to_thread.
    """

    def _sync_scan() -> RbacScanResult:
        if subscription_id:
            client = get_authorization_client(subscription_id)
            sub_result = scan_subscription(client, subscription_id)
            result = RbacScanResult(subscription_results=[sub_result])
        else:
            subs = list_accessible_subscriptions()
            sub_results = []
            for sid, name, _tenant in subs:
                client = get_authorization_client(sid)
                sub_results.append(scan_subscription(client, sid, name))
            result = RbacScanResult(subscription_results=sub_results)
        return resolve_display_names(result)

    return await asyncio.to_thread(_sync_scan)


def collect_all_definitions(
    scan_result: RbacScanResult,
) -> list[ScannedRoleDefinition]:
    """Collect all unique role definitions from all subscription/MG results."""
    definitions: list[ScannedRoleDefinition] = []
    seen: set[str] = set()
    for sub in scan_result.subscription_results:
        for d in sub.definitions:
            if d.id not in seen:
                seen.add(d.id)
                definitions.append(d)
    for mg in scan_result.management_group_results:
        for d in mg.definitions:
            if d.id not in seen:
                seen.add(d.id)
                definitions.append(d)
    return definitions
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/max/projects/az-rbac-watch && python -m pytest tests/mcp/test_azure_scan.py -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/az_rbac_watch/mcp/azure_scan.py tests/mcp/test_azure_scan.py
git commit -m "refactor: extract shared MCP scanning helper into azure_scan module"
```

---

### Task 2: Refactor MCP tools to use shared scanning helper

Remove the duplicated `_scan_subscription()` and `_collect_all_definitions()` from each tool module and import from the new shared module.

**Files:**
- Modify: `src/az_rbac_watch/mcp/tools/scan.py` — remove `_scan_subscription`, import from `azure_scan`
- Modify: `src/az_rbac_watch/mcp/tools/who_can.py` — remove `_scan_subscription` and `_collect_all_definitions`, import from `azure_scan`
- Modify: `src/az_rbac_watch/mcp/tools/blast_radius.py` — remove `_scan_subscription` and `_collect_all_definitions`, import from `azure_scan`
- Modify: `src/az_rbac_watch/mcp/tools/discover.py` — remove `_scan_subscription`, import from `azure_scan`
- Test: `tests/mcp/test_scan.py`, `tests/mcp/test_who_can.py`, `tests/mcp/test_blast_radius.py`, `tests/mcp/test_discover.py`

- [ ] **Step 1: Update scan.py**

In `src/az_rbac_watch/mcp/tools/scan.py`:
- Remove the entire `_scan_subscription()` function (lines 74-100)
- Remove imports it used: `from az_rbac_watch.scanner.rbac_scanner import PrincipalType, RbacScanResult, ScannedRoleAssignment` — keep `PrincipalType` and `ScannedRoleAssignment`, remove `RbacScanResult`
- Add import: `from az_rbac_watch.mcp.azure_scan import scan_subscription_async`
- In `handle_scan()`, change `await _scan_subscription(subscription_id)` to `await scan_subscription_async(subscription_id)`

- [ ] **Step 2: Update who_can.py**

In `src/az_rbac_watch/mcp/tools/who_can.py`:
- Remove `_scan_subscription()` function (lines 75-99)
- Remove `_collect_all_definitions()` function (lines 111-125)
- Remove `_build_role_def_id_set()` function (lines 128-130) — inline it or keep, it's only used once
- Add imports: `from az_rbac_watch.mcp.azure_scan import collect_all_definitions, scan_subscription_async`
- In `handle_who_can()`:
  - Change `await _scan_subscription(subscription_id)` to `await scan_subscription_async(subscription_id)`
  - Change `_collect_all_definitions(scan_result)` to `collect_all_definitions(scan_result)`

- [ ] **Step 3: Update blast_radius.py**

In `src/az_rbac_watch/mcp/tools/blast_radius.py`:
- Remove `_scan_subscription()` function (lines 59-83)
- Remove `_collect_all_definitions()` function (lines 86-100)
- Add imports: `from az_rbac_watch.mcp.azure_scan import collect_all_definitions, scan_subscription_async`
- In `handle_blast_radius()`:
  - Change `await _scan_subscription(subscription_id)` to `await scan_subscription_async(subscription_id)`
  - Change `_collect_all_definitions(scan_result)` to `collect_all_definitions(scan_result)`

- [ ] **Step 4: Update discover.py**

In `src/az_rbac_watch/mcp/tools/discover.py`:
- Remove `_scan_subscription()` function (lines 69-95)
- Add import: `from az_rbac_watch.mcp.azure_scan import scan_subscription_async`
- In `handle_discover()`, change `await _scan_subscription(subscription_id)` to `await scan_subscription_async(subscription_id)`

- [ ] **Step 5: Update test mocks**

The existing tests mock `_scan_subscription` at the module level (e.g., `az_rbac_watch.mcp.tools.scan._scan_subscription`). Update mock paths to `az_rbac_watch.mcp.azure_scan.scan_subscription_async` in:
- `tests/mcp/test_scan.py`
- `tests/mcp/test_who_can.py`
- `tests/mcp/test_blast_radius.py`
- `tests/mcp/test_discover.py`

Also update any mocks of `_collect_all_definitions` to point to `az_rbac_watch.mcp.azure_scan.collect_all_definitions`.

- [ ] **Step 6: Run all MCP tests**

Run: `cd /home/max/projects/az-rbac-watch && python -m pytest tests/mcp/ -v`
Expected: All tests PASS

- [ ] **Step 7: Commit**

```bash
git add src/az_rbac_watch/mcp/tools/ tests/mcp/
git commit -m "refactor: deduplicate MCP tools — use shared azure_scan module"
```

---

### Task 3: Add `az-rbac-watch mcp` sub-command

**Files:**
- Create: `src/az_rbac_watch/cli/cmd_mcp.py`
- Modify: `src/az_rbac_watch/cli/__init__.py` — register the new command module
- Test: `tests/test_cmd_mcp.py`

- [ ] **Step 1: Write failing test**

```python
# tests/test_cmd_mcp.py
"""Tests for the mcp sub-command."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

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
        result = runner.invoke(app, ["mcp"])
    mock_main.assert_called_once()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/max/projects/az-rbac-watch && python -m pytest tests/test_cmd_mcp.py -v`
Expected: FAIL — `mcp` is not a recognized command

- [ ] **Step 3: Implement the mcp sub-command**

```python
# src/az_rbac_watch/cli/cmd_mcp.py
"""CLI mcp sub-command — start the MCP server."""

from __future__ import annotations

from az_rbac_watch.cli import app


@app.command()
def mcp() -> None:
    """Start the MCP server (stdio transport for Claude Desktop / Claude Code)."""
    from az_rbac_watch.mcp.server import main

    main()
```

- [ ] **Step 4: Register the command module in cli/__init__.py**

In `src/az_rbac_watch/cli/__init__.py`, add `cmd_mcp` to the import block at the bottom:

```python
from az_rbac_watch.cli import (  # noqa: E402, F401
    cmd_audit,
    cmd_diff,
    cmd_discover,
    cmd_mcp,
    cmd_scan,
    cmd_snapshot,
    cmd_validate,
)
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd /home/max/projects/az-rbac-watch && python -m pytest tests/test_cmd_mcp.py -v`
Expected: All 2 tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/az_rbac_watch/cli/cmd_mcp.py src/az_rbac_watch/cli/__init__.py tests/test_cmd_mcp.py
git commit -m "feat: add 'az-rbac-watch mcp' sub-command to start MCP server"
```

---

### Task 4: Remove `csight` entry point

**Files:**
- Modify: `pyproject.toml` — remove `csight` script entry

- [ ] **Step 1: Remove csight from pyproject.toml**

In `pyproject.toml`, change the `[project.scripts]` section from:

```toml
[project.scripts]
az-rbac-watch = "az_rbac_watch.cli:app"
csight = "az_rbac_watch.mcp.server:main"
```

to:

```toml
[project.scripts]
az-rbac-watch = "az_rbac_watch.cli:app"
```

- [ ] **Step 2: Reinstall the package**

Run: `cd /home/max/projects/az-rbac-watch && uv pip install -e ".[dev-mcp]"`
Expected: installs successfully, `csight` command no longer available

- [ ] **Step 3: Verify `az-rbac-watch mcp --help` works**

Run: `az-rbac-watch mcp --help`
Expected: shows help text for the mcp sub-command

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml
git commit -m "chore: remove csight entry point — use 'az-rbac-watch mcp' instead"
```

---

### Task 5: Run full test suite and lint

**Files:** None (validation only)

- [ ] **Step 1: Run all tests**

Run: `cd /home/max/projects/az-rbac-watch && python -m pytest tests/ -v`
Expected: All tests PASS

- [ ] **Step 2: Run ruff lint**

Run: `cd /home/max/projects/az-rbac-watch && ruff check src/ tests/`
Expected: No errors

- [ ] **Step 3: Run ruff format check**

Run: `cd /home/max/projects/az-rbac-watch && ruff format --check src/ tests/`
Expected: No formatting issues

- [ ] **Step 4: Fix any issues found and commit**

If any lint/format issues, fix them and commit:
```bash
ruff format src/ tests/
git add -u
git commit -m "style: fix lint/format issues after MCP refactor"
```

---

### Task 6: Update documentation

**Files:**
- Modify: `README.md` — update MCP server usage section to reference `az-rbac-watch mcp` instead of `csight`

- [ ] **Step 1: Update README.md**

Find all references to `csight` command and replace with `az-rbac-watch mcp`. Update the Claude Desktop / Claude Code configuration example:

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

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: update MCP server usage — az-rbac-watch mcp replaces csight"
```
