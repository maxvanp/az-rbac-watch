# az-rbac-watch Cleanup & Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Merge the compliance framework branch, refactor cli.py, fix lint, update changelog + docs, and release v0.9.0.

**Architecture:** cli.py (1158 lines) gets split into a `cli/` package with one module per command. Shared helpers stay in `cli/_helpers.py`. The typer app is assembled in `cli/__init__.py`. All existing tests must pass unchanged after refactoring — the public API (`from az_rbac_watch.cli import app`) stays identical.

**Tech Stack:** Python 3.12, typer, ruff, mypy, pytest

---

## File Structure

### Refactored CLI package

| File | Responsibility |
|---|---|
| `src/az_rbac_watch/cli/__init__.py` | Typer app assembly, `main()` callback, imports all command modules |
| `src/az_rbac_watch/cli/_helpers.py` | Shared helpers: `_load_policy_or_exit`, `_validate_scopes_or_exit`, `_setup_logging`, `_check_credentials_or_exit`, `_resolve_and_filter_model`, `_run_scan`, `_print_dry_run_plan`, `_resolve_names`, `_output_report`, `_exit_code`, `_detect_policy_file`, `_load_or_build_model`, `_inject_framework_rules`, `_build_model_from_args`, globals (`_debug_mode`, `_quiet_mode`, `_no_color_mode`, `_settings`, `console`, `logger`, `_NOISY_LOGGERS`) |
| `src/az_rbac_watch/cli/cmd_validate.py` | `validate` command (lines 455-485) |
| `src/az_rbac_watch/cli/cmd_scan.py` | `scan` command (lines 491-689) |
| `src/az_rbac_watch/cli/cmd_audit.py` | `audit` command (lines 695-878) |
| `src/az_rbac_watch/cli/cmd_discover.py` | `discover` command (lines 884-993) |
| `src/az_rbac_watch/cli/cmd_snapshot.py` | `snapshot` command (lines 998-1084) |
| `src/az_rbac_watch/cli/cmd_diff.py` | `diff_snapshots` command (lines 1090-1158) |

### Files deleted
| File | Reason |
|---|---|
| `src/az_rbac_watch/cli.py` | Replaced by `cli/` package |

---

### Task 1: Merge feat/framework-compliance into main

**Files:**
- All files from `feat/framework-compliance` branch

- [ ] **Step 1: Merge the branch**

```bash
cd /home/max/projects/az-rbac-watch
git checkout main
git merge feat/framework-compliance -m "feat: merge framework compliance (CIS Azure Benchmark)"
```

- [ ] **Step 2: Run full test suite**

Run: `source .venv/bin/activate && pytest -q`
Expected: 542 passed

- [ ] **Step 3: Fix ruff errors**

```bash
source .venv/bin/activate && ruff check --fix src/ tests/
```

Then manually fix any remaining non-auto-fixable errors.

- [ ] **Step 4: Verify ruff + mypy clean**

```bash
ruff check src/ tests/ && mypy src/
```
Expected: no errors

- [ ] **Step 5: Commit fixes**

```bash
git add -A && git commit -m "fix: resolve ruff lint errors after compliance merge"
```

---

### Task 2: Create cli/ package with helpers

**Files:**
- Create: `src/az_rbac_watch/cli/__init__.py`
- Create: `src/az_rbac_watch/cli/_helpers.py`

- [ ] **Step 1: Run tests before refactoring (baseline)**

Run: `pytest -q`
Expected: 542 passed

- [ ] **Step 2: Create `cli/_helpers.py`**

Extract from `cli.py` lines 1-77 (imports, globals, `_debug_callback`) and lines 120-454 (all helper functions). **Do NOT include lines 79-83 (`app = typer.Typer(...)`) or lines 88-118 (`main()` callback)** — those belong in `__init__.py`.

Key contents:
- All imports (typer, logging, traceback, etc.)
- `__all__` with all helper function names
- Globals: `_debug_mode`, `_quiet_mode`, `_no_color_mode`, `_settings`, `console`, `logger`, `_NOISY_LOGGERS`
- `_debug_callback()`
- `_load_policy_or_exit()`
- `_validate_scopes_or_exit()`
- `_setup_logging()`
- `_check_credentials_or_exit()`
- `_resolve_and_filter_model()`
- `_run_scan()`
- `_print_dry_run_plan()`
- `_resolve_names()`
- `_output_report()`
- `_exit_code()`
- `_detect_policy_file()`
- `_load_or_build_model()`
- `_inject_framework_rules()`
- `_build_model_from_args()`

- [ ] **Step 3: Create `cli/__init__.py`**

```python
"""CLI entry point for az-rbac-watch."""

from __future__ import annotations

import os
from typing import Annotated

import typer
from rich.console import Console

from az_rbac_watch.cli._helpers import (
    _detect_policy_file,
    _no_color_mode,
    _quiet_mode,
    _settings,
    console,
)
from az_rbac_watch.config.settings import load_settings

__all__ = ["app", "_detect_policy_file"]

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
    # Exact same body as current main() — includes global console/settings/quiet/no_color
    # handling AND the zero-args → audit fallback (ctx.invoke(audit))
    ...


# Import command modules LAST to register them on the app (avoids circular imports)
from az_rbac_watch.cli import cmd_audit, cmd_diff, cmd_discover, cmd_scan, cmd_snapshot, cmd_validate  # noqa: E402, F401
```

**Important notes:**
- `_detect_policy_file` is re-exported in `__all__` to preserve `from az_rbac_watch.cli import _detect_policy_file` used in `tests/test_cli.py:12`
- `main()` body must include the `_debug_callback` is NOT called here — debug is per-command (`--debug` flag on each command calls `_debug_callback(debug)` as first line). The `main()` callback only handles `--quiet`, `--no-color`, settings loading, and zero-args fallback to audit.

- [ ] **Step 4: Run tests**

Run: `pytest -q`
Expected: all tests still pass (the `app` is still importable from `az_rbac_watch.cli`)

- [ ] **Step 5: Commit**

```bash
git add src/az_rbac_watch/cli/__init__.py src/az_rbac_watch/cli/_helpers.py
git commit -m "refactor: extract CLI helpers into cli/_helpers.py"
```

---

### Task 3: Extract command modules

**Files:**
- Create: `src/az_rbac_watch/cli/cmd_validate.py`
- Create: `src/az_rbac_watch/cli/cmd_scan.py`
- Create: `src/az_rbac_watch/cli/cmd_audit.py`
- Create: `src/az_rbac_watch/cli/cmd_discover.py`
- Create: `src/az_rbac_watch/cli/cmd_snapshot.py`
- Create: `src/az_rbac_watch/cli/cmd_diff.py`
- Delete: `src/az_rbac_watch/cli.py`

- [ ] **Step 1: Create each command module**

Each command module follows this pattern:

```python
"""<Command name> command."""

from __future__ import annotations

# ... only the imports this command needs ...

from az_rbac_watch.cli._helpers import (
    # ... only the helpers this command uses ...
)
from az_rbac_watch.cli import app


@app.command()
def <command_name>(...) -> None:
    # ... exact same body ...
```

Extract each command function from `cli.py` into its own module:
- `cmd_validate.py` ← `validate()` (lines 455-485)
- `cmd_scan.py` ← `scan()` (lines 491-689)
- `cmd_audit.py` ← `audit()` (lines 695-878)
- `cmd_discover.py` ← `discover()` (lines 884-993)
- `cmd_snapshot.py` ← `snapshot()` (lines 998-1084)
- `cmd_diff.py` ← `diff_snapshots()` (lines 1090-1158)

**Critical:** Each module must import `app` from `az_rbac_watch.cli` and use `@app.command()` decorator. The import order in `cli/__init__.py` registers all commands on the app.

- [ ] **Step 2: Delete old cli.py**

```bash
rm src/az_rbac_watch/cli.py
```

- [ ] **Step 3: Run full test suite**

Run: `pytest -q`
Expected: 542 passed

- [ ] **Step 4: Run ruff + mypy**

```bash
ruff check src/ tests/ && mypy src/
```
Expected: clean

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor: split cli.py into cli/ package with one module per command"
```

---

### Task 4: Update CHANGELOG

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Reconstruct missing changelog entries**

Use `git log --oneline v0.2.0..main` and tag history to rebuild entries for:
- v0.3.0: Orphaned assignment detection (`--orphans-only`)
- v0.4.0: Change tracking — snapshot + diff commands
- v0.4.1/v0.4.2: Patch releases (check tags)
- v0.5.0: GitHub Action
- v0.6.0: Enhanced HTML reports
- v0.7.0: HTML report for diffs
- v0.8.0: Azure Portal links
- v0.9.0 (unreleased): Framework compliance mapping (CIS), CLI refactoring

- [ ] **Step 2: Write all entries in Keep a Changelog format**

Add entries in reverse chronological order above the existing `[0.2.0]` section.

- [ ] **Step 3: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs: update CHANGELOG with v0.3.0 through v0.9.0"
```

---

### Task 5: Update README and docs

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add framework compliance section to README**

Add after the "Audit guardrails" section:

```markdown
### 4b. Framework compliance (CIS Benchmark)

\`\`\`bash
# Audit with CIS Azure Foundations Benchmark mapping
az-rbac-watch audit -p my_policy.yaml --framework CIS -o compliance.html

# Console summary only
az-rbac-watch audit -p my_policy.yaml --framework CIS
\`\`\`
```

Update the "Two axes, one tool" table to include framework compliance.

- [ ] **Step 2: Add --framework to CLI reference**

Add `--framework` to the `audit` command options table.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: add framework compliance to README"
```

---

### Task 6: Final verification and tag

- [ ] **Step 1: Full test suite**

Run: `pytest --cov=az_rbac_watch --cov-fail-under=80 -q`
Expected: all pass, coverage >= 80%

- [ ] **Step 2: Full lint**

```bash
ruff check src/ tests/ && ruff format --check src/ tests/ && mypy src/
```
Expected: clean

- [ ] **Step 3: Verify package builds**

```bash
source .venv/bin/activate && uv pip install build && python -m build
```
Expected: `.whl` and `.tar.gz` in `dist/`

- [ ] **Step 4: Tag release**

```bash
git tag v0.9.0
```

- [ ] **Step 5: Push**

Ask user before pushing:
```bash
git push origin main --tags
```
