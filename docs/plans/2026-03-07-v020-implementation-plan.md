# v0.2.0 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Ship azure-permissions-watch v0.2.0 on PyPI with S-tier onboarding, English UI, and mkdocs site.

**Architecture:** Three phases executed sequentially. Phase 1 (product quality) is the largest — it changes CLI behavior, translates all UI strings, adds flags and features. Phase 2 (distribution infra) wires up setuptools-scm and GitHub Actions. Phase 3 (docs) builds a mkdocs-material site.

**Tech Stack:** Python 3.12, Typer, Rich, Pydantic v2, hatchling, setuptools-scm, mkdocs-material, GitHub Actions, PyPI (OIDC trusted publisher).

**Design doc:** `docs/plans/2026-03-07-v020-distribution-roadmap.md`

---

## Task 1: Pre-commit config + coverage setup

**Files:**
- Create: `.pre-commit-config.yaml`
- Modify: `pyproject.toml` (add pytest-cov to dev deps, add coverage config)
- Create: `.coveragerc`
- Modify: `README.md` (add coverage badge placeholder)

**Step 1: Create `.pre-commit-config.yaml`**

```yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.15.5
    hooks:
      - id: ruff-check
        args: [--fix]
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.15.0
    hooks:
      - id: mypy
        additional_dependencies:
          - pydantic
          - types-PyYAML
        args: [--strict, src/]
        pass_filenames: false
```

**Step 2: Add pytest-cov to dev deps in `pyproject.toml`**

In `[project.optional-dependencies]` dev list, add `"pytest-cov"`.

**Step 3: Create `.coveragerc`**

```ini
[run]
source = src/az_perm_watch
branch = true

[report]
show_missing = true
skip_empty = true
exclude_lines =
    pragma: no cover
    if TYPE_CHECKING:
    raise NotImplementedError
```

**Step 4: Run tests with coverage to verify setup**

```bash
.venv/bin/python -m pytest --cov --cov-report=term-missing
```

**Step 5: Commit**

```bash
git add .pre-commit-config.yaml .coveragerc pyproject.toml
git commit -m "chore: add pre-commit config and pytest-cov setup"
```

---

## Task 2: i18n — Translate policy_model.py validation messages

**Files:**
- Modify: `src/az_perm_watch/config/policy_model.py` (lines 53-58, 92-114, 127-140)
- Modify: `tests/test_policy_model.py` (update assertion strings)

**Step 1: Translate all French validation messages to English**

| Location | Current (French) | New (English) |
|----------|-------------------|---------------|
| policy_model.py:56 | "L'identifiant du management group ne peut pas être vide" | "Management group ID must not be empty" |
| policy_model.py:97 | "Le nom de la règle ne peut pas être vide" | "Rule name must not be empty" |
| policy_model.py:105 | "Type de règle invalide : '{v}'. Valeurs possibles : {VALID_RULE_TYPES}" | "Invalid rule type: '{v}'. Valid values: {VALID_RULE_TYPES}" |
| policy_model.py:113 | "Sévérité invalide : '{v}'. Valeurs possibles : {VALID_SEVERITIES}" | "Invalid severity: '{v}'. Valid values: {VALID_SEVERITIES}" |
| policy_model.py:131 | "Version '{v}' non supportée. Versions supportées : {SUPPORTED_VERSIONS}" | "Unsupported version: '{v}'. Supported versions: {SUPPORTED_VERSIONS}" |
| policy_model.py:139 | "Mode scope invalide : '{v}'. Valeurs possibles : {VALID_SCOPE_MODES}" | "Invalid scope mode: '{v}'. Valid values: {VALID_SCOPE_MODES}" |

**Step 2: Update tests that assert on these French strings**

Search `tests/test_policy_model.py` for the old French strings and update assertions.

**Step 3: Run tests**

```bash
.venv/bin/python -m pytest tests/test_policy_model.py -v
```

**Step 4: Commit**

```bash
git commit -am "feat(i18n): translate policy model validation messages to English"
```

---

## Task 3: i18n — Translate console_report.py

**Files:**
- Modify: `src/az_perm_watch/reporters/console_report.py` (lines 28-212)
- Modify: `tests/test_console_report.py` (update assertion strings)

**Step 1: Translate `_print_report()` internal strings (lines 42-136)**

| Current | New |
|---------|-----|
| "Tenant" | "Tenant" (already English) |
| "Policy version" | "Policy version" (already English) |
| "Scan" | "Scan" (already English) |
| "Avertissements" (Panel title) | "Warnings" |
| "Résumé" (Panel title) | "Summary" |
| "Assignations scannées" | "Assignments scanned" |
| "Écarts détectés" | "Findings" |
| "Sévérité" (table column) | "Severity" |
| "Règle" (table column) | "Rule" |
| "Principal" (table column) | "Principal" (already English) |
| "Rôle" (table column) | "Role" |
| "Scope" (table column) | "Scope" (already English) |
| "Erreurs de scan" (Panel title) | "Scan errors" |

**Step 2: Translate report-specific vocabulary**

| Function | Field | Current | New |
|----------|-------|---------|-----|
| print_drift_report | title | "Azure Permissions Watch — Drift Report" | Keep (already English) |
| print_drift_report | drift_label | "Assignations non déclarées" | "Undeclared assignments" |
| print_drift_report | ok_message | "Aucun drift — l'état réel correspond au desired state." | "No drift — actual state matches desired state." |
| print_drift_report | ko_message_template | "{n} assignation(s) non déclarée(s) détectée(s)" | "{n} undeclared assignment(s) detected" |
| print_audit_report | violation_label | "Violations de guardrails" | "Guardrail violations" |
| print_audit_report | ok_message | "Aucune violation — tous les guardrails sont respectés." | "No violations — all guardrails passed." |
| print_audit_report | ko_message_template | "{n} violation(s) de guardrails détectée(s)" | "{n} guardrail violation(s) detected" |
| print_compliance_report | drift_label | "Assignations non déclarées" | "Undeclared assignments" |
| print_compliance_report | violation_label | "Violations de guardrails" | "Guardrail violations" |
| print_compliance_report | ok_message | "Conforme — aucun écart détecté." | "Compliant — no findings." |
| print_compliance_report | ko_message_template | "{n} écart(s) détecté(s)" | "{n} finding(s) detected" |

**Step 3: Translate print_discover_summary()**

Translate all French user-facing strings in lines 187-212.

**Step 4: Update test assertions in `tests/test_console_report.py`**

**Step 5: Run tests**

```bash
.venv/bin/python -m pytest tests/test_console_report.py -v
```

**Step 6: Commit**

```bash
git commit -am "feat(i18n): translate console report to English"
```

---

## Task 4: i18n — Translate html_report.py

**Files:**
- Modify: `src/az_perm_watch/reporters/html_report.py` (lines 55-77 _MODE_LABELS, lines 138-422 _HTML_TEMPLATE)
- Modify: `tests/test_html_report.py` (update assertion strings)

**Step 1: Translate `_MODE_LABELS` dict (lines 55-77)**

Same vocabulary as console_report (see Task 3).

**Step 2: Translate French strings in `_HTML_TEMPLATE` (lines 138-422)**

| Current | New |
|---------|-----|
| "Avertissements" | "Warnings" |
| "Assignations scannées" | "Assignments scanned" |
| "Total écarts" | "Total findings" |
| "Répartition par scope" | "Findings by scope" |
| "Sévérité" | "Severity" |
| "Règle" | "Rule" |
| "Rôle" | "Role" |
| "Remédiation" | "Remediation" |
| "Erreurs de scan" | "Scan errors" |
| "Rechercher..." | "Search..." |
| "Tous" (filter button) | "All" |
| "Sommaire" (back-to-top link) | "Summary" |

**Step 3: Update test assertions in `tests/test_html_report.py`**

**Step 4: Run tests**

```bash
.venv/bin/python -m pytest tests/test_html_report.py -v
```

**Step 5: Commit**

```bash
git commit -am "feat(i18n): translate HTML report to English"
```

---

## Task 5: i18n — Translate cli.py messages and help text

**Files:**
- Modify: `src/az_perm_watch/cli.py` (all `typer.Option` help strings, all `console.print` messages)
- Modify: `tests/test_cli.py` (update assertion strings checking French output)

**Step 1: Translate Typer app help and command docstrings**

| Location | Current | New |
|----------|---------|-----|
| Line 75 (app help) | "Azure RBAC as Code — drift detection et guardrails." | "Azure RBAC as Code — drift detection and guardrails." |
| scan docstring | "Détecte le drift RBAC..." | "Detect RBAC drift — compare actual state to desired state (baseline rules).\n\nClassic mode: --policy <file.yaml>\nAd-hoc mode: --subscription <id> (no policy, every assignment = drift)" |
| audit docstring | "Audit des guardrails..." | "Audit guardrails — check governance rules (forbidden patterns).\n\nClassic mode: --policy <file.yaml>\nAd-hoc mode: --subscription <id> (uses default rules)" |
| discover docstring | French | Translate to English |
| validate docstring | French | Translate to English |

**Step 2: Translate all `typer.Option` help strings**

All option help strings like "Chemin vers le fichier policy model YAML." → "Path to policy model YAML file."

**Step 3: Translate all `console.print` messages**

All messages like:
- "Auto-discovery des scopes accessibles..." → "Auto-discovering accessible scopes..."
- "Résolution des noms via Graph API..." → "Resolving names via Graph API..."
- "[bold red]Erreur[/bold red]" → "[bold red]Error[/bold red]"
- "Relancez avec --debug pour la traceback complète." → "Rerun with --debug for full traceback."
- "Rapport HTML généré" → "HTML report generated"
- "Rapport JSON généré" → "JSON report generated"
- "Mode ad-hoc : aucune baseline..." → "Ad-hoc mode: no baseline rules..."
- "Mode ad-hoc : {n} règle(s) de gouvernance par défaut..." → "Ad-hoc mode: {n} default governance rule(s) loaded."
- etc.

**Step 4: Translate compliance.py user-facing message strings**

In `src/az_perm_watch/analyzers/compliance.py`, translate finding messages:
- "Assignation non déclarée" → "Undeclared assignment"
- "Ajoutez une baseline rule..." → "Add a baseline rule for this assignment or remove it from the tenant"

**Step 5: Translate default_rules.py descriptions and remediation strings**

In `src/az_perm_watch/config/default_rules.py`, translate:
- Rule descriptions and remediation messages to English.

**Step 6: Update test assertions in `tests/test_cli.py`**

Search for French strings in assertions and update. Key patterns:
- `"baseline" in result.output.lower()` — already language-neutral
- `"mutuellement" in result.output` → "mutually exclusive" or similar
- `"ad-hoc" in result.output.lower()` — already language-neutral
- `"governance" in result.output.lower()` — already language-neutral

**Step 7: Run full test suite**

```bash
.venv/bin/python -m pytest -v
```

**Step 8: Run ruff + mypy**

```bash
.venv/bin/ruff check . && .venv/bin/mypy src/ tests/
```

**Step 9: Commit**

```bash
git commit -am "feat(i18n): translate CLI messages and help text to English"
```

---

## Task 6: Add `--quiet` and `--no-color` global options

**Files:**
- Modify: `src/az_perm_watch/cli.py` (add global options, pass to Console)
- Modify: `src/az_perm_watch/reporters/console_report.py` (respect quiet flag)
- Create: `tests/test_cli_flags.py` (or add to existing test_cli.py)

**Step 1: Write failing tests**

```python
class TestQuietFlag:
    @patch("az_perm_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_perm_watch.cli.scan_rbac")
    def test_quiet_suppresses_output(self, mock_scan, _mock_resolve, tmp_path):
        """--quiet only outputs findings-related content, no progress/status."""
        policy_path = _write_policy(tmp_path, with_governance_rules=True)
        mock_scan.return_value = _mock_scan_result(with_assignments=True)
        result = runner.invoke(app, ["audit", "--policy", str(policy_path), "--quiet"])
        assert result.exit_code == 0
        # Quiet mode: no status messages, no panels
        assert "Auto-discover" not in result.output
        assert "Resolving" not in result.output

class TestNoColorFlag:
    def test_no_color_flag(self, tmp_path):
        policy_path = _write_policy(tmp_path, with_baseline_rules=True)
        result = runner.invoke(app, ["validate", "--policy", str(policy_path), "--no-color"])
        assert result.exit_code == 0
```

**Step 2: Implement global options**

Add `--quiet` and `--no-color` as Typer callback options. Store in module-level variables (like `_debug_mode`). When `--quiet` is set, replace the `console` with a null console or skip non-essential prints. When `--no-color` is set or `NO_COLOR` env var is set, initialize Console with `no_color=True`.

**Step 3: Run tests, verify pass**

**Step 4: Commit**

```bash
git commit -am "feat: add --quiet and --no-color global CLI flags"
```

---

## Task 7: Actionable error messages + loud ad-hoc warnings

**Files:**
- Modify: `src/az_perm_watch/cli.py`
- Modify: `tests/test_cli.py` (update/add assertions)

**Step 1: Improve credential error messages**

In `_build_model_from_args()` (lines 237-296), when tenant_id can't be resolved, change message to:
```
"Error: could not determine tenant ID. Try:\n  1. az login\n  2. az account show --query tenantId\n  3. Pass --tenant-id explicitly"
```

When no subscriptions are accessible:
```
"Error: no accessible subscriptions found. Check:\n  1. Run: az login\n  2. Verify: az account list\n  3. Ensure your identity has Reader role on at least one subscription"
```

**Step 2: Make ad-hoc mode warnings loud (BOLD YELLOW)**

In `cli.py`, change ad-hoc mode messages from `[dim]` to `[bold yellow]`:
- Line ~409: "Ad-hoc mode: no baseline — every assignment will be reported as drift."
- Line ~227-232: "Ad-hoc mode: {n} default governance rule(s) loaded."

**Step 3: Improve "no rules" guidance**

When scan finds no baseline rules (line ~404-406):
```
"No baseline rules in policy model. To create a baseline:\n  az-perm-watch discover -o policy.yaml"
```

**Step 4: Improve named progress bar**

In `_run_scan()` (line ~146), change:
```python
def _on_progress(scope_type: str, scope_name: str) -> None:
    progress.update(task, description=f"Scanning {scope_type}: {scope_name}")
    progress.advance(task)
```

**Step 5: Update/add test assertions**

**Step 6: Run tests + lint**

**Step 7: Commit**

```bash
git commit -am "feat: actionable error messages and loud ad-hoc warnings"
```

---

## Task 8: Match operator conflict detection

**Files:**
- Modify: `src/az_perm_watch/config/policy_model.py` (add validator on RuleMatch)
- Add tests in: `tests/test_policy_model.py`

**Step 1: Write failing tests**

```python
def test_conflicting_role_and_role_not_in():
    """role='Owner' + role_not_in=['Owner'] should warn."""
    with pytest.warns(UserWarning, match="contradictory"):
        RuleMatch(role="Owner", role_not_in=["Owner"])

def test_conflicting_role_in_and_role_not_in():
    """role_in=['Owner'] + role_not_in=['Owner'] should warn."""
    with pytest.warns(UserWarning, match="contradictory"):
        RuleMatch(role_in=["Owner"], role_not_in=["Owner"])

def test_conflicting_principal_name_prefix():
    """principal_name_prefix + principal_name_not_prefix same value should warn."""
    with pytest.warns(UserWarning, match="contradictory"):
        RuleMatch(principal_name_prefix="AZ_", principal_name_not_prefix="AZ_")
```

**Step 2: Add model_validator on RuleMatch**

Add a `@model_validator(mode="after")` that checks for contradictions:
- `role` is in `role_not_in`
- Overlap between `role_in` and `role_not_in`
- `principal_name_prefix` == `principal_name_not_prefix`
- `principal_name_contains` == `principal_name_not_contains`

Issue `warnings.warn()` (not raise) — contradictions are warnings, not errors.

**Step 3: Run tests**

**Step 4: Commit**

```bash
git commit -am "feat: warn on contradictory match operator combinations"
```

---

## Task 9: `--dry-run` mode

**Files:**
- Modify: `src/az_perm_watch/cli.py` (add --dry-run to scan, audit, discover)
- Add tests in: `tests/test_cli.py`

**Step 1: Write failing tests**

```python
class TestDryRun:
    def test_scan_dry_run(self, tmp_path):
        """--dry-run validates policy and shows scan plan without calling Azure."""
        policy_path = _write_policy(tmp_path, with_baseline_rules=True)
        result = runner.invoke(app, ["scan", "--policy", str(policy_path), "--dry-run"])
        assert result.exit_code == 0
        assert "dry run" in result.output.lower()
        assert "would scan" in result.output.lower() or "subscription" in result.output.lower()

    @patch("az_perm_watch.cli.scan_rbac")
    def test_scan_dry_run_no_api_call(self, mock_scan, tmp_path):
        """--dry-run must NOT call scan_rbac."""
        policy_path = _write_policy(tmp_path, with_baseline_rules=True)
        runner.invoke(app, ["scan", "--policy", str(policy_path), "--dry-run"])
        mock_scan.assert_not_called()
```

**Step 2: Implement --dry-run**

Add `--dry-run` flag to scan, audit, discover commands. When set:
1. Load/build model normally
2. Resolve and filter scopes
3. Print plan: "Dry run — would scan N subscriptions, M management groups"
4. List each scope with its name
5. Print rule summary: "N baseline rules, M governance rules"
6. Exit 0 without calling `scan_rbac()`

**Step 3: Run tests**

**Step 4: Commit**

```bash
git commit -am "feat: add --dry-run flag to scan, audit, discover commands"
```

---

## Task 10: Config file support

**Files:**
- Create: `src/az_perm_watch/config/settings.py`
- Modify: `src/az_perm_watch/cli.py` (load settings, use as defaults)
- Create: `tests/test_settings.py`

**Step 1: Write failing tests**

```python
# tests/test_settings.py
def test_load_from_yaml(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text("policy: /path/to/policy.yaml\nformat: json\n")
    settings = load_settings(config_path=config)
    assert settings.policy == "/path/to/policy.yaml"
    assert settings.format == "json"

def test_env_var_override(monkeypatch, tmp_path):
    monkeypatch.setenv("AZ_PERM_WATCH_FORMAT", "json")
    settings = load_settings()
    assert settings.format == "json"

def test_defaults():
    settings = load_settings()
    assert settings.policy is None
    assert settings.format == "console"
```

**Step 2: Implement `settings.py`**

Use Pydantic `BaseSettings` with:
- **Fields**: policy (Path | None), format (str = "console"), quiet (bool = False), no_color (bool = False)
- **Sources** (priority order): CLI flags > env vars (`AZ_PERM_WATCH_*`) > config file > defaults
- **Config file search**: `$AZ_PERM_WATCH_CONFIG` env var, then `~/.config/az-perm-watch/config.yaml`

**Step 3: Wire into cli.py**

In the Typer app callback or each command, load settings and use as defaults for options not explicitly set by the user.

**Step 4: Run tests**

**Step 5: Commit**

```bash
git commit -am "feat: add config file and env var support for CLI defaults"
```

---

## Task 11: Auto-detect policy file in cwd

**Files:**
- Modify: `src/az_perm_watch/cli.py` (modify `_load_or_build_model`)
- Add tests in: `tests/test_cli.py`

**Step 1: Write failing tests**

```python
class TestAutoDetectPolicy:
    @patch("az_perm_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_perm_watch.cli.scan_rbac")
    def test_auto_detect_policy_yaml(self, mock_scan, _mock_resolve, tmp_path, monkeypatch):
        """scan without --policy picks up policy.yaml from cwd."""
        monkeypatch.chdir(tmp_path)
        _write_policy(tmp_path, with_baseline_rules=True)  # creates policy.yaml
        mock_scan.return_value = _mock_scan_result(with_assignments=True)
        result = runner.invoke(app, ["scan"])
        assert result.exit_code == 0
        mock_scan.assert_called_once()
```

**Step 2: Implement auto-detect**

In `_load_or_build_model()`, when `policy is None` and no `-s`/`-m` provided, check cwd for:
1. `policy.yaml`
2. `.az-perm-watch.yaml`
3. `az-perm-watch.yaml`

If found, load it. If not found, fall through to auto-discovery.

**Step 3: Run tests**

**Step 4: Commit**

```bash
git commit -am "feat: auto-detect policy file in current directory"
```

---

## Task 12: S-tier onboarding — zero-args default + credential check + next steps footer

**Files:**
- Modify: `src/az_perm_watch/cli.py` (app callback, credential check, next steps)
- Modify: `src/az_perm_watch/auth/azure_clients.py` (add credential check function)
- Modify: `src/az_perm_watch/reporters/console_report.py` (add next_steps parameter)
- Add tests in: `tests/test_cli.py`

**Step 1: Write failing tests**

```python
class TestZeroArgsDefault:
    @patch("az_perm_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_perm_watch.cli.scan_rbac")
    @patch("az_perm_watch.cli.list_accessible_subscriptions")
    @patch("az_perm_watch.cli.list_accessible_management_groups")
    def test_no_args_runs_audit(self, mock_mgs, mock_subs, mock_scan, _mock_resolve):
        """az-perm-watch with no args runs audit with auto-discovery."""
        mock_subs.return_value = [(VALID_SUB_ID, "Prod", VALID_TENANT_ID)]
        mock_mgs.return_value = []
        mock_scan.return_value = _mock_scan_result(with_assignments=True)
        result = runner.invoke(app, [])
        assert result.exit_code in (0, 1)
        mock_scan.assert_called_once()

class TestNextStepsFooter:
    @patch("az_perm_watch.cli.resolve_display_names", side_effect=lambda sr, **kw: sr)
    @patch("az_perm_watch.cli.scan_rbac")
    @patch("az_perm_watch.cli.list_accessible_subscriptions")
    @patch("az_perm_watch.cli.list_accessible_management_groups")
    def test_audit_shows_next_steps(self, mock_mgs, mock_subs, mock_scan, _mock_resolve):
        """Audit output includes next steps guidance."""
        mock_subs.return_value = [(VALID_SUB_ID, "Prod", VALID_TENANT_ID)]
        mock_mgs.return_value = []
        mock_scan.return_value = _mock_scan_result(with_assignments=False)
        result = runner.invoke(app, ["audit"])
        assert "next step" in result.output.lower() or "discover" in result.output.lower()
```

**Step 2: Add credential check utility**

In `azure_clients.py`, add:
```python
def check_credentials() -> bool:
    """Test if Azure credentials are available. Returns True if valid."""
    try:
        cred = get_credential()
        cred.get_token("https://management.azure.com/.default")
        return True
    except Exception:
        return False
```

**Step 3: Change app default behavior**

Replace `no_args_is_help=True` with a Typer callback that:
- If no subcommand given → invoke `audit` with zero args (auto-discovery + default rules)
- Keep `--help` accessible

Implementation approach: use `invoke_without_command=True` on the Typer app callback, and if `ctx.invoked_subcommand is None`, call the audit logic.

**Step 4: Add credential check at start of scan/audit/discover**

Before calling `_run_scan()`, call `check_credentials()`. On failure:
```
"Error: no Azure credentials found.\n\nQuick fix:\n  az login\n\nThen retry:\n  az-perm-watch"
```

**Step 5: Add next steps footer to console reports**

After printing the report, print context-aware next steps:
- After `audit` (no policy): "Next steps:\n  az-perm-watch discover -o policy.yaml  # capture current state\n  az-perm-watch scan -p policy.yaml       # detect drift"
- After `scan` with drift: "Next steps:\n  Review undeclared assignments and update policy.yaml"
- After `scan` compliant: "All good! Integrate in CI: az-perm-watch scan -p policy.yaml --format json"

**Step 6: Add quick start to help epilog**

```python
app = typer.Typer(
    name="az-perm-watch",
    help="Azure RBAC as Code — drift detection and guardrails.",
    epilog="Quick start:  az-perm-watch  (scans all accessible subscriptions with default rules)",
    invoke_without_command=True,
)
```

**Step 7: Run full test suite + lint**

**Step 8: Commit**

```bash
git commit -am "feat: S-tier onboarding — zero-args audit, credential check, next steps footer"
```

---

## Task 13: Shell completion docs in README

**Files:**
- Modify: `README.md`

**Step 1: Add section after "Installation"**

```markdown
## Shell completion

Enable tab completion for bash, zsh, or fish:

\`\`\`bash
az-perm-watch --install-completion
\`\`\`

Restart your shell after installation.
```

**Step 2: Commit**

```bash
git commit -am "docs: add shell completion instructions to README"
```

---

## Task 14: setuptools-scm — version from git tags

**Files:**
- Modify: `pyproject.toml` (replace static version with dynamic)
- Modify: `.github/workflows/ci.yml` (ensure git history for scm)

**Step 1: Update pyproject.toml**

Replace:
```toml
version = "0.1.0"
```

With:
```toml
dynamic = ["version"]
```

Add:
```toml
[tool.setuptools_scm]
```

Change build system to include setuptools-scm:
```toml
[build-system]
requires = ["hatchling", "hatch-vcs"]
build-backend = "hatchling.build"

[tool.hatch.version]
source = "vcs"
```

**Step 2: Verify build works**

```bash
pip install hatch-vcs
git tag v0.2.0-dev  # temporary tag for testing
python -m build
# Check version in dist/ filename
git tag -d v0.2.0-dev
```

**Step 3: Update CI to fetch full git history**

In `.github/workflows/ci.yml`, ensure checkout has `fetch-depth: 0`.

**Step 4: Commit**

```bash
git commit -am "build: switch to hatch-vcs for version from git tags"
```

---

## Task 15: Build check in CI

**Files:**
- Modify: `.github/workflows/ci.yml`

**Step 1: Add build step after tests**

```yaml
    - name: Build package
      run: |
        uv pip install build hatch-vcs
        python -m build
```

**Step 2: Commit**

```bash
git commit -am "ci: add package build verification step"
```

---

## Task 16: Publish workflow (tag → PyPI + GitHub Release)

**Files:**
- Create: `.github/workflows/publish.yml`

**Step 1: Create publish workflow**

```yaml
name: Publish

on:
  push:
    tags: ["v*"]

permissions:
  contents: write
  id-token: write

jobs:
  publish:
    runs-on: ubuntu-latest
    environment: pypi
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install build tools
        run: pip install build hatch-vcs

      - name: Build
        run: python -m build

      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1

      - name: Extract changelog
        id: changelog
        run: |
          VERSION=${GITHUB_REF_NAME#v}
          awk "/^## \[${VERSION}\]/{found=1; next} /^## \[/{found=0} found" CHANGELOG.md > release_notes.md

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          body_path: release_notes.md
          files: dist/*
```

**Step 2: Commit**

```bash
git commit -am "ci: add publish workflow (tag → PyPI + GitHub Release)"
```

**Note:** After pushing, configure PyPI trusted publisher in PyPI project settings (manual step).

---

## Task 17: CONTRIBUTING.md

**Files:**
- Create: `CONTRIBUTING.md`

**Step 1: Write CONTRIBUTING.md**

Cover:
- Dev setup (`uv venv && uv pip install -e ".[dev]"`)
- Running checks (`ruff check .`, `mypy src/ tests/`, `pytest`)
- Pre-commit hooks (`pre-commit install`)
- Conventions: French docstrings/comments, English UI, mypy strict
- PR process: branch from main, tests must pass, one approval required
- Commit style: conventional commits (`feat:`, `fix:`, `docs:`, `chore:`)

**Step 2: Commit**

```bash
git commit -am "docs: add CONTRIBUTING.md"
```

---

## Task 18: mkdocs setup + documentation site

**Files:**
- Create: `mkdocs.yml`
- Create: `docs/index.md`
- Create: `docs/getting-started.md`
- Create: `docs/commands/audit.md`
- Create: `docs/commands/scan.md`
- Create: `docs/commands/discover.md`
- Create: `docs/commands/validate.md`
- Move+adapt: `docs/policy-reference.md` (from `POLICY_REFERENCE.md`)
- Create: `docs/configuration.md`
- Create: `docs/ci-cd.md`
- Create: `docs/architecture.md`
- Modify: `pyproject.toml` (add mkdocs deps to optional group)

**Step 1: Add mkdocs deps**

In `pyproject.toml`, add optional dependency group:
```toml
[project.optional-dependencies]
docs = ["mkdocs-material", "mkdocs-minify-plugin"]
```

**Step 2: Create `mkdocs.yml`**

```yaml
site_name: Azure Permissions Watch
site_description: Azure RBAC as Code — drift detection and guardrails
repo_url: https://github.com/maxvanp/azure-permissions-watch
theme:
  name: material
  palette:
    primary: blue
    accent: cyan
nav:
  - Home: index.md
  - Getting Started: getting-started.md
  - Commands:
    - audit: commands/audit.md
    - scan: commands/scan.md
    - discover: commands/discover.md
    - validate: commands/validate.md
  - Policy Reference: policy-reference.md
  - Configuration: configuration.md
  - CI/CD Integration: ci-cd.md
  - Architecture: architecture.md
  - Contributing: contributing.md
plugins:
  - search
  - minify:
      minify_html: true
```

**Step 3: Write each page**

- `index.md`: Condensed README — what it does, positioning, quick start
- `getting-started.md`: Full onboarding flow (install → az login → first audit → discover → scan)
- `commands/*.md`: Usage, all options, examples, exit codes per command
- `policy-reference.md`: Migrated from POLICY_REFERENCE.md
- `configuration.md`: Config file format, env vars, auto-detect policy, precedence order
- `ci-cd.md`: GitHub Actions example, Azure DevOps example, exit codes, JSON output parsing
- `architecture.md`: Two-pass engine, rule matching, scan flow, module overview
- `contributing.md`: Short page linking to root CONTRIBUTING.md

**Step 4: Test locally**

```bash
uv pip install -e ".[docs]"
mkdocs serve
# Visit http://127.0.0.1:8000
```

**Step 5: Commit**

```bash
git add mkdocs.yml docs/
git commit -m "docs: add mkdocs-material documentation site"
```

---

## Task 19: Docs deploy workflow

**Files:**
- Create: `.github/workflows/docs.yml`

**Step 1: Create workflow**

```yaml
name: Docs

on:
  push:
    branches: [main]
    paths: ["docs/**", "mkdocs.yml"]

permissions:
  pages: write
  id-token: write

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment:
      name: github-pages
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install mkdocs-material mkdocs-minify-plugin
      - run: mkdocs build
      - uses: actions/upload-pages-artifact@v3
        with:
          path: site/
      - uses: actions/deploy-pages@v4
```

**Step 2: Commit**

```bash
git commit -am "ci: add docs deploy workflow for GitHub Pages"
```

---

## Task 20: Final — update CHANGELOG, tag v0.2.0, push

**Files:**
- Modify: `CHANGELOG.md` (update v0.2.0 entry with all changes)
- Modify: `README.md` (final review, ensure consistency with new English UI)

**Step 1: Update CHANGELOG.md**

Add all Phase 1-3 changes to the v0.2.0 entry:
- i18n: English UI
- S-tier onboarding (zero-args, auto-detect policy, credential check, next steps)
- --quiet, --no-color, --dry-run flags
- Config file support
- Match operator conflict warnings
- Pre-commit config, coverage
- setuptools-scm, publish workflow
- mkdocs documentation site
- CONTRIBUTING.md

**Step 2: Final full check**

```bash
.venv/bin/ruff check .
.venv/bin/mypy src/ tests/
.venv/bin/python -m pytest --cov
python -m build
mkdocs build
```

**Step 3: Commit**

```bash
git commit -am "release: prepare v0.2.0"
```

**Step 4: Tag and push**

```bash
git tag v0.2.0
git push && git push --tags
```

This triggers:
1. CI workflow (lint + type check + test + build)
2. Publish workflow (PyPI + GitHub Release)
3. Docs workflow (mkdocs → GitHub Pages)

---

## Execution order summary

| Task | Phase | Description | Depends on |
|------|-------|-------------|------------|
| 1 | 1 | Pre-commit + coverage setup | — |
| 2 | 1 | i18n: policy_model.py | — |
| 3 | 1 | i18n: console_report.py | — |
| 4 | 1 | i18n: html_report.py | — |
| 5 | 1 | i18n: cli.py + compliance.py + default_rules.py | 2, 3, 4 |
| 6 | 1 | --quiet + --no-color flags | 5 |
| 7 | 1 | Actionable errors + loud ad-hoc | 5 |
| 8 | 1 | Match operator conflict detection | 2 |
| 9 | 1 | --dry-run mode | 5 |
| 10 | 1 | Config file support | 6 |
| 11 | 1 | Auto-detect policy in cwd | 10 |
| 12 | 1 | S-tier onboarding (zero-args, cred check, footer) | 7, 11 |
| 13 | 1 | Shell completion docs | — |
| 14 | 2 | setuptools-scm | — |
| 15 | 2 | Build check in CI | 14 |
| 16 | 2 | Publish workflow | 15 |
| 17 | 2 | CONTRIBUTING.md | — |
| 18 | 3 | mkdocs site | 5, 10, 12 |
| 19 | 3 | Docs deploy workflow | 18 |
| 20 | — | Final: changelog, tag, push | All |

Tasks 1-4, 8, 13, 14, 17 can be parallelized (no dependencies between them).
