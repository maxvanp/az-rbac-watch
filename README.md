# Azure Permissions Watch

Azure RBAC as Code — drift detection and guardrails.

## What it does

Two complementary commands in one tool:

- **`scan`** — **RBAC as Code** (affirmative): declare your desired RBAC state in YAML, detect drift from that state
- **`audit`** — **Policy as Code** (negative): define forbidden patterns (guardrails), detect violations
- **`scan --orphans-only`** — detect assignments referencing deleted principals (orphaned identities)

Both commands share the same RBAC scanner — the differentiating value is that neither OPA nor Azure Policy can natively scan RBAC assignments.

## Installation

```bash
# Recommended — isolated install for CLI tools
pipx install az-rbac-watch

# Or with pip
pip install az-rbac-watch
```

Requires Python ≥ 3.12 and [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) for authentication.

## Shell completion

Enable tab completion for bash, zsh, or fish:

```bash
az-rbac-watch --install-completion
```

Restart your shell after installation.

## Quick start

### 1. Authenticate

```bash
az login
```

### 2. Discover existing assignments

```bash
# Single subscription
az-rbac-watch discover -t <tenant-id> -s <subscription-id> -o my_policy.yaml

# All accessible scopes
az-rbac-watch discover -t <tenant-id> -o my_policy.yaml
```

### 3. Scan for drift (RBAC as Code)

The `scan` command compares actual RBAC assignments against your baseline rules. Any assignment not covered by a baseline rule is reported as **DRIFT**.

```bash
# Console output
az-rbac-watch scan -p my_policy.yaml

# HTML report
az-rbac-watch scan -p my_policy.yaml -o report.html

# JSON (CI/CD)
az-rbac-watch scan -p my_policy.yaml --format json
```

### 4. Audit guardrails (Policy as Code)

The `audit` command checks governance rules (forbidden patterns). Any assignment matching a governance rule is reported as a **violation**.

```bash
# Console output
az-rbac-watch audit -p my_policy.yaml

# HTML report
az-rbac-watch audit -p my_policy.yaml -o report.html

# JSON (CI/CD)
az-rbac-watch audit -p my_policy.yaml --format json
```

A starter kit with common governance rules is available in [`examples/deny_rules_starter.yaml`](examples/deny_rules_starter.yaml).

### 5. Validate policy syntax (offline)

```bash
az-rbac-watch validate -p my_policy.yaml
```

### 6. Capture RBAC snapshots

```bash
# From a policy file
az-rbac-watch snapshot -p my_policy.yaml -o snapshot_2026-03-09.json

# From explicit scopes
az-rbac-watch snapshot -t <tenant-id> -s <subscription-id> -o snapshot.json
```

### 7. Compare snapshots (change tracking)

```bash
# Console output
az-rbac-watch diff snapshot_old.json snapshot_new.json

# JSON (CI/CD)
az-rbac-watch diff snapshot_old.json snapshot_new.json --format json -o changes.json
```

## Two axes, one tool

| Axis | Command | Rule type | Finding | Question answered |
|------|---------|-----------|---------|-------------------|
| RBAC as Code | `scan` | `baseline` | `DRIFT` | "Is there something I didn't declare?" |
| Policy as Code | `audit` | `governance` | `GOVERNANCE_VIOLATION` | "Is there something forbidden?" |
| Change tracking | `snapshot` + `diff` | n/a | Added / Removed / Modified | "What changed since last time?" |

You can use both in the same policy file. Each command focuses on its rule type and ignores the other.

## Scope modes

The policy model supports two scope modes:

- **`scope: explicit`** (default) — only scans subscriptions and management groups listed in the YAML
- **`scope: all`** — auto-discovers all accessible scopes at scan time, with optional exclusions

```yaml
scope: all
exclude_subscriptions:
  - "22222222-2222-2222-2222-222222222222"
exclude_management_groups:
  - "mg-sandbox"
```

CLI exclusions (`--exclude-subscription`, `--exclude-management-group`) apply on top of YAML exclusions.

## CLI reference

### `az-rbac-watch scan`

Detects RBAC drift — compares actual state against baseline rules.

| Option | Description |
|---|---|
| `-p, --policy PATH` | Policy model YAML (required) |
| `-t, --tenant-id ID` | Tenant ID (ad-hoc mode) |
| `-s, --subscription ID` | Subscription to scan, repeatable (ad-hoc mode) |
| `-m, --management-group ID` | Management group to scan, repeatable (ad-hoc mode) |
| `-o, --output PATH` | HTML report output path |
| `-f, --format FORMAT` | `console` (default) or `json` |
| `--orphans-only` | Scan only for orphaned assignments (requires `--tenant-id`) |
| `--dry-run` | Show scan plan without making API calls |
| `--exclude-subscription ID` | Exclude subscription (repeatable) |
| `--exclude-management-group ID` | Exclude management group (repeatable) |
| `-v, --verbose` | Debug logging |
| `--debug` | Show full traceback on error |

### `az-rbac-watch audit`

Checks governance guardrails — evaluates governance rules against actual state.

| Option | Description |
|---|---|
| `-p, --policy PATH` | Policy model YAML (required) |
| `-t, --tenant-id ID` | Tenant ID (ad-hoc mode) |
| `-s, --subscription ID` | Subscription to scan, repeatable (ad-hoc mode) |
| `-m, --management-group ID` | Management group to scan, repeatable (ad-hoc mode) |
| `-o, --output PATH` | HTML report output path |
| `-f, --format FORMAT` | `console` (default) or `json` |
| `--dry-run` | Show scan plan without making API calls |
| `--exclude-subscription ID` | Exclude subscription (repeatable) |
| `--exclude-management-group ID` | Exclude management group (repeatable) |
| `-v, --verbose` | Debug logging |
| `--debug` | Show full traceback on error |

### `az-rbac-watch discover`

| Option | Description |
|---|---|
| `-t, --tenant-id ID` | Tenant ID |
| `-s, --subscription ID` | Subscription to scan (repeatable) |
| `-m, --management-group ID` | Management group to scan (repeatable) |
| `-o, --output PATH` | Output YAML (default: `discovered_policy.yaml`) |

### `az-rbac-watch validate`

| Option | Description |
|---|---|
| `-p, --policy PATH` | Policy model YAML to validate (required) |

### `az-rbac-watch snapshot`

Captures a full RBAC snapshot (assignments + role definitions) as JSON.

| Option | Description |
|---|---|
| `-p, --policy PATH` | Policy model YAML (uses its scopes) |
| `-t, --tenant-id ID` | Tenant ID |
| `-s, --subscription ID` | Subscription to scan (repeatable) |
| `-m, --management-group ID` | Management group to scan (repeatable) |
| `--exclude-subscription ID` | Exclude subscription (repeatable) |
| `--exclude-management-group ID` | Exclude management group (repeatable) |
| `-o, --output PATH` | Output JSON file (required) |
| `-v, --verbose` | Debug logging |
| `--debug` | Show full traceback on error |

### `az-rbac-watch diff`

Compares two snapshots and shows RBAC changes (added, removed, modified assignments).

| Option | Description |
|---|---|
| `OLD_SNAPSHOT` | Path to the older snapshot JSON file (required) |
| `NEW_SNAPSHOT` | Path to the newer snapshot JSON file (required) |
| `-f, --format FORMAT` | `console` (default) or `json` |
| `-o, --output PATH` | Output file path |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Compliant — no findings detected |
| `1` | Non-compliant — findings detected |
| `2` | Error — authentication failure, API error, invalid YAML |

The `diff` command returns `0` for no changes, `1` for changes detected.

Example CI/CD usage:

```bash
# Check drift
az-rbac-watch scan -p policy.yaml --format json -o drift.json
scan_exit=$?

# Check guardrails
az-rbac-watch audit -p policy.yaml --format json -o audit.json
audit_exit=$?

if [ "$scan_exit" -eq 1 ] || [ "$audit_exit" -eq 1 ]; then
  echo "Non-compliant — review reports"
elif [ "$scan_exit" -eq 2 ] || [ "$audit_exit" -eq 2 ]; then
  echo "Scan error — check credentials and permissions"
fi
```

## Troubleshooting

**Authentication error**
- Run `az login` to refresh your credentials
- Verify `DefaultAzureCredential` can authenticate (check `AZURE_*` env vars or managed identity)

**Access denied**
- The scanning principal needs `Microsoft.Authorization/roleAssignments/read` on each scoped subscription/MG
- Check with: `az role assignment list --scope /subscriptions/<id> --assignee <principal-id>`

**Names not resolved (UUIDs shown)**
- The App Registration (or user) needs `Directory.Read.All` permission on Microsoft Graph
- Run with `--verbose` to see Graph API errors in the logs

**Throttling**
- Azure ARM API rate-limits parallel requests
- Reduce parallelism: the default is 4 workers (configurable in code via `max_workers`)
- Wait a few minutes and retry

**Full traceback**
- Use `--debug` to see the complete Python traceback on any error

## GitHub Actions

Use the composite action to integrate az-rbac-watch into your CI/CD pipelines.

### Basic usage

```yaml
- uses: maxvanp/az-rbac-watch@v0.5.0
  with:
    mode: scan
    policy: policy.yaml
    format: json
    output: report.json
```

### Available modes

| Mode | Description | Azure auth required |
|------|-------------|---------------------|
| `scan` | Detect RBAC drift against baseline rules | Yes |
| `audit` | Check governance guardrails | Yes |
| `validate` | Validate policy YAML syntax (offline) | No |
| `snapshot` | Capture RBAC snapshot | Yes |
| `diff` | Compare two snapshots | No |

### Example workflows

Ready-to-use workflow templates are available in [`examples/workflows/`](examples/workflows/):

- **[`rbac-scheduled-scan.yml`](examples/workflows/rbac-scheduled-scan.yml)** — Daily scan + audit with artifact reports
- **[`rbac-pr-check.yml`](examples/workflows/rbac-pr-check.yml)** — Validate policy files on pull requests
- **[`rbac-snapshot-diff.yml`](examples/workflows/rbac-snapshot-diff.yml)** — Weekly snapshot comparison with change detection

Copy the desired workflow to `.github/workflows/` in your repository and configure the required secrets.

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `mode` | yes | — | Command: `scan`, `audit`, `validate`, `snapshot`, `diff` |
| `policy` | no | — | Path to policy YAML file |
| `tenant-id` | no | — | Azure tenant ID |
| `subscriptions` | no | — | Subscription IDs (comma-separated) |
| `management-groups` | no | — | Management group IDs (comma-separated) |
| `format` | no | `console` | Output format: `console` or `json` |
| `output` | no | — | Output file path |
| `old-snapshot` | no | — | Old snapshot path (diff mode) |
| `new-snapshot` | no | — | New snapshot path (diff mode) |
| `python-version` | no | `3.12` | Python version |
| `extra-args` | no | — | Additional CLI arguments |

### Outputs

| Output | Description |
|--------|-------------|
| `exit-code` | `0` = compliant, `1` = findings/changes, `2` = error |
| `report-path` | Path to generated report (if `output` is set) |

## Rule match operators

All comparisons are case-insensitive. Conditions are combined with AND logic.

| Operator | Type | Description |
|---|---|---|
| `scope` | `str` | Exact scope match |
| `scope_prefix` | `str` | Scope starts with value |
| `role` | `str` | Exact role name |
| `role_in` | `list` | Role is in list |
| `role_not_in` | `list` | Role is NOT in list |
| `role_type` | `str` | `BuiltInRole` or `CustomRole` |
| `principal_type` | `str` | `User`, `Group`, or `ServicePrincipal` |
| `principal_type_in` | `list` | Principal type is in list |
| `principal_id` | `str` | Exact principal ID |
| `principal_name_prefix` | `str` | Display name starts with |
| `principal_name_not_prefix` | `str` | Display name does NOT start with |
| `principal_name_contains` | `str` | Display name contains |
| `principal_name_not_contains` | `str` | Display name does NOT contain |

Name-based operators require Graph API access. If unavailable, they evaluate to `false` (no false positives).

## Required Azure permissions

- `Microsoft.Authorization/roleAssignments/read` on scanned scopes
- `Directory.Read.All` (Graph API, for display name resolution)

## License

MIT
