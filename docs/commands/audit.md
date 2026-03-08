# audit

Check governance guardrails — evaluates governance rules against actual RBAC state.

Any assignment matching a governance rule is reported as a **GOVERNANCE_VIOLATION**.

## Usage

```bash
# With a policy file
az-rbac-watch audit -p policy.yaml

# Ad-hoc mode (uses default governance rules)
az-rbac-watch audit -s <subscription-id>

# Zero-args (auto-discover + default rules)
az-rbac-watch audit
az-rbac-watch  # audit is the default command
```

## Options

| Option | Short | Description |
|--------|-------|-------------|
| `--policy PATH` | `-p` | Policy model YAML file |
| `--subscription ID` | `-s` | Subscription ID to scan (repeatable, ad-hoc mode) |
| `--management-group ID` | `-m` | Management group ID to scan (repeatable, ad-hoc mode) |
| `--tenant-id ID` | `-t` | Tenant ID (auto-detected if omitted) |
| `--exclude-subscription ID` | | Subscription ID to exclude (repeatable) |
| `--exclude-management-group ID` | | Management group ID to exclude (repeatable) |
| `--output PATH` | `-o` | Output file path (HTML or JSON depending on format) |
| `--format FORMAT` | `-f` | Output format: `console` (default) or `json` |
| `--verbose` | `-v` | Enable debug logging |
| `--dry-run` | | Show scan plan without making API calls |
| `--debug` | | Show full traceback on error |
| `--quiet` | `-q` | Suppress all output except findings and exit code |
| `--no-color` | | Disable colored output |

`--policy` and `--subscription`/`--management-group` are mutually exclusive.

## Policy auto-detection

When no `--policy` is provided and no `-s`/`-m` flags are used, the CLI looks for a policy file in the current directory:

1. `policy.yaml`
2. `.az-rbac-watch.yaml`
3. `az-rbac-watch.yaml`

## Examples

```bash
# Console output with custom policy
az-rbac-watch audit -p governance.yaml

# HTML report
az-rbac-watch audit -p policy.yaml -o audit-report.html

# JSON output to stdout
az-rbac-watch audit -p policy.yaml --format json

# JSON output to file
az-rbac-watch audit -p policy.yaml --format json -o audit.json

# Exclude a sandbox subscription
az-rbac-watch audit -p policy.yaml --exclude-subscription 22222222-2222-2222-2222-222222222222

# Dry run — see what would be scanned
az-rbac-watch audit -p policy.yaml --dry-run

# Verbose logging
az-rbac-watch audit -p policy.yaml --verbose
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Compliant — no governance violations |
| `1` | Non-compliant — governance violations detected |
| `2` | Error — auth failure, API error, invalid YAML |
