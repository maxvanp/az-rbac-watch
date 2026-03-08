# scan

Detect RBAC drift — compare actual state against baseline rules.

Any assignment not covered by a baseline rule is reported as **DRIFT**.

## Usage

```bash
# With a policy file
az-rbac-watch scan -p policy.yaml

# Ad-hoc mode (every assignment = drift)
az-rbac-watch scan -s <subscription-id>
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
# Console output
az-rbac-watch scan -p policy.yaml

# HTML report
az-rbac-watch scan -p policy.yaml -o drift-report.html

# JSON for CI/CD
az-rbac-watch scan -p policy.yaml --format json

# JSON to file
az-rbac-watch scan -p policy.yaml --format json -o drift.json

# Ad-hoc: scan a single subscription (all assignments = drift)
az-rbac-watch scan -s 11111111-1111-1111-1111-111111111111

# Exclude subscriptions at runtime
az-rbac-watch scan -p policy.yaml --exclude-subscription 22222222-2222-2222-2222-222222222222

# Dry run
az-rbac-watch scan -p policy.yaml --dry-run

# Verbose + debug
az-rbac-watch scan -p policy.yaml --verbose --debug
```

## Baseline rule requirement

The `scan` command requires at least one baseline rule in the policy. If there are no baseline rules:

- **With `--policy`**: exits with a message suggesting `discover` to create a baseline
- **Ad-hoc mode** (no `--policy`): every assignment is reported as drift

To generate baseline rules from your current state:

```bash
az-rbac-watch discover -o policy.yaml
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Compliant — no drift detected |
| `1` | Non-compliant — drift detected |
| `2` | Error — auth failure, API error, invalid YAML |
