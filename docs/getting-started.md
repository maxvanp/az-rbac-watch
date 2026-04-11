# Getting Started

## Prerequisites

- **Azure CLI** (`az`) — for authentication
- **Azure permissions**: `Microsoft.Authorization/roleAssignments/read` on scopes you want to scan
- **Optional**: `Directory.Read.All` on Microsoft Graph for display name resolution
- **Optional**: Python 3.12+ if you are not using the bootstrap script or `uv`

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/maxvanp/az-rbac-watch/main/scripts/install.sh | sh
```

Or install explicitly with `uv`:

```bash
uv tool install az-rbac-watch
uv tool update-shell
```

This installs the `az-rbac-watch` command into your user tool directory so it is available directly on your `PATH`.

## Authenticate

```bash
az login
```

Any credential supported by `DefaultAzureCredential` works: Azure CLI, managed identity, environment variables, etc.

## First audit (zero-config)

Run with no arguments to audit all accessible subscriptions with built-in governance rules:

```bash
az-rbac-watch
```

This auto-discovers your subscriptions, scans RBAC assignments, and checks against default governance rules (no direct users, no Owner at subscription scope, etc.).

## Discover existing assignments

Generate a baseline policy from your current RBAC state:

```bash
# Single subscription
az-rbac-watch discover -t <tenant-id> -s <subscription-id> -o policy.yaml

# All accessible scopes
az-rbac-watch discover -t <tenant-id> -o policy.yaml
```

The output is a ready-to-use YAML policy with one baseline rule per assignment.

## Scan for drift

Compare actual state against your baseline:

```bash
az-rbac-watch scan -p policy.yaml
```

Any assignment not covered by a baseline rule is reported as **DRIFT**.

```bash
# HTML report
az-rbac-watch scan -p policy.yaml -o report.html

# JSON for CI/CD
az-rbac-watch scan -p policy.yaml --format json
```

## Audit governance rules

Check forbidden patterns:

```bash
az-rbac-watch audit -p policy.yaml
```

Any assignment matching a governance rule is reported as a **GOVERNANCE_VIOLATION**.

## Interpret results

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Compliant — no findings |
| `1` | Non-compliant — findings detected |
| `2` | Error — auth failure, API error, invalid YAML |

### Console output

Findings are grouped by scope and sorted by severity. Each finding shows:

- Severity (critical/high/medium/low/info)
- Finding type (DRIFT or GOVERNANCE_VIOLATION)
- The matched rule name and description
- The role assignment details (principal, role, scope)

## Validate policy syntax

Check your YAML without Azure credentials:

```bash
az-rbac-watch validate -p policy.yaml
```

## Track changes over time

Capture a point-in-time RBAC snapshot:

```bash
az-rbac-watch snapshot -p policy.yaml -o snapshot-2026-04-11.json
```

Then compare two snapshots:

```bash
az-rbac-watch diff snapshot-old.json snapshot-new.json
```

Use `--format json` for automation or `--output changes.html` to generate an HTML change report.

## Recommended workflow

1. `az-rbac-watch` — quick audit with default rules
2. `az-rbac-watch discover -o policy.yaml` — capture current state
3. Add governance rules to `policy.yaml`
4. `az-rbac-watch scan -p policy.yaml` — detect drift from baseline
5. `az-rbac-watch audit -p policy.yaml` — check guardrails
6. `az-rbac-watch snapshot -p policy.yaml -o snapshot.json` — capture a reference state when needed
7. `az-rbac-watch diff old.json new.json` — review RBAC changes over time
8. Integrate in CI/CD with `--format json`
