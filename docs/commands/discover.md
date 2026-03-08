# discover

Discover existing RBAC assignments and generate a draft policy model.

The output is a YAML file with one baseline rule per discovered assignment — ready to use with `scan`.

## Usage

```bash
# All accessible scopes
az-rbac-watch discover -t <tenant-id> -o policy.yaml

# Single subscription
az-rbac-watch discover -t <tenant-id> -s <subscription-id> -o policy.yaml

# Multiple subscriptions
az-rbac-watch discover -t <tenant-id> -s <sub-1> -s <sub-2> -o policy.yaml

# From existing policy (re-discover)
az-rbac-watch discover -p existing-policy.yaml -o updated-policy.yaml
```

## Options

| Option | Short | Description |
|--------|-------|-------------|
| `--policy PATH` | `-p` | Existing policy YAML file (optional, uses its scope definition) |
| `--tenant-id ID` | `-t` | Tenant ID (auto-detected if omitted) |
| `--subscription ID` | `-s` | Subscription ID to scan (repeatable) |
| `--management-group ID` | `-m` | Management group ID to scan (repeatable) |
| `--exclude-subscription ID` | | Subscription ID to exclude (repeatable) |
| `--exclude-management-group ID` | | Management group ID to exclude (repeatable) |
| `--output PATH` | `-o` | Output YAML file path (default: `discovered_policy.yaml`) |
| `--verbose` | `-v` | Enable debug logging |
| `--dry-run` | | Show scan plan without making API calls |
| `--debug` | | Show full traceback on error |

## Examples

```bash
# Discover all accessible subscriptions
az-rbac-watch discover -t 0197b94a-021f-4794-8c1e-0a4ac9b304a4 -o policy.yaml

# Discover a specific subscription
az-rbac-watch discover -t <tenant-id> -s 9025917f-064b-4b0d-abac-73281ef2051b -o policy.yaml

# Discover with exclusions
az-rbac-watch discover -t <tenant-id> --exclude-subscription 22222222-2222-2222-2222-222222222222 -o policy.yaml

# Dry run — see what would be scanned
az-rbac-watch discover -t <tenant-id> --dry-run

# Re-discover from an existing policy's scope
az-rbac-watch discover -p old-policy.yaml -o refreshed-policy.yaml
```

## Output format

The generated YAML contains:

- `version: "2.0"`
- `tenant_id` from the scan
- `subscriptions` and `management_groups` that were scanned
- One `baseline` rule per discovered assignment

Example generated rule:

```yaml
rules:
  - name: grp-team-infra-contributor
    type: baseline
    description: "GRP-TEAM-INFRA -- Contributor"
    match:
      principal_id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
      role: Contributor
      scope: /subscriptions/.../resourceGroups/rg-infra
```

## Recommended workflow

1. Run `discover` to capture current state
2. Review the generated YAML
3. Add governance rules manually
4. Use `scan` to detect future drift
5. Use `audit` to check guardrails

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Discovery completed successfully |
| `2` | Error — auth failure, API error |
