# snapshot

Capture a full RBAC snapshot as JSON.

The snapshot contains assignments, role definitions, and scope metadata so you can compare two moments in time later with `diff`.

## Usage

```bash
# From a policy file
az-rbac-watch snapshot -p policy.yaml -o snapshot.json

# From explicit scopes
az-rbac-watch snapshot -t <tenant-id> -s <subscription-id> -o snapshot.json
```

## Options

| Option | Short | Description |
|--------|-------|-------------|
| `--policy PATH` | `-p` | Policy YAML file (uses its scopes) |
| `--tenant-id ID` | `-t` | Tenant ID |
| `--subscription ID` | `-s` | Subscription ID to scan (repeatable) |
| `--management-group ID` | `-m` | Management group ID to scan (repeatable) |
| `--exclude-subscription ID` | | Subscription ID to exclude (repeatable) |
| `--exclude-management-group ID` | | Management group ID to exclude (repeatable) |
| `--output PATH` | `-o` | Output JSON file path (required) |
| `--verbose` | `-v` | Enable verbose logging |
| `--debug` | | Show full traceback on error |

`--policy` and `--subscription`/`--management-group` are mutually exclusive.

## Examples

```bash
# Snapshot from a baseline policy
az-rbac-watch snapshot -p policy.yaml -o snapshot-2026-04-11.json

# Snapshot one subscription directly
az-rbac-watch snapshot -t <tenant-id> -s 11111111-1111-1111-1111-111111111111 -o snapshot.json

# Snapshot with exclusions
az-rbac-watch snapshot -p policy.yaml --exclude-subscription 22222222-2222-2222-2222-222222222222 -o snapshot.json
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Snapshot created successfully |
| `2` | Error — auth failure, API error, invalid arguments |
