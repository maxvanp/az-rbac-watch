# v0.4.0 — Change Tracking

**Date:** 2026-03-08
**Status:** Approved
**Goal:** Track RBAC changes over time by capturing tenant state snapshots and comparing them offline.

## Concept

Two new commands, independent from the existing scan/audit workflow:
- **`snapshot`** — scans a tenant and saves the raw state (assignments, role definitions, principal names) to a JSON file
- **`diff`** — compares two snapshots offline and displays changes

## Commande `snapshot`

```bash
# Auto-discovery (all accessible subscriptions)
az-rbac-watch snapshot -t <tenant-id> -o state.json

# Explicit scopes
az-rbac-watch snapshot -t <tenant-id> -s <sub-id> -o state.json

# Via policy file (reuses scopes from policy)
az-rbac-watch snapshot -p policy.yaml -o state.json
```

The JSON file contains:
- Metadata: timestamp, tenant_id, tool version, scopes scanned
- Complete list of assignments (id, scope, role_name, role_type, principal_id, principal_type, principal_display_name)
- List of role definitions (id, role_name, role_type)

## Command `diff`

```bash
# Compare two snapshots (offline, no Azure credentials needed)
az-rbac-watch diff state-monday.json state-tuesday.json

# JSON format for CI/CD
az-rbac-watch diff state-monday.json state-tuesday.json --format json
```

Console output: Rich table with:
- **Added** (green) — new assignments
- **Removed** (red) — deleted assignments
- **Modified** (yellow) — role, scope, or principal name changes on the same assignment ID

Exit codes: 0 = no changes, 1 = changes detected, 2 = error

## Snapshot file format

```json
{
  "version": "1.0",
  "tool_version": "0.4.0",
  "timestamp": "2026-03-08T12:00:00Z",
  "tenant_id": "...",
  "scopes": {
    "subscriptions": [{"id": "...", "name": "..."}],
    "management_groups": [{"id": "...", "name": "..."}]
  },
  "assignments": [
    {
      "id": "...",
      "scope": "...",
      "role_name": "...",
      "role_type": "BuiltInRole",
      "principal_id": "...",
      "principal_type": "User",
      "principal_display_name": "..."
    }
  ],
  "role_definitions": [
    {
      "id": "...",
      "role_name": "...",
      "role_type": "BuiltInRole"
    }
  ]
}
```

## What does not change

- Commands `scan`, `audit`, `discover`, `validate` unchanged
- Policy model unchanged (version "2.0")
- No automatic persistence — user decides when and where to save

## Typical CI/CD workflow

```yaml
- run: az-rbac-watch snapshot -t $TENANT_ID -o current.json
- run: az-rbac-watch diff previous.json current.json --format json -o changes.json
- run: cp current.json previous.json
```

## Out of scope

- Inline diff in scan/audit reports (planned for v0.5.0)
- Database storage
- Automatic scheduling
