# Architecture

## Module overview

```
src/az_rbac_watch/
├── cli.py                    # Typer CLI entry point (scan, audit, discover, validate)
├── auth/
│   └── azure_clients.py      # Azure credential management, Graph API name resolution
├── config/
│   ├── policy_model.py       # Pydantic v2 policy schema, YAML parsing/validation
│   ├── settings.py           # User settings (config file + env vars)
│   └── default_rules.py      # Built-in governance rules for ad-hoc mode
├── scanner/
│   ├── rbac_scanner.py       # Parallel RBAC scanning (ThreadPoolExecutor)
│   └── discovery.py          # Generate policy from existing RBAC assignments
├── analyzers/
│   └── compliance.py         # Two-pass compliance engine (governance → baseline)
├── reporters/
│   ├── console_report.py     # Rich terminal output
│   ├── html_report.py        # Single-file HTML with Jinja2
│   └── json_report.py        # Machine-readable JSON
└── utils/
    └── scope.py              # Azure ARM scope parsing helpers
```

## Scan flow

1. **Load policy** — parse YAML, validate with Pydantic v2
2. **Resolve scopes** — if `scope: all`, auto-discover subscriptions and management groups
3. **Apply exclusions** — filter out excluded scopes (from YAML and CLI flags)
4. **Scan RBAC** — parallel scan using `ThreadPoolExecutor` (default 4 workers)
5. **Resolve names** — call Graph API for display name resolution (graceful degradation if unavailable)
6. **Analyze compliance** — two-pass engine produces findings
7. **Output report** — console, HTML, or JSON

## Two-pass compliance engine

The compliance engine in `analyzers/compliance.py` runs two sequential passes:

### Pass 1: Governance rules

For each scanned assignment, every governance rule is evaluated. If the `match` conditions are satisfied, a `GOVERNANCE_VIOLATION` finding is created with the rule's severity.

One assignment can violate multiple governance rules.

### Pass 2: Baseline gating

If at least one baseline rule exists in the policy:

- Each assignment is tested against all baseline rules
- If no baseline rule matches, a `DRIFT` finding is created (severity: HIGH)
- If at least one baseline rule matches, the assignment is considered compliant (for baseline purposes)

If no baseline rules exist, this pass is skipped (governance-only mode).

### Result matrix

| Situation | Finding |
|-----------|---------|
| Assignment matches a governance rule | `GOVERNANCE_VIOLATION` (rule's severity) |
| Assignment matches no baseline rule | `DRIFT` (HIGH) |
| Assignment matches both governance + no baseline | Both findings created |
| Assignment matches baseline, no governance | Compliant (no finding) |

## Rule matching (14 operators)

All match conditions are AND-combined. An empty `match: {}` matches everything. All comparisons are case-insensitive.

| Operator | Type | Description |
|----------|------|-------------|
| `scope` | string | Exact scope match |
| `scope_prefix` | string | Scope starts with value |
| `role` | string | Exact role name |
| `role_in` | list | Role is in list |
| `role_not_in` | list | Role is NOT in list |
| `role_type` | string | `BuiltInRole` or `CustomRole` |
| `principal_type` | string | `User`, `Group`, `ServicePrincipal` |
| `principal_type_in` | list | Principal type is in list |
| `principal_id` | string | Exact principal UUID |
| `principal_name_prefix` | string | Display name starts with |
| `principal_name_not_prefix` | string | Display name does NOT start with |
| `principal_name_contains` | string | Display name contains |
| `principal_name_not_contains` | string | Display name does NOT contain |

Name-based operators require Graph API access. If unavailable, they evaluate to `false` (no false positives).

Performance: match operators use pre-computed frozensets for list-based comparisons.

## Deduplication

When scanning both management groups and subscriptions, the same assignment can appear at both levels (inherited from the management group). The scanner deduplicates: management group assignments take priority over subscription-level duplicates.

## Parallel scanning

RBAC scanning uses `ThreadPoolExecutor` with 4 workers by default. Each scope (subscription or management group) is scanned in a separate thread. Scan errors are collected in the result (not raised), so scanning continues past individual scope failures.

## Authentication

Uses `DefaultAzureCredential` from the Azure SDK, which tries (in order):

1. Environment variables (`AZURE_CLIENT_ID`, etc.)
2. Managed identity
3. Azure CLI (`az login`)
4. Visual Studio Code
5. Azure PowerShell

The credential is lazily initialized as a singleton.

## Required Azure permissions

| Permission | Scope | Purpose |
|------------|-------|---------|
| `Microsoft.Authorization/roleAssignments/read` | Each scanned scope | Read RBAC assignments |
| `Directory.Read.All` | Microsoft Graph | Resolve display names (optional) |
