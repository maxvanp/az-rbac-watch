# Policy Reference

The policy model is a YAML file that defines:

1. **Which scopes to scan** (subscriptions, management groups)
2. **What is expected** (baseline rules)
3. **What is forbidden** (governance rules)

## Full structure

```yaml
version: "2.0"                          # Required
tenant_id: "xxxxxxxx-xxxx-..."          # Required (UUID)
scope: explicit                          # Optional (default: explicit)

subscriptions:                           # Subscriptions to scan
  - id: "11111111-1111-..."
    name: "Production"

management_groups:                       # Management groups to scan
  - id: "mg-production"
    name: "Production"

exclude_subscriptions:                   # Optional (scope: all only)
  - "22222222-2222-..."

exclude_management_groups:               # Optional (scope: all only)
  - "mg-sandbox"

rules:                                   # Compliance rules
  - name: rule-name
    type: governance
    description: "..."
    severity: high
    remediation: "..."
    match:
      principal_type: User
```

## Header fields

### version

**Required** | Type: `string` | Value: `"2.0"`

```yaml
version: "2.0"
```

### tenant_id

**Required** | Type: `UUID`

Entra ID (Azure AD) tenant identifier.

```yaml
tenant_id: "0197b94a-021f-4794-8c1e-0a4ac9b304a4"
```

Find it with: `az account show --query tenantId -o tsv`

### scope

**Optional** | Type: `string` | Values: `"explicit"` (default), `"all"`

| Mode | Behavior |
|------|----------|
| `explicit` | Only scopes listed in `subscriptions` and `management_groups` are scanned |
| `all` | Auto-discovers all accessible scopes at scan time |

```yaml
# Explicit mode (default) — you list the scopes
scope: explicit
subscriptions:
  - id: "11111111-..."
    name: "Production"

# All mode — auto-discover everything accessible
scope: all
```

`explicit` is recommended for production. `all` is useful for initial discovery or exhaustive scans.

### subscriptions

**Optional** | Type: list of objects

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | UUID | yes | Subscription ID |
| `name` | string | no | Display name (for reports) |

```yaml
subscriptions:
  - id: "9025917f-064b-4b0d-abac-73281ef2051b"
    name: "Production"
  - id: "11111111-1111-1111-1111-111111111111"
    name: "Staging"
```

Scanning a subscription also returns role assignments inherited from parent management groups (standard Azure ARM API behavior).

### management_groups

**Optional** | Type: list of objects

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Management group ID |
| `name` | string | no | Display name |

```yaml
management_groups:
  - id: "mg-production"
    name: "Production"
```

### Exclusions

**Optional** | Type: list of strings | **Only with `scope: all`**

```yaml
scope: all
exclude_subscriptions:
  - "22222222-2222-2222-2222-222222222222"
exclude_management_groups:
  - "mg-legacy"
```

CLI exclusions (`--exclude-subscription`, `--exclude-management-group`) apply on top of YAML exclusions.

## Rules

### Two types of rules

| Type | Purpose | Finding | When to use |
|------|---------|---------|-------------|
| `baseline` | Declares an **expected** assignment | `DRIFT` (HIGH) for any unmatched assignment | Document your permission architecture |
| `governance` | Declares a **forbidden** pattern | `GOVERNANCE_VIOLATION` with the rule's severity | Ban dangerous practices |

Behavior:

- If there is at least one baseline rule, any assignment not matching any baseline = `DRIFT`
- If there are no baseline rules (governance-only), no DRIFT findings are generated
- Governance rules produce a finding for each matched assignment
- An assignment can trigger both: be out-of-baseline AND match a governance rule

Recommended approach:

1. Start with governance rules only (easier to set up)
2. Add baseline rules progressively via `discover`
3. Long-term goal: complete baseline + governance rules = full coverage

### Rule fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | **yes** | -- | Unique identifier (shown in reports) |
| `type` | string | no | `"governance"` | `"baseline"` or `"governance"` |
| `description` | string | no | `""` | Human-readable description |
| `severity` | string | no | `"high"` | Finding severity |
| `remediation` | string | no | `null` | Remediation advice (shown in reports) |
| `match` | object | no | `{}` | Match conditions (see below) |

### Severity levels

| Severity | Recommended use |
|----------|-----------------|
| `critical` | Immediate compromise risk (Owner at subscription scope, guest with Owner) |
| `high` | Major governance violation (direct user assignment, direct SP) |
| `medium` | Practice deviation (custom roles, naming convention) |
| `low` | Worth monitoring |
| `info` | Informational, no action required |

## Match operators

The `match` block contains filter conditions. **All conditions are combined with AND logic.** An empty `match: {}` matches all assignments.

All comparisons are **case-insensitive**.

### Scope operators

| Operator | Type | Description |
|----------|------|-------------|
| `scope` | string | Exact scope match |
| `scope_prefix` | string | Scope starts with value |

```yaml
# Exact: only the subscription itself
match:
  scope: /subscriptions/11111111-1111-1111-1111-111111111111

# Prefix: subscription + all its resource groups/resources
match:
  scope_prefix: /subscriptions/11111111-1111-1111-1111-111111111111

# Prefix: a specific resource group and its resources
match:
  scope_prefix: /subscriptions/11111111-.../resourceGroups/rg-production

# Prefix: a management group and all children
match:
  scope_prefix: /providers/Microsoft.Management/managementGroups/mg-production
```

The trailing slash is automatically stripped.

### Role operators

| Operator | Type | Description |
|----------|------|-------------|
| `role` | string | Exact role name |
| `role_in` | list | Role is in list |
| `role_not_in` | list | Role is NOT in list |
| `role_type` | string | `BuiltInRole` or `CustomRole` |

```yaml
# Exact role
match:
  role: Owner

# Whitelist
match:
  role_in:
    - Reader
    - Contributor

# Blacklist
match:
  role_not_in:
    - Reader
    - Contributor

# All custom roles
match:
  role_type: CustomRole
```

### Principal operators

| Operator | Type | Description |
|----------|------|-------------|
| `principal_type` | string | `User`, `Group`, `ServicePrincipal`, `ForeignGroup`, `Device` |
| `principal_type_in` | list | Principal type is in list |
| `principal_id` | string | Exact principal UUID |

```yaml
# All users
match:
  principal_type: User

# Users and service principals
match:
  principal_type_in:
    - User
    - ServicePrincipal

# Specific principal (for baseline)
match:
  principal_id: "5dbfb716-7c4e-4825-865d-13b64957b3a5"
```

### Display name operators

These require Graph API access (`Directory.Read.All`). If name resolution fails, they evaluate to `false` (no false positives).

| Operator | Type | Description |
|----------|------|-------------|
| `principal_name_prefix` | string | Display name starts with |
| `principal_name_not_prefix` | string | Display name does NOT start with |
| `principal_name_contains` | string | Display name contains |
| `principal_name_not_contains` | string | Display name does NOT contain |

```yaml
# Groups not starting with AZ_
match:
  principal_type: Group
  principal_name_not_prefix: "AZ_"

# Groups containing "TEMP"
match:
  principal_type: Group
  principal_name_contains: "TEMP"

# Service principals starting with "SP_"
match:
  principal_type: ServicePrincipal
  principal_name_prefix: "SP_"
```

### Combining operators (AND)

All conditions are AND-combined:

```yaml
# Owner at subscription scope
match:
  scope_prefix: /subscriptions/
  role: Owner

# Custom roles on Production subscription only
match:
  scope_prefix: /subscriptions/11111111-1111-1111-1111-111111111111
  role_type: CustomRole

# Non-AZ_ groups with Owner role
match:
  principal_type: Group
  principal_name_not_prefix: "AZ_"
  role: Owner
```

There is no OR operator. For OR logic, create separate rules.

## Example: governance-only policy

```yaml
version: "2.0"
tenant_id: "0197b94a-021f-4794-8c1e-0a4ac9b304a4"
subscriptions:
  - id: "9025917f-064b-4b0d-abac-73281ef2051b"
    name: "Production"

rules:
  - name: no-direct-users
    type: governance
    severity: high
    description: "Users must use groups"
    remediation: "Add user to an Entra group and assign the role to the group"
    match:
      principal_type: User

  - name: groups-naming
    type: governance
    severity: medium
    description: "Groups must start with AZ_"
    remediation: "Rename group with AZ_ prefix"
    match:
      principal_type: Group
      principal_name_not_prefix: "AZ_"
```

## Example: scope: all with exclusions

```yaml
version: "2.0"
tenant_id: "0197b94a-021f-4794-8c1e-0a4ac9b304a4"
scope: all

exclude_subscriptions:
  - "22222222-2222-2222-2222-222222222222"
exclude_management_groups:
  - "mg-legacy"

rules:
  - name: no-direct-users
    type: governance
    severity: high
    match:
      principal_type: User
```
