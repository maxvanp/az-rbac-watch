# validate

Validate a policy model YAML file offline — no Azure credentials needed.

## Usage

```bash
az-rbac-watch validate -p policy.yaml
```

## Options

| Option | Short | Description |
|--------|-------|-------------|
| `--policy PATH` | `-p` | Policy model YAML file to validate (required) |

## What it checks

- YAML syntax
- Required fields (`version`, `tenant_id`)
- Version format (must be `"2.0"`)
- UUID format for `tenant_id` and subscription IDs
- Rule structure: valid `type`, `severity`, and `match` operators
- Match operator conflicts (e.g., `role` and `role_in` on the same rule)
- Scope mode validity (`explicit` or `all`)

## Examples

```bash
# Validate a policy file
az-rbac-watch validate -p policy.yaml

# Output on success:
# Policy model valid — version 2.0
#   Scope                : explicit
#   Subscriptions        : 2
#   Management groups    : 0
#   Rules                : 15 (10 baseline, 5 governance)
```

```bash
# Invalid file — shows validation errors
az-rbac-watch validate -p broken.yaml
# Validation error: version must be "2.0"
```

## Use cases

- **Pre-commit hook**: validate policy files before committing
- **CI pipeline**: fail early if policy syntax is wrong
- **Local development**: check YAML before running scan/audit

```bash
# Pre-commit usage
az-rbac-watch validate -p policy.yaml || exit 1
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Policy is valid |
| `2` | Validation error — invalid YAML, missing fields, bad structure |
