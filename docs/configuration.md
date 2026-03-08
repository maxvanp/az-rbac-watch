# Configuration

## Config file

Default location: `~/.config/az-rbac-watch/config.yaml`

Override with the `AZ_RBAC_WATCH_CONFIG` environment variable:

```bash
export AZ_RBAC_WATCH_CONFIG=/path/to/custom-config.yaml
```

### Format

```yaml
policy: /path/to/policy.yaml
format: console    # or json
quiet: false
no_color: false
```

All fields are optional. Only set what you want to override.

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `policy` | string | `null` | Default policy file path |
| `format` | string | `console` | Output format: `console` or `json` |
| `quiet` | bool | `false` | Suppress all output except findings and exit code |
| `no_color` | bool | `false` | Disable colored output |

## Environment variables

| Variable | Maps to | Example |
|----------|---------|---------|
| `AZ_RBAC_WATCH_POLICY` | `policy` | `/home/user/policy.yaml` |
| `AZ_RBAC_WATCH_FORMAT` | `format` | `json` |
| `AZ_RBAC_WATCH_QUIET` | `quiet` | `1`, `true`, `yes` |
| `AZ_RBAC_WATCH_NO_COLOR` | `no_color` | `1`, `true`, `yes` |
| `AZ_RBAC_WATCH_CONFIG` | config file path | `/path/to/config.yaml` |
| `NO_COLOR` | `no_color` | (any non-empty value) |

Boolean env vars accept: `1`, `true`, `yes` (case-insensitive).

`NO_COLOR` follows the [no-color.org](https://no-color.org/) convention.

## Precedence order

From lowest to highest priority:

1. **Defaults** — built-in values
2. **Config file** — `~/.config/az-rbac-watch/config.yaml`
3. **Environment variables** — `AZ_RBAC_WATCH_*`
4. **CLI flags** — `--policy`, `--format`, `--quiet`, `--no-color`

CLI flags always win.

## Policy auto-detection

When no `--policy` flag is provided and no `-s`/`-m` ad-hoc flags are used, the CLI searches the current directory for:

1. `policy.yaml`
2. `.az-rbac-watch.yaml`
3. `az-rbac-watch.yaml`

This happens after config file and env var resolution. If `AZ_RBAC_WATCH_POLICY` is set, auto-detection is skipped.

## Examples

### CI/CD: JSON output by default

```bash
export AZ_RBAC_WATCH_FORMAT=json
export AZ_RBAC_WATCH_POLICY=/opt/policy.yaml
az-rbac-watch scan
az-rbac-watch audit
```

### Local dev: config file

```yaml
# ~/.config/az-rbac-watch/config.yaml
policy: ~/projects/infra/policy.yaml
```

```bash
# No flags needed — picks up the config
az-rbac-watch scan
az-rbac-watch audit
```
