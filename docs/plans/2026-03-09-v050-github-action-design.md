# v0.5.0 — GitHub Action (Composite)

## Goal

Provide a reusable GitHub composite action so users can integrate az-rbac-watch into their CI/CD pipelines without writing boilerplate. Three example workflows demonstrate the main use cases.

## Decisions

- **Composite action** (not Docker) — simple, fast, no container overhead
- **Single action with `mode` input** — one `action.yml` at repo root, covers all commands
- **No built-in alerting** — rely on GitHub native notifications (workflow failure → email/Slack)
- **Snapshots stored as GitHub artifacts** — no commits to the repo
- **Authentication handled by the user** — `azure/login` action before calling az-rbac-watch

## Composite Action (`action.yml`)

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `mode` | yes | — | `scan`, `audit`, `validate`, `snapshot`, `diff` |
| `policy` | no | — | Path to policy YAML file |
| `tenant-id` | no | — | Azure tenant ID |
| `subscriptions` | no | — | Subscription IDs (comma-separated) |
| `management-groups` | no | — | Management group IDs (comma-separated) |
| `format` | no | `console` | `console` or `json` |
| `output` | no | — | Output file path |
| `old-snapshot` | no | — | Old snapshot path (diff mode) |
| `new-snapshot` | no | — | New snapshot path (diff mode) |
| `python-version` | no | `3.12` | Python version to use |
| `extra-args` | no | — | Additional CLI arguments |

### Outputs

| Output | Description |
|--------|-------------|
| `exit-code` | Command exit code (0, 1, 2) |
| `report-path` | Path to generated report (if `output` is set) |

### Steps

1. Setup Python via `actions/setup-python`
2. `pip install az-rbac-watch`
3. Build CLI command from inputs
4. Execute command, capture exit code
5. Set outputs

## Example Workflows

### Scheduled Scan (`rbac-scheduled-scan.yml`)

- **Trigger**: `schedule` (cron, e.g. daily at 06:00 UTC)
- **Steps**:
  1. `azure/login` with OIDC federated credentials
  2. `az-rbac-watch` mode `scan`, format `json`, output to file
  3. `az-rbac-watch` mode `audit`, format `json`, output to file
  4. Upload reports as artifacts
- Exit code 1 → workflow fails → GitHub notifications fire

### PR Check (`rbac-pr-check.yml`)

- **Trigger**: `pull_request` on paths `**/policy*.yaml`
- **Steps**:
  1. `az-rbac-watch` mode `validate` on modified policy file
- No Azure auth needed — offline validation only

### Snapshot Diff (`rbac-snapshot-diff.yml`)

- **Trigger**: `schedule` (weekly or daily)
- **Steps**:
  1. `azure/login`
  2. Download previous snapshot from GitHub artifacts
  3. `az-rbac-watch` mode `snapshot` → new snapshot
  4. `az-rbac-watch` mode `diff` → compare old vs new
  5. Upload new snapshot + diff report as artifacts
- Exit code 1 (changes detected) → workflow fails

## File Structure

```
action.yml                              # Composite action (repo root)
examples/
├── workflows/
│   ├── rbac-scheduled-scan.yml         # Scheduled scan + audit
│   ├── rbac-pr-check.yml              # PR validation
│   └── rbac-snapshot-diff.yml         # Snapshot diff
├── policy_model.yaml                   # (existing)
└── deny_rules_starter.yaml             # (existing)
```

## In Scope

- `action.yml` composite action
- 3 example workflows
- README update (GitHub Actions section)
- CI test: workflow that runs the action in `validate` mode (no Azure auth)

## Out of Scope

- GitHub Marketplace publication
- Built-in alerting/notifications
- Web dashboard
- Azure DevOps support
