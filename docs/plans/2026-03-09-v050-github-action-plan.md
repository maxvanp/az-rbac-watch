# v0.5.0 — GitHub Action Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Provide a reusable GitHub composite action and example workflows for CI/CD integration.

**Architecture:** Single composite action at repo root (`action.yml`) with a `mode` input that maps to CLI commands. Three example workflows demonstrate scheduled scan, PR validation, and snapshot diff. A CI test validates the action works in `validate` mode.

**Tech Stack:** GitHub Actions composite action (YAML + shell), `actions/setup-python`, `pip install az-rbac-watch`

---

### Task 1: Create composite action (`action.yml`)

**Files:**
- Create: `action.yml`

**Step 1: Write `action.yml`**

```yaml
name: "Azure Permissions Watch"
description: "RBAC compliance monitoring — detect permission drift and governance violations"
branding:
  icon: "shield"
  color: "blue"

inputs:
  mode:
    description: "Command to run: scan, audit, validate, snapshot, diff"
    required: true
  policy:
    description: "Path to policy YAML file"
    required: false
  tenant-id:
    description: "Azure tenant ID"
    required: false
  subscriptions:
    description: "Subscription IDs (comma-separated)"
    required: false
  management-groups:
    description: "Management group IDs (comma-separated)"
    required: false
  format:
    description: "Output format: console or json"
    required: false
    default: "console"
  output:
    description: "Output file path"
    required: false
  old-snapshot:
    description: "Path to old snapshot (diff mode)"
    required: false
  new-snapshot:
    description: "Path to new snapshot (diff mode)"
    required: false
  python-version:
    description: "Python version to use"
    required: false
    default: "3.12"
  extra-args:
    description: "Additional CLI arguments"
    required: false

outputs:
  exit-code:
    description: "Command exit code (0=compliant, 1=findings, 2=error)"
    value: ${{ steps.run.outputs.exit-code }}
  report-path:
    description: "Path to generated report"
    value: ${{ steps.run.outputs.report-path }}

runs:
  using: "composite"
  steps:
    - name: Setup Python
      uses: actions/setup-python@v5
      with:
        python-version: ${{ inputs.python-version }}

    - name: Install az-rbac-watch
      shell: bash
      run: pip install az-rbac-watch

    - name: Run az-rbac-watch
      id: run
      shell: bash
      run: |
        # Build command
        CMD="az-rbac-watch ${{ inputs.mode }}"

        # Mode-specific positional args (diff)
        if [ "${{ inputs.mode }}" = "diff" ]; then
          CMD="$CMD ${{ inputs.old-snapshot }} ${{ inputs.new-snapshot }}"
        fi

        # Optional flags
        if [ -n "${{ inputs.policy }}" ]; then
          CMD="$CMD --policy ${{ inputs.policy }}"
        fi
        if [ -n "${{ inputs.tenant-id }}" ]; then
          CMD="$CMD --tenant-id ${{ inputs.tenant-id }}"
        fi
        if [ -n "${{ inputs.subscriptions }}" ]; then
          IFS=',' read -ra SUBS <<< "${{ inputs.subscriptions }}"
          for sub in "${SUBS[@]}"; do
            CMD="$CMD --subscription $(echo "$sub" | xargs)"
          done
        fi
        if [ -n "${{ inputs.management-groups }}" ]; then
          IFS=',' read -ra MGS <<< "${{ inputs.management-groups }}"
          for mg in "${MGS[@]}"; do
            CMD="$CMD --management-group $(echo "$mg" | xargs)"
          done
        fi
        if [ "${{ inputs.format }}" != "console" ]; then
          CMD="$CMD --format ${{ inputs.format }}"
        fi
        if [ -n "${{ inputs.output }}" ]; then
          CMD="$CMD --output ${{ inputs.output }}"
        fi
        if [ -n "${{ inputs.extra-args }}" ]; then
          CMD="$CMD ${{ inputs.extra-args }}"
        fi

        echo "Running: $CMD"
        set +e
        eval "$CMD"
        EXIT_CODE=$?
        set -e

        echo "exit-code=$EXIT_CODE" >> "$GITHUB_OUTPUT"
        if [ -n "${{ inputs.output }}" ]; then
          echo "report-path=${{ inputs.output }}" >> "$GITHUB_OUTPUT"
        fi

        exit $EXIT_CODE
```

**Step 2: Commit**

```bash
git add action.yml
git commit -m "feat: add composite GitHub Action"
```

---

### Task 2: Create scheduled scan example workflow

**Files:**
- Create: `examples/workflows/rbac-scheduled-scan.yml`

**Step 1: Write the workflow**

```yaml
# Copy this file to .github/workflows/rbac-scheduled-scan.yml in your repository.
#
# Prerequisites:
#   1. Azure AD app registration with federated credential for GitHub Actions
#   2. App needs: Microsoft.Authorization/roleAssignments/read on scanned scopes
#   3. Repository secrets: AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID
#   4. A policy.yaml file in your repository root (or adjust the path below)

name: RBAC Scheduled Scan

on:
  schedule:
    - cron: "0 6 * * *"  # Daily at 06:00 UTC
  workflow_dispatch:       # Allow manual trigger

permissions:
  id-token: write   # OIDC token for azure/login
  contents: read

jobs:
  rbac-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Azure Login (OIDC)
        uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - name: Scan for drift
        uses: maxvanp/az-rbac-watch@v0.5.0
        with:
          mode: scan
          policy: policy.yaml
          format: json
          output: drift-report.json

      - name: Audit governance rules
        if: always()
        uses: maxvanp/az-rbac-watch@v0.5.0
        with:
          mode: audit
          policy: policy.yaml
          format: json
          output: audit-report.json

      - name: Upload reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: rbac-reports-${{ github.run_id }}
          path: |
            drift-report.json
            audit-report.json
          retention-days: 90
```

**Step 2: Commit**

```bash
git add examples/workflows/rbac-scheduled-scan.yml
git commit -m "docs: add scheduled scan example workflow"
```

---

### Task 3: Create PR check example workflow

**Files:**
- Create: `examples/workflows/rbac-pr-check.yml`

**Step 1: Write the workflow**

```yaml
# Copy this file to .github/workflows/rbac-pr-check.yml in your repository.
#
# Validates policy YAML files on pull requests. No Azure credentials needed.

name: RBAC Policy Validation

on:
  pull_request:
    paths:
      - "**/policy*.yaml"
      - "**/policy*.yml"

jobs:
  validate-policy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Validate policy
        uses: maxvanp/az-rbac-watch@v0.5.0
        with:
          mode: validate
          policy: policy.yaml
```

**Step 2: Commit**

```bash
git add examples/workflows/rbac-pr-check.yml
git commit -m "docs: add PR check example workflow"
```

---

### Task 4: Create snapshot diff example workflow

**Files:**
- Create: `examples/workflows/rbac-snapshot-diff.yml`

**Step 1: Write the workflow**

```yaml
# Copy this file to .github/workflows/rbac-snapshot-diff.yml in your repository.
#
# Takes a weekly RBAC snapshot and compares it against the previous one.
# If changes are detected (exit code 1), the workflow fails and GitHub sends a notification.
#
# Prerequisites:
#   1. Azure AD app registration with federated credential for GitHub Actions
#   2. App needs: Microsoft.Authorization/roleAssignments/read on scanned scopes
#   3. Repository secrets: AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID
#   4. A policy.yaml file in your repository root (or adjust the path below)

name: RBAC Snapshot Diff

on:
  schedule:
    - cron: "0 7 * * 1"  # Weekly on Monday at 07:00 UTC
  workflow_dispatch:

permissions:
  id-token: write
  contents: read

jobs:
  snapshot-diff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Azure Login (OIDC)
        uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - name: Install az-rbac-watch
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install az-rbac-watch

      - name: Download previous snapshot
        id: download
        uses: actions/download-artifact@v4
        with:
          name: rbac-latest-snapshot
          path: previous/
        continue-on-error: true

      - name: Take new snapshot
        uses: maxvanp/az-rbac-watch@v0.5.0
        with:
          mode: snapshot
          policy: policy.yaml
          output: current-snapshot.json

      - name: Compare snapshots
        if: steps.download.outcome == 'success'
        uses: maxvanp/az-rbac-watch@v0.5.0
        with:
          mode: diff
          old-snapshot: previous/current-snapshot.json
          new-snapshot: current-snapshot.json
          format: json
          output: diff-report.json

      - name: Upload current snapshot
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: rbac-latest-snapshot
          path: current-snapshot.json
          retention-days: 90
          overwrite: true

      - name: Upload diff report
        if: steps.download.outcome == 'success' && always()
        uses: actions/upload-artifact@v4
        with:
          name: rbac-diff-report-${{ github.run_id }}
          path: diff-report.json
          retention-days: 90
```

**Step 2: Commit**

```bash
git add examples/workflows/rbac-snapshot-diff.yml
git commit -m "docs: add snapshot diff example workflow"
```

---

### Task 5: Add CI test for the action

**Files:**
- Create: `.github/workflows/test-action.yml`

**Step 1: Write the CI test workflow**

This workflow tests the composite action using `validate` mode (no Azure auth needed).

```yaml
name: Test Action

on:
  push:
    branches: [main]
    paths:
      - "action.yml"
  pull_request:
    branches: [main]
    paths:
      - "action.yml"

jobs:
  test-validate-mode:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Test validate mode (valid policy)
        uses: ./
        with:
          mode: validate
          policy: examples/policy_model.yaml

      - name: Test validate mode (invalid policy)
        id: invalid
        uses: ./
        with:
          mode: validate
          policy: examples/deny_rules_starter.yaml
          extra-args: "--debug"
        continue-on-error: true

      - name: Verify invalid policy was detected
        shell: bash
        run: |
          if [ "${{ steps.invalid.outcome }}" = "success" ]; then
            echo "Expected validation to fail for deny_rules_starter.yaml"
          fi
```

**Step 2: Commit**

```bash
git add .github/workflows/test-action.yml
git commit -m "ci: add integration test for composite action"
```

---

### Task 6: Update README

**Files:**
- Modify: `README.md`

**Step 1: Add GitHub Actions section after the "Troubleshooting" section**

Add the following section before "## Rule match operators":

```markdown
## GitHub Actions

Use the composite action to integrate az-rbac-watch into your CI/CD pipelines.

### Basic usage

```yaml
- uses: maxvanp/az-rbac-watch@v0.5.0
  with:
    mode: scan
    policy: policy.yaml
    format: json
    output: report.json
```

### Available modes

| Mode | Description | Azure auth required |
|------|-------------|---------------------|
| `scan` | Detect RBAC drift against baseline rules | Yes |
| `audit` | Check governance guardrails | Yes |
| `validate` | Validate policy YAML syntax (offline) | No |
| `snapshot` | Capture RBAC snapshot | Yes |
| `diff` | Compare two snapshots | No |

### Example workflows

Ready-to-use workflow templates are available in [`examples/workflows/`](examples/workflows/):

- **[`rbac-scheduled-scan.yml`](examples/workflows/rbac-scheduled-scan.yml)** — Daily scan + audit with artifact reports
- **[`rbac-pr-check.yml`](examples/workflows/rbac-pr-check.yml)** — Validate policy files on pull requests
- **[`rbac-snapshot-diff.yml`](examples/workflows/rbac-snapshot-diff.yml)** — Weekly snapshot comparison with change detection

Copy the desired workflow to `.github/workflows/` in your repository and configure the required secrets.

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `mode` | yes | — | Command: `scan`, `audit`, `validate`, `snapshot`, `diff` |
| `policy` | no | — | Path to policy YAML file |
| `tenant-id` | no | — | Azure tenant ID |
| `subscriptions` | no | — | Subscription IDs (comma-separated) |
| `management-groups` | no | — | Management group IDs (comma-separated) |
| `format` | no | `console` | Output format: `console` or `json` |
| `output` | no | — | Output file path |
| `old-snapshot` | no | — | Old snapshot path (diff mode) |
| `new-snapshot` | no | — | New snapshot path (diff mode) |
| `python-version` | no | `3.12` | Python version |
| `extra-args` | no | — | Additional CLI arguments |

### Outputs

| Output | Description |
|--------|-------------|
| `exit-code` | `0` = compliant, `1` = findings/changes, `2` = error |
| `report-path` | Path to generated report (if `output` is set) |
```

**Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add GitHub Actions section to README"
```

---

### Task 7: Final verification

**Step 1: Run linters**

```bash
ruff check .
ruff format --check .
```

Expected: PASS (no Python changes)

**Step 2: Run tests**

```bash
pytest --cov=az_rbac_watch --cov-fail-under=80
```

Expected: PASS (no Python changes)

**Step 3: Validate YAML syntax of all new files**

```bash
python -c "
import yaml
for f in ['action.yml', 'examples/workflows/rbac-scheduled-scan.yml', 'examples/workflows/rbac-pr-check.yml', 'examples/workflows/rbac-snapshot-diff.yml', '.github/workflows/test-action.yml']:
    with open(f) as fh:
        yaml.safe_load(fh)
    print(f'{f}: OK')
"
```

Expected: All OK

**Step 4: Verify action references are consistent**

Check that example workflows reference `maxvanp/az-rbac-watch@v0.5.0` and the CI test uses `./`.
