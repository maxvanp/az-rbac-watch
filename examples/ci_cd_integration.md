# CI/CD Integration Guide

Run az-rbac-watch in your CI/CD pipeline to automatically detect RBAC drift and governance violations.

## Exit Codes

| Code | Meaning | Pipeline action |
|------|---------|-----------------|
| `0` | Compliant — no findings | Pass |
| `1` | Findings detected | Fail (or warn, depending on policy) |
| `2` | Error (scan failure, invalid config) | Fail |

## Service Principal Setup

Your CI/CD runner needs a service principal with:

1. **Reader** role on each subscription/management group to scan
2. **Directory.Read.All** application permission in Microsoft Graph (for resolving principal names)

```bash
# Create the service principal
az ad sp create-for-rbac --name "sp-rbac-watch-ci" --role Reader \
  --scopes /subscriptions/<subscription-id>

# Grant Graph API permission (requires Global Admin or Privileged Role Admin)
az ad app permission add --id <app-id> \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions 7ab1d382-f21e-4acd-a863-ba3e13f7da61=Role

az ad app permission admin-consent --id <app-id>
```

For GitHub Actions, use [federated identity credentials](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust) (OIDC) instead of client secrets.

## GitHub Actions

### Scheduled compliance scan (recommended)

```yaml
# .github/workflows/rbac-scan.yml
name: RBAC Compliance Scan

on:
  schedule:
    - cron: "0 6 * * 1"  # Every Monday at 6:00 UTC
  workflow_dispatch:       # Manual trigger

permissions:
  id-token: write  # Required for OIDC authentication
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    environment: azure-rbac-watch

    steps:
      - uses: actions/checkout@v4

      - name: Azure Login (OIDC)
        uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - name: Install az-rbac-watch
        run: pip install az-rbac-watch

      - name: Validate policy
        run: az-rbac-watch validate -p policy.yaml

      - name: Run compliance scan
        run: az-rbac-watch scan -p policy.yaml --format console
```

### PR gate — validate policy changes

```yaml
# .github/workflows/rbac-validate.yml
name: Validate RBAC Policy

on:
  pull_request:
    paths:
      - "policy.yaml"
      - "policy_*.yaml"

jobs:
  validate:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Install az-rbac-watch
        run: pip install az-rbac-watch

      - name: Validate policy syntax
        run: |
          for f in policy*.yaml; do
            echo "Validating $f..."
            az-rbac-watch validate -p "$f"
          done
```

## Azure DevOps

### Scheduled scan pipeline

```yaml
# azure-pipelines-rbac-scan.yml
trigger: none

schedules:
  - cron: "0 6 * * 1"
    displayName: "Weekly RBAC scan"
    branches:
      include:
        - main

pool:
  vmImage: "ubuntu-latest"

steps:
  - task: AzureCLI@2
    displayName: "Run RBAC compliance scan"
    inputs:
      azureSubscription: "rbac-watch-service-connection"
      scriptType: "bash"
      scriptLocation: "inlineScript"
      inlineScript: |
        pip install az-rbac-watch
        az-rbac-watch validate -p policy.yaml
        az-rbac-watch scan -p policy.yaml --format console
```

## Generating reports in CI

```bash
# JSON report for programmatic processing
az-rbac-watch scan -p policy.yaml --format json -o rbac-report.json

# HTML report as build artifact
az-rbac-watch scan -p policy.yaml --format html -o rbac-report.html
```

Upload the HTML report as a build artifact for easy review:

```yaml
# GitHub Actions
- name: Upload report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: rbac-compliance-report
    path: rbac-report.html
```
