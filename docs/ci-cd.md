# CI/CD Integration

## Exit codes

| Code | Meaning | CI action |
|------|---------|-----------|
| `0` | Compliant | Pass |
| `1` | Findings detected | Fail (or warn) |
| `2` | Error (auth, API, invalid YAML) | Fail |

## GitHub Actions

```yaml
name: RBAC Compliance
on:
  schedule:
    - cron: '0 6 * * *'  # Daily at 6 AM UTC
  workflow_dispatch:

permissions:
  id-token: write
  contents: read

jobs:
  rbac-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install az-rbac-watch
        run: pip install az-rbac-watch

      - name: Azure Login
        uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - name: Scan for drift
        run: |
          az-rbac-watch scan -p policy.yaml --format json -o drift.json
          echo "scan_exit=$?" >> $GITHUB_ENV
        continue-on-error: true

      - name: Audit guardrails
        run: |
          az-rbac-watch audit -p policy.yaml --format json -o audit.json
          echo "audit_exit=$?" >> $GITHUB_ENV
        continue-on-error: true

      - name: Upload reports
        uses: actions/upload-artifact@v4
        with:
          name: rbac-reports
          path: |
            drift.json
            audit.json

      - name: Check results
        run: |
          if [ "$scan_exit" = "1" ] || [ "$audit_exit" = "1" ]; then
            echo "::error::RBAC compliance findings detected"
            exit 1
          fi
          if [ "$scan_exit" = "2" ] || [ "$audit_exit" = "2" ]; then
            echo "::error::RBAC scan error"
            exit 2
          fi
```

## Azure DevOps Pipeline

```yaml
trigger: none
schedules:
  - cron: '0 6 * * *'
    displayName: Daily RBAC check
    branches:
      include:
        - main

pool:
  vmImage: ubuntu-latest

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.12'

  - script: pip install az-rbac-watch
    displayName: Install az-rbac-watch

  - task: AzureCLI@2
    displayName: Scan for drift
    inputs:
      azureSubscription: 'your-service-connection'
      scriptType: bash
      scriptLocation: inlineScript
      inlineScript: |
        az-rbac-watch scan -p policy.yaml --format json -o $(Build.ArtifactStagingDirectory)/drift.json

  - task: AzureCLI@2
    displayName: Audit guardrails
    inputs:
      azureSubscription: 'your-service-connection'
      scriptType: bash
      inlineScript: |
        az-rbac-watch audit -p policy.yaml --format json -o $(Build.ArtifactStagingDirectory)/audit.json

  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: $(Build.ArtifactStagingDirectory)
      artifactName: rbac-reports
```

## Parsing JSON output

The JSON output structure:

```json
{
  "summary": {
    "total_assignments": 42,
    "total_findings": 3,
    "by_severity": {
      "critical": 0,
      "high": 2,
      "medium": 1,
      "low": 0,
      "info": 0
    }
  },
  "findings": [
    {
      "type": "GOVERNANCE_VIOLATION",
      "severity": "high",
      "rule_name": "no-direct-users",
      "description": "Users must use groups",
      "assignment": {
        "principal_id": "...",
        "principal_type": "User",
        "role": "Contributor",
        "scope": "/subscriptions/..."
      }
    }
  ],
  "scan_errors": []
}
```

### jq examples

```bash
# Count findings
az-rbac-watch audit -p policy.yaml --format json | jq '.summary.total_findings'

# List high-severity findings
az-rbac-watch audit -p policy.yaml --format json | jq '[.findings[] | select(.severity == "high")]'

# Extract principal IDs with violations
az-rbac-watch audit -p policy.yaml --format json | jq '[.findings[].assignment.principal_id] | unique'

# Check if compliant (exit 0 if no findings)
FINDINGS=$(az-rbac-watch scan -p policy.yaml --format json | jq '.summary.total_findings')
if [ "$FINDINGS" -gt 0 ]; then
  echo "Non-compliant: $FINDINGS findings"
  exit 1
fi
```

## Quiet mode for CI

Use `--quiet` to suppress progress bars and status messages. Only findings and exit codes are emitted:

```bash
az-rbac-watch scan -p policy.yaml --format json --quiet -o drift.json
```

## Validate policy in CI

Add a validation step before scanning to fail fast on invalid YAML:

```bash
az-rbac-watch validate -p policy.yaml
```

This requires no Azure credentials and runs offline.
