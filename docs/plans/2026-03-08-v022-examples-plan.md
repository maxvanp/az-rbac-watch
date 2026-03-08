# v0.2.2 Real-World Examples — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add 4 practical example files (3 YAML policies + 1 CI/CD guide) covering small teams, enterprise landing zones, compliance frameworks, and CI/CD integration.

**Architecture:** Pure content — no code changes. Each YAML file must pass `az-rbac-watch validate`. Uses the same policy model schema (version 2.0) as existing examples.

**Tech Stack:** YAML, Markdown, az-rbac-watch CLI for validation.

---

## Task 1: Create `examples/small_team.yaml`

**Files:**
- Create: `examples/small_team.yaml`

**Step 1:** Create the file with this exact content:

```yaml
# az-rbac-watch — Small Team Policy
#
# A minimal policy for a small team (5-10 people) with one subscription.
# Copy this file, replace the placeholder IDs with your real values,
# and run: az-rbac-watch scan -p small_team.yaml
#
# How to find your IDs:
#   Tenant ID:       az account show --query tenantId -o tsv
#   Subscription ID: az account show --query id -o tsv
#   Principal IDs:   az ad group show --group "MyGroup" --query id -o tsv

version: "2.0"

tenant_id: "00000000-0000-0000-0000-000000000000"

scope: explicit

subscriptions:
  - id: "11111111-1111-1111-1111-111111111111"
    name: "My Subscription"

rules:
  # ── Baseline rules ─────────────────────────────────────────
  # These define your EXPECTED permissions. Any assignment not covered
  # by a baseline rule will be flagged as DRIFT.
  #
  # Tip: run `az-rbac-watch discover` to auto-generate baseline rules
  # from your current assignments, then review and clean up.

  - name: admins-infra
    type: baseline
    description: "Admin group — Owner on infrastructure resource group"
    match:
      principal_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"  # Replace: az ad group show --group "Admins" --query id
      role: Owner
      scope: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-infra

  - name: devs-app
    type: baseline
    description: "Developer group — Contributor on application resource group"
    match:
      principal_id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"  # Replace: az ad group show --group "Developers" --query id
      role: Contributor
      scope: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-app

  - name: cicd-deploy
    type: baseline
    description: "CI/CD service principal — Contributor on application resource group"
    match:
      principal_id: "cccccccc-cccc-cccc-cccc-cccccccccccc"  # Replace: az ad sp show --id "sp-deploy" --query id
      role: Contributor
      scope: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-app

  # ── Governance rules ───────────────────────────────────────
  # These define what is FORBIDDEN. Any matching assignment
  # produces a GOVERNANCE_VIOLATION finding.

  # Nobody should have Owner at subscription level — too broad
  - name: no-owner-at-sub
    type: governance
    description: "Owner role is forbidden at subscription scope"
    severity: critical
    remediation: "Scope the Owner role to a specific resource group instead"
    match:
      scope_prefix: /subscriptions/
      role: Owner

  # Roles should be assigned to groups, not individual users
  - name: no-direct-users
    type: governance
    description: "Direct user assignments are not allowed — use Entra groups"
    severity: high
    remediation: "Add the user to a security group and assign the role to the group"
    match:
      principal_type: User

  # Stick to built-in roles — custom roles are hard to audit
  - name: no-custom-roles
    type: governance
    description: "Custom roles are not allowed — use built-in roles"
    severity: medium
    remediation: "Replace the custom role with a built-in role (Reader, Contributor, or a scoped built-in)"
    match:
      role_type: CustomRole
```

**Step 2:** Validate the file:

```bash
.venv/bin/az-rbac-watch validate -p examples/small_team.yaml
```

Expected: validation passes (exit code 0).

**Step 3:** Commit:

```bash
git add examples/small_team.yaml
git commit -m "docs(examples): add small team policy example"
```

---

## Task 2: Create `examples/enterprise_landing_zone.yaml`

**Files:**
- Create: `examples/enterprise_landing_zone.yaml`

**Step 1:** Create the file with this exact content:

```yaml
# az-rbac-watch — Enterprise Landing Zone Policy
#
# A comprehensive policy following the Azure Cloud Adoption Framework
# landing zone pattern. Covers multiple subscriptions, management groups,
# team-based baseline rules, and strict governance.
#
# Adapt this to your organization:
#   1. Replace all placeholder IDs (tenant, subscriptions, principal IDs)
#   2. Adjust group names to match your naming convention
#   3. Remove or add rules as needed
#
# Reference: https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/

version: "2.0"

tenant_id: "00000000-0000-0000-0000-000000000000"

scope: explicit

# ── Subscriptions ────────────────────────────────────────────
subscriptions:
  - id: "11111111-1111-1111-1111-111111111111"
    name: "Production"
  - id: "22222222-2222-2222-2222-222222222222"
    name: "Staging"
  - id: "33333333-3333-3333-3333-333333333333"
    name: "Development"

# ── Management groups ───────────────────────────────────────
management_groups:
  - id: "mg-root"
    name: "Organization Root"
  - id: "mg-platform"
    name: "Platform"
  - id: "mg-workloads"
    name: "Workloads"

rules:
  # ══════════════════════════════════════════════════════════
  # BASELINE RULES — Expected permissions architecture
  # ══════════════════════════════════════════════════════════

  # ── Break-glass account ────────────────────────────────────
  # One emergency account with Owner at root — PIM-eligible in production
  - name: break-glass-owner
    type: baseline
    description: "Break-glass account — Owner at management group root (emergency only)"
    match:
      principal_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
      role: Owner
      scope: /providers/Microsoft.Management/managementGroups/mg-root

  # ── Platform team ──────────────────────────────────────────
  - name: platform-team-contributor
    type: baseline
    description: "Platform team — Contributor on platform management group"
    match:
      principal_id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
      role: Contributor
      scope: /providers/Microsoft.Management/managementGroups/mg-platform

  # ── Network team ───────────────────────────────────────────
  - name: network-team-prod
    type: baseline
    description: "Network team — Network Contributor on production"
    match:
      principal_id: "cccccccc-cccc-cccc-cccc-cccccccccccc"
      role: "Network Contributor"
      scope: /subscriptions/11111111-1111-1111-1111-111111111111

  - name: network-team-staging
    type: baseline
    description: "Network team — Network Contributor on staging"
    match:
      principal_id: "cccccccc-cccc-cccc-cccc-cccccccccccc"
      role: "Network Contributor"
      scope: /subscriptions/22222222-2222-2222-2222-222222222222

  # ── Security team ──────────────────────────────────────────
  - name: security-team-reader
    type: baseline
    description: "Security team — Security Reader at organization root"
    match:
      principal_id: "dddddddd-dddd-dddd-dddd-dddddddddddd"
      role: "Security Reader"
      scope: /providers/Microsoft.Management/managementGroups/mg-root

  # ── Workload teams ─────────────────────────────────────────
  - name: app-team-prod
    type: baseline
    description: "Application team — Contributor on production app resource group"
    match:
      principal_id: "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
      role: Contributor
      scope: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-app

  - name: app-team-dev
    type: baseline
    description: "Application team — Contributor on development app resource group"
    match:
      principal_id: "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
      role: Contributor
      scope: /subscriptions/33333333-3333-3333-3333-333333333333/resourceGroups/rg-app-dev

  # ── CI/CD service principals ───────────────────────────────
  - name: cicd-prod-deploy
    type: baseline
    description: "CI/CD service principal — Contributor on production app resource group"
    match:
      principal_id: "ffffffff-ffff-ffff-ffff-ffffffffffff"
      role: Contributor
      scope: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-app

  # ══════════════════════════════════════════════════════════
  # GOVERNANCE RULES — What is forbidden
  # ══════════════════════════════════════════════════════════

  # ── Critical ───────────────────────────────────────────────

  - name: no-owner-at-sub
    type: governance
    description: "Owner is forbidden at subscription scope — use resource groups"
    severity: critical
    remediation: "Remove the Owner assignment or scope it to a resource group"
    match:
      scope_prefix: /subscriptions/
      role: Owner

  - name: no-owner-at-mg
    type: governance
    description: "Owner is forbidden at management group scope (except break-glass)"
    severity: critical
    remediation: "Remove the Owner assignment — only the break-glass account should have Owner at MG scope"
    match:
      scope_prefix: /providers/Microsoft.Management/managementGroups/
      role: Owner

  - name: no-guest-privileged
    type: governance
    description: "Guest accounts must not have Owner, Contributor, or User Access Administrator"
    severity: critical
    remediation: "Remove the privileged role from the guest account or convert to member"
    match:
      principal_name_contains: "#EXT#"
      role_in:
        - Owner
        - Contributor
        - "User Access Administrator"

  # ── High ───────────────────────────────────────────────────

  - name: no-direct-users
    type: governance
    description: "Direct user assignments are forbidden — use security groups"
    severity: high
    remediation: "Add the user to an Entra security group and assign the role to the group"
    match:
      principal_type: User

  - name: no-direct-service-principals
    type: governance
    description: "Service principals must be assigned roles through groups"
    severity: high
    remediation: "Add the service principal to a security group and assign the role to the group"
    match:
      principal_type: ServicePrincipal

  - name: no-contributor-at-sub
    type: governance
    description: "Contributor at subscription scope is too broad — use resource groups"
    severity: high
    remediation: "Scope the Contributor role to a specific resource group"
    match:
      scope_prefix: /subscriptions/
      role: Contributor

  - name: no-uaa-at-sub
    type: governance
    description: "User Access Administrator is forbidden at subscription scope"
    severity: high
    remediation: "Scope to a resource group or use a custom role with fewer permissions"
    match:
      scope_prefix: /subscriptions/
      role: "User Access Administrator"

  - name: groups-naming-convention
    type: governance
    description: "Groups must follow the GRP-PERM-* naming convention"
    severity: high
    remediation: "Rename the group to follow GRP-PERM-* convention"
    match:
      principal_type: Group
      principal_name_not_prefix: "GRP-PERM-"

  - name: dev-restricted-roles
    type: governance
    description: "Only Reader and Contributor are allowed in development"
    severity: high
    remediation: "Change to Reader or Contributor, or move the assignment to another subscription"
    match:
      scope_prefix: /subscriptions/33333333-3333-3333-3333-333333333333
      role_not_in:
        - Reader
        - Contributor

  # ── Medium ─────────────────────────────────────────────────

  - name: no-custom-roles-prod
    type: governance
    description: "Custom roles are forbidden in production — use built-in roles"
    severity: medium
    remediation: "Replace the custom role with a built-in role"
    match:
      scope_prefix: /subscriptions/11111111-1111-1111-1111-111111111111
      role_type: CustomRole

  - name: no-temp-groups
    type: governance
    description: "Temporary groups are forbidden — use permanent security groups"
    severity: medium
    remediation: "Replace the temporary group with a permanent security group"
    match:
      principal_type: Group
      principal_name_contains: "TEMP"

  - name: no-classic-admins
    type: governance
    description: "Classic administrator roles (Co-Admin, Service Admin) must be removed"
    severity: medium
    remediation: "Migrate to Azure RBAC roles and remove the classic administrator assignment"
    match:
      role_in:
        - "Co-Administrator"
        - "Service Administrator"
```

**Step 2:** Validate the file:

```bash
.venv/bin/az-rbac-watch validate -p examples/enterprise_landing_zone.yaml
```

Expected: validation passes (exit code 0).

**Step 3:** Commit:

```bash
git add examples/enterprise_landing_zone.yaml
git commit -m "docs(examples): add enterprise landing zone policy example"
```

---

## Task 3: Create `examples/compliance_rules.yaml`

**Files:**
- Create: `examples/compliance_rules.yaml`

**Step 1:** Create the file with this exact content:

```yaml
# az-rbac-watch — Compliance Framework Rules
#
# Governance rules mapped to common compliance frameworks:
#   - CIS Microsoft Azure Foundations Benchmark v2.1
#   - NIST SP 800-53 Rev. 5
#   - SOC 2 Trust Services Criteria
#   - ISO 27001:2022
#
# These are MODULAR rules — copy the ones you need into your policy file.
# Each rule references the framework control it satisfies in its description.
#
# Usage:
#   1. Copy relevant rules into your policy_model.yaml under the `rules:` key
#   2. Adjust match conditions to your environment
#   3. Run: az-rbac-watch scan -p policy_model.yaml

# ── Least Privilege ──────────────────────────────────────────
# CIS 1.23: Ensure no custom subscription owner roles are created
# NIST AC-6: Least Privilege
# SOC 2 CC6.3: Logical access security

- name: cis-no-custom-owner-roles
  type: governance
  description: "[CIS 1.23] [NIST AC-6] Custom subscription owner roles must not exist"
  severity: critical
  remediation: "Delete the custom owner role and use the built-in Owner role with a narrower scope"
  match:
    role_type: CustomRole
    role_in:
      - Owner

# CIS 1.24: Ensure that no custom subscription contributor roles are created
- name: cis-no-custom-contributor-roles
  type: governance
  description: "[CIS 1.24] [NIST AC-6] Custom subscription contributor roles must not exist"
  severity: high
  remediation: "Delete the custom contributor role and use built-in Contributor with a narrower scope"
  match:
    role_type: CustomRole
    role_in:
      - Contributor

# ── Access Control ───────────────────────────────────────────
# NIST AC-2: Account Management
# SOC 2 CC6.1: Logical access security software/infrastructure
# ISO 27001 A.9.2: User access management

- name: nist-no-direct-users
  type: governance
  description: "[NIST AC-2] [SOC2 CC6.1] [ISO A.9.2] Users must be assigned roles through groups"
  severity: high
  remediation: "Add the user to a security group and assign the role to the group"
  match:
    principal_type: User

- name: nist-no-direct-sp
  type: governance
  description: "[NIST AC-2] [SOC2 CC6.1] Service principals must be assigned roles through groups"
  severity: high
  remediation: "Add the service principal to a security group and assign the role to the group"
  match:
    principal_type: ServicePrincipal

# ── Separation of Duties ────────────────────────────────────
# NIST AC-5: Separation of Duties
# SOC 2 CC6.1: Logical access security
# ISO 27001 A.6.1.2: Segregation of duties

- name: nist-no-owner-at-sub
  type: governance
  description: "[NIST AC-5] [SOC2 CC6.1] [ISO A.6.1.2] Owner role at subscription scope violates separation of duties"
  severity: critical
  remediation: "Scope the Owner role to a resource group or use Contributor + separate UAA"
  match:
    scope_prefix: /subscriptions/
    role: Owner

- name: nist-no-uaa-at-sub
  type: governance
  description: "[NIST AC-5] User Access Administrator at subscription scope violates separation of duties"
  severity: high
  remediation: "Scope to a resource group or use a custom role with fewer permissions"
  match:
    scope_prefix: /subscriptions/
    role: "User Access Administrator"

# ── Privileged Access ────────────────────────────────────────
# NIST AC-6(5): Privileged Accounts
# CIS 1.22: Ensure fewer than 5 users have Owner role
# ISO 27001 A.9.2.3: Management of privileged access rights

- name: nist-no-guest-privileged
  type: governance
  description: "[NIST AC-6(5)] [ISO A.9.2.3] Guest accounts must not hold privileged roles"
  severity: critical
  remediation: "Remove the privileged role from the guest account"
  match:
    principal_name_contains: "#EXT#"
    role_in:
      - Owner
      - Contributor
      - "User Access Administrator"

- name: nist-no-contributor-at-sub
  type: governance
  description: "[NIST AC-6] Contributor at subscription scope is overly broad"
  severity: high
  remediation: "Scope the Contributor role to a specific resource group"
  match:
    scope_prefix: /subscriptions/
    role: Contributor

# ── Audit and Accountability ────────────────────────────────
# NIST AU-6: Audit Review, Analysis, and Reporting
# SOC 2 CC7.2: Monitoring activities
# ISO 27001 A.12.4: Logging and monitoring

- name: nist-no-custom-roles
  type: governance
  description: "[NIST AU-6] [SOC2 CC7.2] Custom roles must be audited — prefer built-in roles"
  severity: medium
  remediation: "Replace the custom role with a built-in role or document the exception"
  match:
    role_type: CustomRole

# ── Group Governance ─────────────────────────────────────────
# SOC 2 CC6.2: Registration and authorization
# ISO 27001 A.9.2.1: User registration and de-registration

- name: soc2-groups-naming
  type: governance
  description: "[SOC2 CC6.2] [ISO A.9.2.1] Groups must follow a consistent naming convention"
  severity: medium
  remediation: "Rename the group to follow your organization's naming convention (e.g. GRP-PERM-*)"
  match:
    principal_type: Group
    principal_name_not_prefix: "GRP-PERM-"
```

**Step 2:** Validate by embedding in a temporary policy (since this is a modular fragment, it can't be validated standalone — but we can verify YAML syntax):

```bash
python3 -c "import yaml; yaml.safe_load(open('examples/compliance_rules.yaml'))" && echo "YAML OK"
```

Expected: "YAML OK" (valid YAML).

**Step 3:** Commit:

```bash
git add examples/compliance_rules.yaml
git commit -m "docs(examples): add compliance framework rules (CIS, NIST, SOC2, ISO)"
```

---

## Task 4: Create `examples/ci_cd_integration.md`

**Files:**
- Create: `examples/ci_cd_integration.md`

**Step 1:** Create the file with this exact content:

````markdown
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
````

**Step 2:** Verify markdown renders correctly (visual check — no automated validation needed).

**Step 3:** Commit:

```bash
git add examples/ci_cd_integration.md
git commit -m "docs(examples): add CI/CD integration guide (GitHub Actions, Azure DevOps)"
```

---

## Task 5: Final verification and version bump

**Step 1:** Verify all YAML examples validate:

```bash
.venv/bin/az-rbac-watch validate -p examples/policy_model.yaml
.venv/bin/az-rbac-watch validate -p examples/small_team.yaml
.venv/bin/az-rbac-watch validate -p examples/enterprise_landing_zone.yaml
python3 -c "import yaml; yaml.safe_load(open('examples/compliance_rules.yaml'))" && echo "YAML OK"
```

Expected: all pass.

**Step 2:** Verify no French remains:

```bash
grep -rn '[àâéèêëîïôùûüç]' examples/ --include='*.yaml' --include='*.md'
```

Expected: no output.

**Step 3:** Run full test suite (no regressions):

```bash
.venv/bin/python -m pytest -q && .venv/bin/ruff check . && .venv/bin/mypy src/ tests/
```

Expected: all pass.

**Step 4:** List final examples directory:

```bash
ls -la examples/
```

Expected: 6 files (4 YAML + 1 MD + possibly deny_rules_starter.yaml).

---

## Execution order summary

| Task | File | Type | Depends on |
|------|------|------|------------|
| 1 | `small_team.yaml` | Autonomous YAML | — |
| 2 | `enterprise_landing_zone.yaml` | Autonomous YAML | — |
| 3 | `compliance_rules.yaml` | Modular YAML | — |
| 4 | `ci_cd_integration.md` | Guide | — |
| 5 | Final verification | — | 1-4 |

Tasks 1-4 can be parallelized (no dependencies between them).
