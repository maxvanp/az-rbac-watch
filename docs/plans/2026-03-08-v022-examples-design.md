# v0.2.2 — Real-World Examples

**Date:** 2026-03-08
**Status:** Approved
**Goal:** Add practical, real-world policy examples covering small teams, enterprise landing zones, compliance frameworks, and CI/CD integration.

## Scope

4 new files in `examples/`:

### 1. `small_team.yaml` (Autonomous)
Complete policy file for a small team (5-10 people), 1 subscription, 2 resource groups.
- 3 baseline rules (admin group, dev group, CI/CD SP)
- 3 governance rules (no Owner at sub scope, no direct users, no custom roles)
- Pedagogical comments explaining each section for beginners
- Goal: copy, replace IDs, run `az-rbac-watch scan` in 5 minutes

### 2. `enterprise_landing_zone.yaml` (Autonomous)
Complete policy file following Cloud Adoption Framework patterns.
- Management group root + 3 subscriptions (prod, staging, dev)
- ~8 baseline rules (platform team, workload teams, network team, security team, break-glass account)
- ~12 governance rules (no Owner/UAA/Contributor at sub scope, no direct users/SPs, no guests with privileged roles, no custom roles in prod, naming conventions, scope-bound CI/CD SPs, no classic admin roles)
- Realistic severities (critical/high/medium)

### 3. `compliance_rules.yaml` (Modular)
Fragment of rules (like `deny_rules_starter.yaml`) mapped to compliance frameworks.
- ~10 rules with framework references in descriptions: `[CIS 1.23]`, `[NIST AC-6]`, `[SOC2 CC6.1]`
- Covers: least privilege, separation of duties, no wildcard custom roles, guest review, orphaned assignments (marked as planned for v0.3.0)
- Comments explaining framework-to-rule mapping

### 4. `ci_cd_integration.md` (Guide)
Integration guide with copy-paste pipeline examples.
- GitHub Actions workflow (scheduled + on-PR)
- Azure DevOps pipeline YAML
- Exit code interpretation (0/1/2)
- Service principal setup (minimum permissions: Reader + Directory.Read.All)

## Out of scope

- No code changes — examples only
- No new CLI features
- No changes to existing examples

## Verification

- `az-rbac-watch validate -p examples/<file>.yaml` must pass for all YAML files
- Markdown renders correctly on GitHub
