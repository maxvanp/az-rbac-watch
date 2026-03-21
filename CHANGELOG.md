# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Framework compliance mapping module (CIS Azure Benchmark)
- CLI refactored into `cli/` package with one module per command

## [0.8.0] - 2026-03-21

### Added

- Azure Portal deep links in scan and audit reports for every finding

## [0.7.0] - 2026-03-21

### Added

- HTML report for snapshot diffs (`az-rbac-watch diff --html`)

## [0.6.0] - 2026-03-21

### Added

- Enhanced HTML reports: severity filter buttons, text search, and improved layout

## [0.5.0] - 2026-03-21

### Added

- Reusable GitHub Action (`uses: maxvanp/az-rbac-watch/.github/workflows/rbac-check.yml`)

## [0.4.2] - 2026-03-09

No code changes; tag created to align release artifacts.

## [0.4.1] - 2026-03-09

### Added

- README documentation for `snapshot`, `diff`, and `--orphans-only` commands

## [0.4.0] - 2026-03-08

### Added

- `snapshot` command: capture current RBAC assignments to a JSON file
- `diff` command: compare two snapshots and report added/removed assignments
- Snapshot model with save/load serialization
- Diff engine with console and JSON reporters
- Orphaned assignment detection surfaced in diff output

## [0.3.0] - 2026-03-08

### Added

- Orphaned assignment detection: flags assignments whose principal no longer exists in Azure AD
- `--orphans-only` flag on `scan` command to report only orphaned assignments
- `orphan_count` field in `ComplianceSummary`
- Example policies: small team, enterprise landing zone, CIS/NIST/SOC2/ISO framework rules
- CI/CD integration guide (GitHub Actions, Azure DevOps)

## [0.2.0] - 2026-03-07

### Changed

- **Two-command architecture**: `scan` (drift detection from baseline rules) and `audit` (guardrail violations from governance rules)
- Renamed finding type `OUT_OF_BASELINE` → `DRIFT` (backward-compatible alias kept)
- Renamed summary fields: `out_of_baseline_count` → `drift_count`, `governance_violation_count` → `violation_count`
- `scan` command now only evaluates baseline rules — exits 0 with hint if none exist
- Console and HTML reports are mode-aware (drift-specific or audit-specific labels)
- **English UI**: all CLI messages, help text, reports, and validation errors translated to English (code comments/docstrings remain in French)

### Added

- **S-tier onboarding**: `az-rbac-watch` with zero arguments runs audit with auto-discovery and default governance rules
- **Auto-detect policy file**: looks for `policy.yaml`, `.az-rbac-watch.yaml`, `az-rbac-watch.yaml` in cwd
- **Credential check**: upfront Azure credential validation with actionable error messages
- **Next steps footer**: context-aware guidance after each report
- `--quiet` / `-q` global flag: suppress all output except findings and exit code
- `--no-color` global flag + `NO_COLOR` env var support
- `--dry-run` flag on scan, audit, discover: show scan plan without API calls
- **Config file support**: `~/.config/az-rbac-watch/config.yaml` + `AZ_RBAC_WATCH_*` env vars
- **Match operator conflict detection**: warnings on contradictory rule combinations (e.g., `role: Owner` + `role_not_in: [Owner]`)
- Actionable error messages with step-by-step guidance for common failures
- Bold yellow ad-hoc mode warnings
- Named progress bar showing current scope being scanned
- `audit` command: checks governance rules (forbidden patterns), reports violations
- `check_drift()` and `check_violations()` functions in compliance engine
- Mode-specific console reporters: `print_drift_report()`, `print_audit_report()`
- HTML report `mode` parameter: `"scan"`, `"audit"`, or `"combined"`
- Shell completion instructions in README
- Pre-commit config (ruff + mypy)
- pytest-cov coverage reporting
- CONTRIBUTING.md
- mkdocs-material documentation site

### Build

- Switched to hatch-vcs for automatic versioning from git tags
- Added package build verification step in CI
- Added publish workflow: tag → build → PyPI (OIDC trusted publisher) → GitHub Release
- Added docs deploy workflow for GitHub Pages

## [0.1.0] - 2026-02-21

### Added

- Policy model v2.0 with baseline and governance rules (YAML format)
- RBAC scanner for Azure subscriptions and management groups (parallel scanning)
- Compliance engine: OUT_OF_BASELINE and GOVERNANCE_VIOLATION findings
- Display name resolution via Microsoft Graph API (graceful degradation)
- Console report with Rich panels and severity coloring
- HTML report with JS filtering (severity buttons + text search)
- JSON report for CI/CD integration
- Auto-discovery: generate a draft policy model from existing RBAC assignments
- Offline policy validation (`az-rbac-watch validate`)
- Scope modes: `explicit` (default) and `all` (auto-discovery with exclusions)
- 14 rule match operators (scope, role, principal — all case-insensitive)
- Exit codes: 0 (compliant), 1 (findings), 2 (error)
- Starter kit with 8 governance rules (`examples/deny_rules_starter.yaml`)
