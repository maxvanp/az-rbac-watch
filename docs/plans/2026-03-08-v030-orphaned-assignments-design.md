# v0.3.0 — Orphaned Assignment Detection

**Date:** 2026-03-08
**Status:** Approved
**Goal:** Detect RBAC assignments whose principal (user/group/SP) has been deleted from Entra ID, and report them as findings.

## Concept

An orphaned assignment is an RBAC role assignment where the principal no longer exists in Entra ID. Azure keeps the assignment active but returns an empty `principalType` and no `displayName`. These assignments are noise at best and a compliance risk at worst.

They are reported as a new finding type: `ORPHANED_ASSIGNMENT`, severity HIGH.

## Two usage modes

```bash
# Mode 1: full scan (baseline + governance + orphans)
az-rbac-watch scan -p policy.yaml

# Mode 2: orphans only, no policy file needed
az-rbac-watch scan --orphans-only -t <tenant-id>
# Auto-discovers all accessible subscriptions

# Mode 2 with explicit scope
az-rbac-watch scan --orphans-only -t <tenant-id> -s <sub-id>
```

## Data model changes

- New `FindingType` value: `ORPHANED_ASSIGNMENT` in the existing StrEnum
- Fixed severity: HIGH
- Finding contains: scope, role, principal_id (only remaining identifier), assignment creation date if available

## Detection

In `rbac_scanner.py`, during the existing scan: if an assignment has an empty/absent `principal_type` or empty `display_name`, it is marked as orphaned. No additional API call needed — detectable directly from the RBAC API response.

## Output

Same treatment as other findings — appears in console, HTML, and JSON reports. No separate section.

## CLI changes

- `--orphans-only` flag on the `scan` command
- When `--orphans-only` is used, `--tenant-id` / `-t` is required
- `--subscription-id` / `-s` is optional (if absent → auto-discovery of all accessible subs)
- `--orphans-only` is incompatible with `-p` (policy file)

## Out of scope

- Policy model version stays "2.0" (no schema change)
- `validate`, `discover`, `audit` commands unchanged
- Change tracking / audit trail (planned for v0.4.0)

## Verification

- Unit tests for orphan detection logic (mocked Azure responses)
- Integration with existing report formats
- CLI flag validation (--orphans-only without -t should error)
- Existing 401 tests must continue to pass
