# v0.2.1 — Full English

**Date:** 2026-03-08
**Status:** Approved
**Goal:** Translate all remaining French content in the codebase to English. No functional changes.

## Scope

- All comments and docstrings in `src/` and `tests/`
- All variable and function names still in French
- YAML comments in `examples/`
- No behavior changes — tests must pass identically
- No opportunistic refactoring — translation only

## Out of scope

- CLAUDE.md (local only, not committed)
- docs/plans/ (internal working documents)

## Verification

After translation, grep for common French characters (è, é, ê, ç, à, ù, î, ô, etc.) to confirm nothing remains.

## Deliverable

Single PR, version bump to v0.2.1, tag + publish to PyPI.
