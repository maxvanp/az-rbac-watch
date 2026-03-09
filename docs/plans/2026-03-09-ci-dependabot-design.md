# CI Reinforcement & Dependabot Auto-merge — Design

## Context

Dependabot creates one PR per dependency update, leading to branch sprawl (8+ branches).
CI currently runs ruff check + mypy + pytest + build but lacks coverage enforcement and security audit.

## Dependabot Changes

### Grouping

Group all updates per ecosystem into a single PR:
- `pip-all`: all Python dependencies in one weekly PR
- `actions-all`: all GitHub Actions in one weekly PR

Result: max 2 PRs/week instead of 10+.

### Auto-merge

New workflow `auto-merge-dependabot.yml`:
- Triggered on `pull_request` events from Dependabot
- Enables GitHub native auto-merge (squash) on the PR
- PR merges automatically once CI passes

## CI Reinforcement

Additions to the existing `lint-and-test` job:

| Step | Command | Purpose |
|------|---------|---------|
| Format check | `ruff format --check .` | Enforce consistent formatting |
| Coverage | `pytest --cov=az_rbac_watch --cov-fail-under=80` | Minimum 80% coverage gate |
| Security audit | `pip-audit` | Detect known vulnerabilities in dependencies |

No changes: stays on Python 3.12 only, single OS (ubuntu-latest).

## Cleanup

Delete existing orphaned Dependabot branches from the recreated repo.
