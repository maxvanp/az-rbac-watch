# az-rbac-watch

**CLI for Azure RBAC drift detection, governance guardrails, and change tracking.**

`az-rbac-watch` treats Azure RBAC assignments as code: declare a baseline in YAML, detect drift, enforce guardrails, and compare snapshots over time from a single CLI.

## What it does

Six focused commands in one tool:

| Axis | Command | Rule type | Finding | Question answered |
|------|---------|-----------|---------|-------------------|
| Baseline capture | `discover` | `baseline` | n/a | "What should my current RBAC look like?" |
| RBAC as Code | `scan` | `baseline` | `DRIFT` | "Is there something I didn't declare?" |
| Policy as Code | `audit` | `governance` | `GOVERNANCE_VIOLATION` | "Is there something forbidden?" |
| Offline validation | `validate` | n/a | n/a | "Is my policy file valid?" |
| Change tracking | `snapshot` | n/a | n/a | "What did RBAC look like at this moment?" |
| Change tracking | `diff` | n/a | Added / Removed / Modified | "What changed since last time?" |

Neither OPA nor Azure Policy can natively scan RBAC assignments. This tool fills that gap and keeps the workflow simple enough for local use and CI/CD automation.

## Key features

- **Drift detection** — compare actual RBAC state against a declared baseline
- **Governance guardrails** — define forbidden patterns (e.g., no direct user assignments, no Owner at subscription scope)
- **14 match operators** — scope, role, principal type, display name patterns, and more
- **Multiple output formats** — console (Rich), HTML single-file report, JSON for CI/CD
- **Auto-discovery** — generate a baseline policy from existing assignments
- **Change tracking** — capture snapshots and diff them over time
- **Zero-config start** — run with no arguments to audit all accessible subscriptions with default rules
- **CI/CD ready** — deterministic exit codes (0/1/2), JSON output, quiet mode

## Quick start

```bash
pip install az-rbac-watch
az login
az-rbac-watch
```

That's it. With no arguments, `az-rbac-watch` auto-discovers all accessible subscriptions and runs a governance audit with default rules.

## Next steps

- [Getting Started](getting-started.md) — full onboarding guide
- [Commands: snapshot](commands/snapshot.md) — capture current RBAC state as JSON
- [Commands: diff](commands/diff.md) — compare snapshots over time
- [Policy Reference](policy-reference.md) — YAML format and match operators
- [CI/CD Integration](ci-cd.md) — GitHub Actions and Azure DevOps examples
