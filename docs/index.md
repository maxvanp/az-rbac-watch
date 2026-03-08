# Azure Permissions Watch

**Azure RBAC as Code — drift detection and guardrails.**

Azure Permissions Watch is the only open-source tool that treats Azure RBAC assignments as code. Declare your desired permission state in YAML, detect drift, and enforce governance guardrails — all from a single CLI.

## What it does

Two complementary commands in one tool:

| Axis | Command | Rule type | Finding | Question answered |
|------|---------|-----------|---------|-------------------|
| RBAC as Code | `scan` | `baseline` | `DRIFT` | "Is there something I didn't declare?" |
| Policy as Code | `audit` | `governance` | `GOVERNANCE_VIOLATION` | "Is there something forbidden?" |

Neither OPA nor Azure Policy can natively scan RBAC assignments. This tool fills that gap.

## Key features

- **Drift detection** — compare actual RBAC state against a declared baseline
- **Governance guardrails** — define forbidden patterns (e.g., no direct user assignments, no Owner at subscription scope)
- **14 match operators** — scope, role, principal type, display name patterns, and more
- **Multiple output formats** — console (Rich), HTML single-file report, JSON for CI/CD
- **Auto-discovery** — generate a baseline policy from existing assignments
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
- [Policy Reference](policy-reference.md) — YAML format and match operators
- [CI/CD Integration](ci-cd.md) — GitHub Actions and Azure DevOps examples
