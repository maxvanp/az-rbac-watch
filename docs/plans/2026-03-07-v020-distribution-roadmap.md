# v0.2.0 Distribution Roadmap

**Date:** 2026-03-07
**Status:** Approved
**Goal:** Publish azure-permissions-watch v0.2.0 on PyPI with S-tier onboarding, English UI, and documentation site.

## Context

### Current state (post-merge)
- Two-command architecture: `scan` (drift) + `audit` (guardrails)
- 342 tests passing, mypy strict, ruff clean
- Ad-hoc mode exists but is poorly promoted
- UI is in French, README in English
- No publish workflow, no docs site, version inconsistency (pyproject.toml=0.1.0 vs CHANGELOG=0.2.0)

### Market positioning
azure-permissions-watch is the **only open-source tool** combining:
- Declarative RBAC-as-Code (YAML baseline + drift detection)
- Custom governance guardrails
- CI/CD-native output (exit codes, JSON)
- Discovery/bootstrap workflow
- Multi-scope scanning (subscriptions + management groups)

Direct competitors are PowerShell export scripts with no policy engine. Commercial CIEM tools (Wiz, Defender CSPM, Prisma) cost $24K-200K+/year and don't offer policy-as-code.

### Onboarding benchmark
S-tier tools (Ruff, Checkov, Trivy, kube-bench) share: zero config, auto-detect, one command, immediate results. We target S-tier despite requiring Azure credentials (incompressible).

**Target flow:**
```
pip install az-perm-watch
az login
az-perm-watch              # results in 30 seconds, zero config
```

## Design decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Distribution target | PyPI only | No Docker/GitHub Action for now |
| Audience | Internal + open-source community | Presentable from day one |
| Versioning | setuptools-scm (from git tags) | No manual version bumping |
| Release workflow | Tag triggers build + PyPI + GitHub Release | Fully automated |
| UI language | English default, i18n later | Broader audience, consistent with README |
| Code comments/docstrings | Stay in French | Existing convention maintained |
| Documentation | mkdocs-material on GitHub Pages | Standard Python ecosystem |

---

## Phase 1 — Product quality

### 1a. S-tier onboarding

**Goal:** `az-perm-watch` with zero arguments produces useful results.

| Change | Files | Detail |
|--------|-------|--------|
| Zero-args default to audit | `cli.py` | Replace `no_args_is_help` with a callback that runs `audit` with auto-discovery + default governance rules |
| Auto-detect policy in cwd | `cli.py` | Look for `policy.yaml`, `.az-perm-watch.yaml`, `az-perm-watch.yaml` in cwd. If found, use as `-p` |
| Credential check upfront | `cli.py`, `azure_clients.py` | Before scanning, test `get_credential().get_token()`. On failure: "No Azure credentials found. Run: `az login`" |
| Footer "Next steps" | `console_report.py` | After each report, print the logical next command based on context |
| Quick start in `--help` | `cli.py` | Typer epilog: "Quick start: `az-perm-watch`" |

### 1b. i18n — English UI

| Change | Files |
|--------|-------|
| CLI help text to English | `cli.py` (all `typer.Option` help strings) |
| Console messages to English | `cli.py` (all `console.print`) |
| Console report labels to English | `console_report.py` |
| HTML report labels to English | `html_report.py` (template, labels, titles) |
| Validation messages to English | `policy_model.py` (Pydantic errors) |

### 1c. UX fixes

| Change | Files | Detail |
|--------|-------|--------|
| `--quiet` flag | `cli.py` | Global option, suppresses all output except findings and exit code |
| `--no-color` flag + `NO_COLOR` env var | `cli.py` | `Console(no_color=True)` when flag set or env var present |
| Loud ad-hoc warnings | `cli.py` | BOLD YELLOW when default rules are injected |
| Actionable error messages | `cli.py` | tenant_id: mention `az login`; no rules: show exact `discover` command; scan errors: step-by-step guidance |
| Named progress bar | `cli.py` | `progress.update(task, description=f"Scanning {scope_name}")` |

### 1d. Features

| Change | Files | Detail |
|--------|-------|--------|
| `--dry-run` mode | `cli.py` | Validate policy, resolve scopes, print scan plan, stop before API calls |
| Config file support | New `config/settings.py` | Load from `~/.config/az-perm-watch/config.yaml` + `AZ_PERM_WATCH_*` env vars + cwd file. Provides defaults for `--policy`, `--format`, etc. |
| Match operator conflict detection | `policy_model.py` | Warn on contradictions like `role: Owner` + `role_not_in: [Owner]` |
| Shell completion docs | `README.md` | Section documenting `--install-completion` |
| Pre-commit config | `.pre-commit-config.yaml` | ruff check + mypy |
| Coverage reporting | `pyproject.toml` | Add pytest-cov to dev deps, `.coveragerc`, badge in README |

---

## Phase 2 — Distribution infrastructure

| Change | Files | Detail |
|--------|-------|--------|
| setuptools-scm | `pyproject.toml` | Replace `version = "0.1.0"` with `dynamic = ["version"]` + setuptools-scm config |
| Publish workflow | `.github/workflows/publish.yml` | Trigger on tag `v*` → build → PyPI (OIDC trusted publisher) → GitHub Release with extracted changelog |
| Docs workflow | `.github/workflows/docs.yml` | Trigger on push main → mkdocs build → GitHub Pages |
| CONTRIBUTING.md | Root | Dev setup, conventions (French docstrings, English UI), PR process, required checks |
| Build check in CI | `.github/workflows/ci.yml` | Add `python -m build` step to verify package builds on every PR |

### Release flow
```
git tag v0.2.0
git push --tags
  -> GitHub Actions:
       1. ruff + mypy + pytest (CI gate)
       2. python -m build (wheel + sdist)
       3. pypi publish (OIDC trusted publisher)
       4. gh release create (changelog v0.2.0 extracted)
       5. mkdocs build + deploy GitHub Pages
```

---

## Phase 3 — Documentation site

### Stack
- **Generator:** mkdocs-material
- **Hosting:** GitHub Pages (auto-deployed from main)
- **Config:** `mkdocs.yml` at root

### Site structure
```
docs/
  index.md                 # Landing page (condensed README)
  getting-started.md       # Install + az login + first run + next steps
  commands/
    audit.md               # Usage, options, examples, exit codes
    scan.md
    discover.md
    validate.md
  policy-reference.md      # Migrated from POLICY_REFERENCE.md
  configuration.md         # Config file, env vars, auto-detect policy
  ci-cd.md                 # Pipeline integration (GitHub Actions, Azure DevOps)
  architecture.md          # Compliance engine, two-pass, rule matching
  contributing.md          # Links to CONTRIBUTING.md
```

### Content priority
| Page | Source | Effort |
|------|--------|--------|
| getting-started.md | New — S-tier flow documented step by step | Medium |
| commands/*.md | Extracted from current README + CLI help text | Low |
| policy-reference.md | Copy + reformat of existing POLICY_REFERENCE.md | Low |
| configuration.md | New — config file + env vars + auto-detect docs | Low |
| ci-cd.md | Extracted from README + GitHub Actions/Azure DevOps examples | Medium |
| architecture.md | Extracted from CLAUDE.md + compliance engine docs | Low |

---

## Deliverable

Tag `v0.2.0` → published on PyPI + GitHub Release + docs site live on GitHub Pages.

## Out of scope (v0.3+)
- Docker image
- GitHub Action marketplace
- `--lang fr` i18n support
- JSON schema publication for policy model
- Orphaned assignment detection
- PIM integration
