# v0.2.1 Full English — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Translate all remaining French comments, docstrings, and variable names to English across the entire codebase.

**Architecture:** Pure translation pass — no functional changes. Each task covers one logical group of files. Tests must pass identically after each task.

**Tech Stack:** Python 3.12, sed/manual edits, pytest, ruff, mypy.

---

## Task 1: Translate src/az_rbac_watch/scanner/ (57 occurrences)

**Files:**
- Modify: `src/az_rbac_watch/scanner/rbac_scanner.py` (44 occurrences — heaviest file)
- Modify: `src/az_rbac_watch/scanner/discovery.py` (13 occurrences)

**Step 1:** Read both files and translate all French comments, docstrings, and variable names to English. Preserve all logic exactly.

**Step 2:** Run tests:
```bash
.venv/bin/python -m pytest tests/test_rbac_scanner.py tests/test_discovery.py -v
```
Expected: all pass, identical behavior.

**Step 3:** Run lint:
```bash
.venv/bin/ruff check src/az_rbac_watch/scanner/ && .venv/bin/mypy src/az_rbac_watch/scanner/
```

**Step 4:** Commit:
```bash
git commit -am "chore(i18n): translate scanner module to English"
```

---

## Task 2: Translate src/az_rbac_watch/config/ (24 occurrences)

**Files:**
- Modify: `src/az_rbac_watch/config/policy_model.py` (15 occurrences)
- Modify: `src/az_rbac_watch/config/settings.py` (9 occurrences)

**Step 1:** Read both files. Translate all French comments, docstrings, and variable names.

**Step 2:** Run tests:
```bash
.venv/bin/python -m pytest tests/test_policy_model.py tests/test_settings.py -v
```

**Step 3:** Run lint:
```bash
.venv/bin/ruff check src/az_rbac_watch/config/ && .venv/bin/mypy src/az_rbac_watch/config/
```

**Step 4:** Commit:
```bash
git commit -am "chore(i18n): translate config module to English"
```

---

## Task 3: Translate src/az_rbac_watch/auth/ and cli.py (25 occurrences)

**Files:**
- Modify: `src/az_rbac_watch/auth/azure_clients.py` (16 occurrences)
- Modify: `src/az_rbac_watch/cli.py` (9 occurrences)

**Step 1:** Read both files. Translate all French content.

**Step 2:** Run tests:
```bash
.venv/bin/python -m pytest tests/test_cli.py -v
```

**Step 3:** Run lint:
```bash
.venv/bin/ruff check src/az_rbac_watch/auth/ src/az_rbac_watch/cli.py && .venv/bin/mypy src/az_rbac_watch/auth/ src/az_rbac_watch/cli.py
```

**Step 4:** Commit:
```bash
git commit -am "chore(i18n): translate auth module and CLI to English"
```

---

## Task 4: Translate remaining src/ files (4 occurrences)

**Files:**
- Modify: `src/az_rbac_watch/reporters/__init__.py` (1)
- Modify: `src/az_rbac_watch/utils/__init__.py` (1)
- Modify: `src/az_rbac_watch/utils/scope.py` (1)
- Modify: `src/az_rbac_watch/analyzers/__init__.py` (1)

**Step 1:** Read and translate all four files.

**Step 2:** Run full test suite:
```bash
.venv/bin/python -m pytest -q
```

**Step 3:** Run lint:
```bash
.venv/bin/ruff check src/ && .venv/bin/mypy src/
```

**Step 4:** Commit:
```bash
git commit -am "chore(i18n): translate remaining src modules to English"
```

---

## Task 5: Translate tests/ (91 occurrences)

**Files:**
- Modify: `tests/test_cli.py` (26)
- Modify: `tests/test_rbac_scanner.py` (18)
- Modify: `tests/test_html_report.py` (16)
- Modify: `tests/test_discovery.py` (8)
- Modify: `tests/test_settings.py` (8)
- Modify: `tests/test_compliance.py` (4)
- Modify: `tests/test_console_report.py` (4)
- Modify: `tests/test_policy_model.py` (4)
- Modify: `tests/factories.py` (2)
- Modify: `tests/conftest.py` (1)

**Step 1:** Read and translate all test files. French content will be in test docstrings, comments, and possibly test data variable names.

**Step 2:** Run full test suite:
```bash
.venv/bin/python -m pytest -q
```
Expected: 401 passed.

**Step 3:** Run lint:
```bash
.venv/bin/ruff check tests/ && .venv/bin/mypy tests/
```

**Step 4:** Commit:
```bash
git commit -am "chore(i18n): translate all test files to English"
```

---

## Task 6: Translate examples/ and final verification

**Files:**
- Modify: `examples/policy_model.yaml` (French YAML comments)

**Step 1:** Read and translate all French comments in example files.

**Step 2:** Final verification — grep for any remaining French:
```bash
grep -rn '[àâéèêëîïôùûüç]' src/ tests/ examples/ --include='*.py' --include='*.yaml'
```
Expected: no output.

**Step 3:** Full check:
```bash
.venv/bin/python -m pytest -q && .venv/bin/ruff check . && .venv/bin/mypy src/ tests/
```
Expected: 401 passed, all checks clean.

**Step 4:** Commit:
```bash
git commit -am "chore(i18n): translate examples to English"
```

---

## Task 7: Update CLAUDE.md locally + update version convention

**Step 1:** Update CLAUDE.md to change the language convention:
- Remove: "Comments and docstrings are in French"
- Replace with: "All code, comments, and docstrings are in English"

**Step 2:** This is local only — no commit needed (CLAUDE.md is in global gitignore).

---

## Execution order summary

| Task | Files | Occurrences | Depends on |
|------|-------|-------------|------------|
| 1 | scanner/ | 57 | — |
| 2 | config/ | 24 | — |
| 3 | auth/ + cli.py | 25 | — |
| 4 | remaining src/ | 4 | — |
| 5 | tests/ | 91 | 1-4 |
| 6 | examples/ + verify | 1 | 5 |
| 7 | CLAUDE.md (local) | — | 6 |

Tasks 1-4 can be parallelized (no dependencies between them).
