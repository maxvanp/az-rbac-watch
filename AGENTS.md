# Repository Guidelines

## Project Structure & Module Organization
Core code lives in `src/az_rbac_watch/`. Keep changes scoped to the relevant module: `cli/` for Typer commands, `scanner/` for Azure RBAC collection, `analyzers/` for compliance and diff logic, `reporters/` for console/HTML/JSON output, and `config/` for Pydantic settings and policy models. Tests live in `tests/`. Documentation is in `docs/`, reusable policy examples in `examples/`, and generated build artifacts in `dist/` should not be edited manually.

## Build, Test, and Development Commands
Set up a local environment with `uv venv && uv pip install -e ".[dev]"`. Install hooks with `pre-commit install`.

Run the same checks as CI before opening a PR:
- `ruff check .` for linting
- `ruff format --check .` for formatting verification
- `mypy src/ tests/` for strict type checking
- `pytest --cov=az_rbac_watch --cov-fail-under=80` for tests and minimum coverage
- `mkdocs build` when editing docs or navigation

## Coding Style & Naming Conventions
Target Python 3.12 and keep imports, typing, and syntax compatible with `mypy --strict`. Ruff enforces a `120` character line length and import ordering. Use `snake_case` for modules, functions, and test files; keep Typer command modules named `cmd_<command>.py`. Follow the repository language split: docstrings and code comments in French, user-facing CLI strings and error messages in English.

## Testing Guidelines
Add or update tests beside the affected area using `tests/test_<feature>.py`. Prefer focused unit tests first, then CLI integration coverage for new commands or flags. Regressions in report output should include assertions on structured JSON or stable text fragments rather than broad snapshots.

## Commit & Pull Request Guidelines
Use Conventional Commits as seen in history: `feat:`, `fix:`, `refactor:`, `docs:`, and `chore:`. Keep PRs based on `main`, describe the user-visible impact, and link the relevant issue or design note when one exists. A merge-ready PR should pass `ruff`, `mypy`, `pytest`, and any touched docs build; include sample output or screenshots only when CLI/report presentation changes.

## Security & Agent Notes
This project is read-only against Azure; do not add code that mutates RBAC state. Avoid exposing credentials or raw SDK errors in logs or reports. When using Codex CLI in this repository, prefix shell commands with `rtk` per the local workflow instruction.
