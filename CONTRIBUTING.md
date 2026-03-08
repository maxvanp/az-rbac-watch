# Contributing

## Dev Setup

```bash
uv venv && uv pip install -e ".[dev]"
pre-commit install
```

## Running Checks

```bash
ruff check .
mypy src/ tests/
pytest
```

All three must pass before submitting a PR.

## Conventions

- **Docstrings and comments**: French
- **UI strings (CLI output, error messages)**: English
- **Type checking**: mypy strict mode (`--strict`)
- **Formatting/linting**: ruff

## Commit Style

We use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation only
- `chore:` maintenance, CI, tooling

## PR Process

1. Branch from `main`
2. All checks must pass (`ruff`, `mypy`, `pytest`)
3. One approval required to merge
