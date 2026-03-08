# Contributing

See the full contributing guide in the repository root: [CONTRIBUTING.md](https://github.com/maxvanp/az-rbac-watch/blob/main/CONTRIBUTING.md)

## Quick reference

```bash
# Setup
uv venv && uv pip install -e ".[dev]"
pre-commit install

# Run checks
ruff check .
mypy src/ tests/
pytest
```

All three checks must pass before submitting a PR.

## Conventions

- **Docstrings and comments**: French
- **UI strings (CLI output, error messages)**: English
- **Type checking**: mypy strict mode
- **Linting**: ruff
- **Commits**: [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `chore:`)
