# Contributing to PyDeepMesh

Thanks for helping improve PyDeepMesh. This project is intentionally standalone:
contributions must not introduce dependencies on sibling repositories. See
[`REPOSITORY_BOUNDARIES.md`](REPOSITORY_BOUNDARIES.md).

## Development setup

PyDeepMesh targets Python 3.10+. [`uv`](https://docs.astral.sh/uv/) is recommended.

```bash
uv venv --python 3.12
uv pip install -e ".[dev]"
```

Or with plain pip in a virtual environment:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
```

## Local quality suite

Run everything the way CI does:

```bash
ruff format --check .
ruff check .
mypy
python scripts/check_boundaries.py
pytest --cov=pydeepmesh --cov-report=term-missing
```

Live-network advisory tests are opt-in and tagged `network`:

```bash
pytest -m network
```

## Adding a parser

1. Create a module in `src/pydeepmesh/parsers/<ecosystem>/`.
2. Implement a class deriving from `parsers.base.Parser`, declaring
   `ecosystem`, `file_globs`, `matches()`, and `parse()`.
3. Never raise on malformed input: append diagnostics and return partial data.
4. Register it in `parsers.registry`.
5. Add fixtures under `tests/fixtures/` and tests including a malformed case.

## Adding an advisory provider

1. Implement `advisories.base.AdvisoryProvider`.
2. Return normalized `Advisory` records or an explicit `unavailable` result.
3. Register it in `advisories.registry`.
4. Mock the transport in tests; do not require live network in the default suite.

## Code style

- Formatting and import order: `ruff format` and `ruff check`.
- Typing: `mypy --strict` over `src/pydeepmesh`.
- No comments unless they explain non-obvious intent.
- Keep modules focused; avoid circular imports and speculative abstractions.

## Commit and PR expectations

- Small, coherent changes with tests.
- Update `CHANGELOG.md` for user-visible changes.
- Do not commit secrets, local config, or generated artifacts.
