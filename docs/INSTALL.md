# Install

PyDeepMesh is a pure-Python CLI/package (Python 3.10+). It has no daemon and no
required external service.

## PyPI

```bash
pip install pydeepmesh
```

Or install the CLI in an isolated environment:

```bash
uv tool install pydeepmesh
```

Verify:

```bash
pydeepmesh --version
pydeepmesh --help
```

## From source

```bash
git clone https://github.com/Mullassery/PyDeepMesh
cd PyDeepMesh
python -m venv .venv && . .venv/bin/activate
pip install .
```

For development:

```bash
pip install -e ".[dev]"
pytest -q
```

## Optional: Syft (container images)

`pydeepmesh image` requires the Apache-2.0 [Syft](https://github.com/anchore/syft)
binary. It is **not** vendored or installed by pip.

```bash
brew install syft          # macOS
# or download a release binary for your platform
```

Point at a specific binary with `--syft PATH`. If Syft is missing, the command
raises `SyftUnavailable`; it never reports an empty image.

## Advisory data

- `audit`/`report` use a local advisory cache/snapshot when `--offline`.
- `advisories update` explicitly refreshes the cache (online).
- `--require-advisory` makes missing advisory data an error (exit 4).
- Absence of a match is reported as `unmatched`/`unavailable`, never as "safe".

## Output paths

`--output` must stay inside the output root (default: the scanned project).
Writing outside it fails with a security error unless you pass `--output-root`:

```bash
pydeepmesh sbom . --output /tmp/sbom.cdx.json --output-root /tmp
```

## Troubleshooting

- **`--output` rejected** — add `--output-root DIR` (see above).
- **`SyftUnavailable`** — install Syft or pass `--syft`.
- **Exit code 4** — advisory data was required but unavailable; run
  `advisories update` online or provide `--advisory-dir`.
- **Partial coverage** — see [Support matrix](../SUPPORT_MATRIX.md) (for
  example, `yarn.lock` and Cargo workspaces are partial).
