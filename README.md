# PyDeepMesh

**Deterministic, extensible dependency-graph, vulnerability, and attack-surface
intelligence for Python, Rust, Node.js, and container projects.**

[![PyPI](https://img.shields.io/pypi/v/pydeepmesh.svg)](https://pypi.org/project/pydeepmesh/)

PyDeepMesh statically parses the dependency metadata already in your repository
(manifests, lockfiles, Dockerfiles, Compose files), normalizes it into a single
canonical dependency graph, matches it against advisory data, and emits
explainable security and dependency intelligence in machine- and human-readable
formats — all without executing any of your code.

> PyDeepMesh is a standalone product. It has no dependency on, and shares no code
> with, any other repository. See [`REPOSITORY_BOUNDARIES.md`](REPOSITORY_BOUNDARIES.md).

## Scope: what PyDeepMesh is, and is not

PyDeepMesh is scoped to **repository-wide dependency-graph and vulnerability
intelligence**: it discovers manifests and lockfiles, builds a canonical
dependency graph, and matches packages against advisory data across Python,
Rust, Node.js, and containers.

It deliberately does **not** do dependency provenance/usage attribution, dbt or
Airflow project linting, pipeline cost analysis, runtime data-quality checks,
network discovery, or API/agent-failure diagnosis. Those are separate concerns
with their own tooling; PyDeepMesh neither depends on nor bundles them.

## The problem

Dependency risk is spread across ecosystems and file formats. A single service
may have a `pyproject.toml`, a `Cargo.lock`, a `package-lock.json`, and three
Dockerfiles — each with its own versioning rules, scopes, and lockfile
semantics. Answering "which of my projects are exposed, through what path, and
what should I upgrade?" requires a normalized graph plus evidence-based advisory
matching. PyDeepMesh builds that graph and answers those questions, locally and
deterministically.

## What PyDeepMesh does

- **Discovers** manifests and lockfiles across four ecosystems.
- **Parses** them defensively, preserving provenance and resolution confidence,
  and reporting diagnostics instead of inventing data.
- **Builds** a canonical directed dependency graph with scopes, resolution
  status, transitive edges, and multiple project roots.
- **Matches** packages against advisory data with ecosystem-aware version
  semantics (PEP 440 for PyPI, SemVer for npm/crates.io).
- **Analyzes** exposure: direct vs. transitive, reachable paths, dependency
  concentration, and fix candidates.
- **Reports** a terminal summary, a versioned JSON document, SARIF 2.1.0, a
  CycloneDX 1.5 SBOM, and a self-contained local HTML graph view (static HTML +
  inline SVG; no JavaScript, no CDN, no telemetry).

PyDeepMesh distinguishes **confirmed**, **potential**, **unmatched**,
**unavailable**, and **error** outcomes. **A package is never reported as
"safe" merely because no advisory was found.**

## Container image scanning (Syft)

Dockerfile parsing is not the same as scanning a built image. The optional
Syft adapter catalogs packages inside an image and feeds them into the same
canonical graph:

```bash
# install the Apache-2.0 Syft binary (not a vendored dependency)
brew install syft

pydeepmesh image ghcr.io/example/app:latest --format terminal
pydeepmesh image ghcr.io/example/app:latest --format json
```

```python
from pydeepmesh.integrations import scan_image

result = scan_image("ghcr.io/example/app:latest")
print(len(result.components), result.graph.nodes)
```

Syft is never vendored; a missing binary raises `SyftUnavailable` instead of
pretending the image has no packages.

## Installation

Requires Python 3.10+.

Install the published package from PyPI:

```bash
pip install pydeepmesh

# or, as an isolated CLI tool
uv tool install pydeepmesh
```

Or install from source:

```bash
git clone https://github.com/Mullassery/PyDeepMesh
cd PyDeepMesh
python -m venv .venv && . .venv/bin/activate
pip install .
```

## CLI usage

```bash
pydeepmesh scan   <path>     # discover + parse + build graph; summary or --format json
pydeepmesh graph  <path>     # graph queries: paths, reverse-deps; --format html export
pydeepmesh audit  <path>     # vulnerability + exposure findings (offline by default)
pydeepmesh sbom   <path>     # emit a CycloneDX 1.5 SBOM
pydeepmesh report <path>     # combined report: --format json|sarif|terminal
pydeepmesh advisories update # refresh the local advisory cache (explicit, online)
```

Common options: `--output PATH`, `--offline/--online`,
`--fail-on {critical,high,medium,low,never}`, `--config PATH`, `--verbose`,
`--quiet`. `--format` depends on the command: `terminal`/`json` everywhere,
`sarif` for `audit`/`report`, and `html` for `graph`.

### Examples

```bash
# Structure only, deterministic JSON to stdout
pydeepmesh scan . --format json

# Audit using a local OSV snapshot (fully offline)
pydeepmesh audit . --offline --advisory-dir ./osv-snapshot --format sarif --output findings.sarif

# Audit against live OSV, failing CI on high severity
pydeepmesh audit . --online --fail-on high

# SBOM
pydeepmesh sbom . --output sbom.cdx.json

# Self-contained HTML graph view (no JavaScript, no network)
pydeepmesh graph . --format html --output graph.html
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success; no finding met the `--fail-on` threshold |
| `1` | A finding met the `--fail-on` threshold |
| `2` | Usage / configuration error |
| `3` | An input error prevented analysis (e.g. a fatal read/parse failure) |
| `4` | Advisory data unavailable when results were required |

## Offline vs. online

PyDeepMesh is **offline by default**. No network request is made unless you pass
`--online`. Offline analysis uses `--advisory-dir` snapshots or the local cache
at `.pydeepmesh-cache/`. `pydeepmesh advisories update` is the only command that
refreshes the cache, and it is explicit.

## Advisory sources

- **OSV** (`https://api.osv.dev`) — provider-neutral, aggregates GHSA and
  ecosystem advisories. Used for online queries with timeout, bounded retries,
  and a response size cap.
- **Offline snapshots** — a directory of OSV-format JSON records.

Integrations with other vendors are documented as future interoperability
opportunities, not dependencies.

## Supported formats

See [`SUPPORT_MATRIX.md`](SUPPORT_MATRIX.md) for the authoritative list of
implemented, partial, planned, and unsupported formats and capabilities.

## Architecture

See [`ARCHITECTURE.md`](ARCHITECTURE.md). Core logic (models, parsers, graph,
advisories, risk) is independent of the CLI, network, and presentation layers.

## Security model

PyDeepMesh treats every scanned file and advisory response as untrusted: it never
executes scanned code, never runs package managers or builds, bounds input
sizes, confines output writes to a configured directory, and never logs or
reports secrets. See [`SECURITY.md`](SECURITY.md).

## Development

```bash
uv pip install -e ".[dev]"
ruff format --check . && ruff check .
mypy
python scripts/check_boundaries.py
pytest --cov=pydeepmesh --cov-report=term-missing
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Limitations

- PyDeepMesh reports **graph reachability**, not proven runtime exploitability.
- Advisory coverage depends on the providers and snapshots available; absence of
  a match is reported as `unmatched`/`unavailable`, never as "safe".
- `yarn.lock` and `Cargo.toml` workspaces are partially supported (see the
  support matrix).
- SPDX export is planned; CycloneDX is implemented.

## Known issues and deferred work

**Blocked / failed:**
- `pip install pydeepmesh` still 404; publish PyPI + Action.
- Container image scanning; reachability precision.

**Rejected / deferred:**
- Another dependency-provenance tool; merge with PyDependencyCheck.

Full shipped/blocked/rejected detail: [`QUEUE_STATUS.md`](QUEUE_STATUS.md).

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
