# Support Matrix

This matrix separates what PyDeepMesh actually implements from what is partial,
planned, or unsupported. A capability is only marked **Implemented** when code
exists and is covered by tests. Claims elsewhere in the repository must not
exceed this matrix.

## Manifest and lockfile parsing

| Ecosystem | File | Status | Notes |
| --- | --- | --- | --- |
| Python | `pyproject.toml` | Implemented | PEP 621 `[project]` + Poetry `[tool.poetry]`/PEP 621 deps; `[tool.uv]` extras ignored gracefully |
| Python | `requirements*.txt` | Partial | `-r`/`--requirement`, `-c`/`--constraint`, `-e`, and extras handled; environment markers are parsed but not evaluated; `--hash=` lines are not supported (reported as diagnostics) |
| Python | `poetry.lock` | Implemented | `package` entries with dependencies; groups/scopes |
| Python | `uv.lock` | Implemented | `package` entries, `dependencies`, resolution markers |
| Python | `Pipfile.lock` | Planned | Parsed best-effort is not yet implemented |
| Rust | `Cargo.toml` | Implemented | `[dependencies]`, `dev-`, `build-`, target-specific, optional, workspace deps |
| Rust | `Cargo.lock` | Implemented | Resolved packages and dependency edges |
| Rust | `Cargo.toml` `[workspace]` | Partial | Members resolved when present as manifests in the tree |
| Node.js | `package.json` | Implemented | `dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies` |
| Node.js | `package-lock.json` | Implemented | Lockfile v1/v2/v3 `packages` and legacy `dependencies` |
| Node.js | `pnpm-lock.yaml` | Implemented | `importers` + `packages`/`snapshots` |
| Node.js | `yarn.lock` | Partial | Classic (v1) and Berry (v2+) top-level entries; pathological cases diagnosed |
| Container | `Dockerfile` | Implemented | `FROM` (incl. `AS`, `--platform`), `ARG`, digest preservation |
| Container | `docker-compose.yml` / `compose.yaml` | Implemented | `services.*.image`, `build`, `depends_on` |

## Graph and analysis

| Capability | Status | Notes |
| --- | --- | --- |
| Canonical graph + provenance | Implemented | Nodes/edges carry source file, line, scope, resolution |
| Transitive traversal, reverse deps | Implemented | Deterministic ordering |
| Path analysis, cycle detection | Implemented | Bounded path enumeration |
| Direct vs. transitive exposure | Implemented | |
| Dependency concentration | Implemented | Fan-in counts and top-dependency reporting |
| Reachability vs. exploitability distinction | Implemented | Explicitly reported; exploitability never asserted |

## Vulnerability intelligence

| Capability | Status | Notes |
| --- | --- | --- |
| OSV online provider | Implemented | `POST /v1/querybatch`; timeout, retry, size cap |
| Offline snapshot provider | Implemented | Directory of OSV JSON records |
| Advisory cache | Implemented | Content-addressed, TTL, offline-first |
| Ecosystem-aware version matching | Implemented | PEP 440 for PyPI; SemVer for npm/crates.io |
| Confirmed/potential/unmatched/unavailable/error states | Implemented | |
| Other vendors (GHSA direct, NVD) | Planned | OSV already aggregates GHSA; direct NVD not implemented |

## Reports and interoperability

| Format | Status | Notes |
| --- | --- | --- |
| Terminal summary | Implemented | |
| PyDeepMesh JSON (`schema_version`) | Implemented | Versioned, deterministic |
| SARIF 2.1.0 | Implemented | Validated against schema in tests |
| CycloneDX 1.5 JSON | Implemented | Validated against schema in tests |
| SPDX | Planned | CycloneDX chosen first; SPDX not yet implemented |
| Local graph viewer | Implemented | Static HTML + inline SVG, no JavaScript, no CDN, no telemetry; deterministic |

## Operating modes

| Mode | Status | Notes |
| --- | --- | --- |
| Offline (default) | Implemented | No network unless `--online` |
| Online advisory queries | Implemented | Explicit opt-in per command |
| Advisory cache update | Implemented | `pydeepmesh advisories update` only |
