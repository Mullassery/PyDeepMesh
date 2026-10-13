# Changelog

All notable changes to PyDeepMesh are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Renamed the project from DepMesh to **PyDeepMesh**: distribution name
  `pydeepmesh`, import package `pydeepmesh`, CLI command `pydeepmesh`,
  environment variables `PYDEEPMESH_*`, config `pydeepmesh.toml`, and cache
  directories `.pydeepmesh*`.

## [0.1.0]

### Added

- Dependency discovery and parsers for:
  - Python: `pyproject.toml`, `requirements*.txt`, `poetry.lock`, `uv.lock`.
  - Rust: `Cargo.toml`, `Cargo.lock`.
  - Node.js: `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`.
  - Containers: `Dockerfile`, Compose manifests.
- Canonical dependency graph with provenance, scopes, resolution status,
  traversal, reverse-dependency queries, path analysis, and cycle detection.
- Provider-neutral advisory interface with an OSV provider, offline snapshot
  provider, and on-disk cache.
- Ecosystem-aware version and affected-range matching (PEP 440 for PyPI,
  semantic versioning for npm/crates.io, OSV event semantics).
- Risk analysis: direct vs. transitive exposure, dependency concentration,
  reachable paths, fix candidates, and explainable prioritization.
- Reports: terminal summary, versioned JSON, SARIF 2.1.0, CycloneDX 1.5 SBOM.
- Self-contained, dependency-free local HTML graph viewer (static HTML + inline
  SVG; no JavaScript, no CDN, no telemetry).
- Repository-boundary enforcement (`scripts/check_boundaries.py`) and CI.
