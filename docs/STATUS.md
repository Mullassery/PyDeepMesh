# Project status

**Version:** 0.1.0 (alpha) · **Updated:** 2026-10-19

## Working today

- Discovery and defensive parsing of Python, Rust, Node, Dockerfile, and
  Compose inputs (see [Support matrix](../SUPPORT_MATRIX.md) for partials).
- Canonical dependency graph with scopes, resolution status, transitive edges,
  and multiple project roots.
- Advisory matching with ecosystem-aware version semantics (PEP 440/SemVer).
- Exposure analysis: direct/transitive, reachable paths, reverse dependencies,
  concentration, fix candidates.
- Outputs: terminal, versioned JSON, SARIF 2.1.0, CycloneDX 1.5, static HTML.
- Explicit outcome states: confirmed, potential, unmatched, unavailable, error.
- Offline advisory cache/snapshots; `advisories update|clear`.
- Optional container image cataloging via an external Syft binary.

## Verified gaps

| Gap | Impact | Status |
|---|---|---|
| No official GitHub Action | CI use requires a manual step (SARIF exists) | Planned |
| Reachability is graph-based, not runtime exploitability | Potential false confidence if misread | Documented limitation |
| `yarn.lock` and Cargo workspaces partially supported | Some transitive coverage missing | Partial |
| SPDX export | Only CycloneDX 1.5 is implemented | Planned |
| PyPI license metadata is `None` | License scanners/trust signals | Open |
| Alpha maturity | CLI/output schema may change | By design |

## Not a goal

- Dependency provenance/usage attribution (`why`, unused deps) — that is
  PyDependencyCheck's scope.
- dbt/Airflow linting, pipeline cost, runtime data quality, network discovery,
  or API/agent diagnosis.
- Multi-ecosystem scanning is intentionally owned here; provenance is not.

## Verify

```bash
pydeepmesh scan . --format json
pydeepmesh audit . --offline
pydeepmesh sbom . --output sbom.cdx.json
```

See [Quickstart](QUICKSTART.md), [Comparison](COMPARISON.md), and
[`internal/QUEUE_STATUS.md`](internal/QUEUE_STATUS.md).
