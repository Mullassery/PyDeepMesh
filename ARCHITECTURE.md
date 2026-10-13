# PyDeepMesh Architecture

PyDeepMesh converts heterogeneous dependency metadata (Python, Rust, Node.js, and
container manifests/lockfiles) into a single canonical dependency graph, matches
that graph against advisory data, and emits explainable security and dependency
intelligence as machine- and human-readable artifacts.

## Design principles

1. **Deterministic** — identical inputs produce byte-identical outputs.
   Ordering and identifiers are stable and derived from content.
2. **Separation of concerns** — parsing, normalization, graph construction,
   advisory evaluation, scoring, and serialization are independent components.
   Core domain logic does not depend on the CLI framework, network services, or
   presentation layers.
3. **Provenance everywhere** — every node and edge records where it came from
   and how confident the resolution is.
4. **Evidence, not guesses** — vulnerability results distinguish *confirmed*,
   *potential*, *unmatched*, *unavailable*, and *error*. Absence of an advisory
   is never reported as "safe".
5. **Untrusted input** — every scanned file and advisory response is treated as
   hostile. PyDeepMesh never executes scanned code or lifecycle scripts.

## Module map

```
pydeepmesh
├── cli/            Command-line interface, argument parsing, exit codes, output routing
├── config/         Configuration model and loading (file + environment + flags)
├── diagnostics/    Structured diagnostics, severity, and error types
├── models/         Canonical domain types (ecosystem, package, graph, vuln, finding, provenance)
├── discovery/      Filesystem discovery of manifests/lockfiles and undo/scan orchestration
├── parsers/        Ecosystem adapters: Python, Rust, Node.js, container
├── graph/          Canonical graph construction and algorithms (paths, reverse deps, cycles)
├── advisories/     Provider interfaces, OSV client, offline snapshots, cache, version matching
├── risk/           Findings, explainable prioritization, remediation, attack-surface analysis
├── sbom/           CycloneDX export/validation
├── report/         Terminal, JSON, and SARIF serialization
└── viz/            Optional local, dependency-free graph export/viewer
```

## Data flow

```
filesystem ──discovery──▶ DiscoveredFile[]
                              │
                          parsers (per ecosystem)
                              │  ParsedManifest {declared, resolved, edges, diagnostics, provenance}
                              ▼
                    graph.builder ──▶ DependencyGraph (nodes, edges, roots, diagnostics)
                              │
        advisories (provider-neutral) ──matcher──▶ [Vulnerability | Unavailable | Error]
                              │
                        risk.analysis ──▶ Findings (explained priority, remediation)
                              │
             report/sbom ──▶ terminal | JSON | SARIF | CycloneDX | graph export
```

## Key contracts

- `models.graph.DependencyGraph` — the canonical graph. Nodes are packages
  (ecosystem + normalized name + version + scope + resolution status); edges are
  dependency relationships with provenance and confidence.
- `parsers.base.Parser` — a `Parser` declares which files it claims
  (`matches`) and yields a `ParsedManifest`. Parsers never raise for malformed
  input; they emit `Diagnostic`s and return partial data.
- `advisories.base.AdvisoryProvider` — provider-neutral interface returning
  normalized `Advisory` records or an explicit `Unavailable` marker.
- `report` writers — pure functions from analysis results plus options to a
  deterministic byte string.

## Extensibility

Adding an ecosystem means implementing one `Parser` and registering it in
`parsers.registry`. Adding an advisory source means implementing one
`AdvisoryProvider` and registering it in `advisories.registry`. Neither change
touches the graph, risk, or report layers.

## Stability

- The **CLI** and the **`pydeepmesh.reporting.schema_version`** machine-readable
  output schema are the versioned public interfaces.
- The Python API under `pydeepmesh.api` is a small, supported facade. Other
  internal modules may change between minor versions.
