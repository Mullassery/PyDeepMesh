# Comparison

PyDeepMesh builds a **canonical multi-ecosystem dependency graph** and explains
vulnerability exposure. The tools below overlap on parts of that job.

Sources verified on **2026-10-19**:

- Syft — <https://github.com/anchore/syft>
- OSV-Scanner — <https://github.com/google/osv-scanner>
- OWASP Dependency-Check — <https://owasp.org/www-project-dependency-check/>
- Dependabot alerts — <https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts>

Not assessed in this pass: Trivy, Snyk, Socket. This is not a benchmark.

## Pick by problem

| Your problem | Start with | Why |
|---|---|---|
| One graph across Python/Rust/Node/containers | **PyDeepMesh** | Canonical multi-ecosystem graph |
| "Through what path am I exposed?" | **PyDeepMesh** | Reachability paths, reverse deps |
| SBOM for an image/filesystem | Syft | Mature SBOM generation, signed attestations |
| Vulnerability scan across many ecosystems | OSV-Scanner | Broad ecosystem/lockfile coverage, offline DB |
| Multi-language SCA with build-tool integrations | OWASP Dependency-Check | NVD/CPE, Maven/Gradle/Jenkins/Azure |
| Zero-config GitHub alerts/updates | Dependabot | GitHub-native |
| CI findings in SARIF | **PyDeepMesh** or OSV-Scanner | SARIF output |

## Matrix

| Capability | PyDeepMesh | Syft | OSV-Scanner | OWASP DC | Dependabot |
|---|---|---|---|---|---|
| Multi-ecosystem graph | ✅ | SBOM catalog | ✅ | ✅ | ✅ |
| Vulnerability matching | ✅ OSV | — | ✅ OSV | ✅ NVD/CPE | ✅ |
| Exposure paths / reverse deps | ✅ | — | — | — | — |
| SARIF | ✅ | — | ✅ | via integrations | ✅ |
| CycloneDX SBOM | ✅ 1.5 | ✅ | — | — | — |
| Offline advisory snapshot | ✅ | — | ✅ offline DB | local NVD | — |
| Explainable outcome states | ✅ confirmed/potential/unmatched/unavailable/error | — | — | — | — |
| Container image scan | ✅ via Syft | ✅ | ✅ | ✅ | — |
| License | Apache-2.0 | Apache-2.0 | Apache-2.0 | Apache-2.0 | GitHub service |

Legend: ✅ stated in reviewed official docs; — not stated (not proof of absence).

## Differentiation

PyDeepMesh combines a single cross-ecosystem graph, exposure paths, and explicit
uncertainty states with SARIF/CycloneDX/HTML output. Syft and OSV-Scanner are
stronger as standalone SBOM/scanner primitives; PyDeepMesh is the integration
and explanation layer.

## What it does not do

- Prove runtime exploitability (it reports graph reachability).
- Replace PyDependencyCheck for `why`/provenance and unused-dependency
  attribution. See [Project status](STATUS.md).
