# Competitive intelligence in roadmap and upgrade work

**Policy date:** 2026-10-19

Competitive findings are an input to product decisions, not a one-off report.
Every pending roadmap item, new feature, and routine dependency upgrade should
check the repository's [`AUDIT_FINDINGS.md`](AUDIT_FINDINGS.md) before work
starts, and record the decision in the PR or changelog.

## Required check before building

1. **Read `AUDIT_FINDINGS.md`.** Find the relevant competitor row and the
   ranked next actions. If the finding is stale, update it with a dated source.
2. **Name the competitor and the user problem.** A feature is not justified by
   "competitor has it". State the workflow it unlocks, who needs it, and how
   often. Mark unverified demand as a hypothesis.
3. **Prefer reuse over new code.** Check whether an existing Mullassery repo
   already provides the capability (see `BUNDLES.md` in the profile repo and
   the bundle role file in this repo, when present). Typical reuse:
   - crawling/fetching/robots/SSRF → **MudFish**
   - architecture maps / PR diffs → **CodeAtlas**
   - data-quality contracts / validation → **StatGuardian**
   - token counting / cost tables → **PyTokenCalc**
   - dependency graph / advisories / SBOM → **PyDeepMesh**
   - segmentation / CLV / churn → **ClusterAudienceKit**
   - activation / lineage / PII → **PyReverseETL**
   - fleet state sync → **SyncFleet** (only after conflict resolution)
4. **Choose one disposition:** build, integrate, defer, or reject. Write it
   down. A rejection with a reason is a successful outcome.
5. **For routine upgrades**, check whether the upgrade closes a known
   competitor gap or breaks a differentiated capability. Run the tests that
   cover the affected path; do not merge a green build that silently changes a
   user-visible contract.

## PR / changelog checklist

- [ ] Competitor and source URL/date recorded (or "no direct competitor").
- [ ] User impact and frequency stated; unverified demand labelled.
- [ ] Reuse check done against sibling repos/bundles.
- [ ] Failure mode and rollback considered (especially auth, PII, cost).
- [ ] Docs/roadmap status updated honestly.
- [ ] Tests or a manual verification command included.

## Review cadence

- Refresh the competitor row when a release changes the capability.
- Re-check the full `AUDIT_FINDINGS.md` at least quarterly and before a major
  release.
- If a finding is wrong or stale, correct it in the same PR that relies on it.

## Non-goals

- Copying features for parity.
- Adding a dependency just because a competitor uses it.
- Treating star counts or download counts as proof of user need.

## OSS gap analysis — 2026-10-24

Scope: PyDeepMesh assessed against four maintained dependency scanners on source/lockfile coverage, container image scanning, advisory breadth and freshness, SBOM/SARIF output, offline operation, remediation, and CI policy. Package-level vulnerability matching was the basis; runtime exploitability was out of scope for every tool.

### Comparable OSS projects

| Project | GitHub | License | Last activity | Why it is the comparison |
| --- | --- | --- | --- | --- |
| OSV-Scanner | https://github.com/google/osv-scanner | Apache-2.0 | v2.7.0, 2026-10-12 | Closest direct analogue: OSV-backed source and container scanning, offline databases, SARIF, guided remediation. |
| Trivy | https://github.com/aquasecurity/trivy | Apache-2.0 | v0.76.1, 2026-10-21 | Broadest ecosystem and artifact coverage; the default CI scanner PyDeepMesh will be compared against. |
| Grype | https://github.com/anchore/grype | Apache-2.0 | v0.121.0, 2026-10-19 | Vulnerability matching over Syft SBOMs and images; the container/SBOM counterpart to our Syft adapter. |
| pip-audit | https://github.com/pypa/pip-audit | Apache-2.0 | v2.10.1, 2026-06-10 | Python-only baseline with environment auditing and automatic dependency fixes; the bar for Python remediation. |

### Capability comparison

| Capability | Ours | OSV-Scanner | Trivy | Grype | pip-audit | Gap |
| --- | --- | --- | --- | --- | --- | --- |
| Cross-ecosystem source coverage | Partial | Yes | Yes | Yes | No | Large |
| Manifest and lockfile parsing | Partial | Yes | Yes | Partial | Partial | Small |
| Container image scanning | Partial | Yes | Yes | Yes | No | Medium |
| Multiple advisory sources | Partial | Partial | Yes | Yes | Yes | Large |
| Advisory freshness | Partial | Yes | Yes | Yes | Yes | Medium |
| SBOM output | Partial | No | Yes | No | Partial | Medium |
| SARIF and severity gating | Yes | Yes | Yes | Yes | No | Small |
| Offline / air-gapped | Yes | Yes | Yes | Yes | No | None |
| Guided remediation | No | Yes | No | No | Yes | Large |
| Ignore/waiver policy | No | Yes | Yes | Yes | Partial | Medium |
| Unified cross-ecosystem graph | Yes | No | Partial | No | No | Ahead |
| Dependency-path reachability | Yes | Partial | Partial | No | No | Ahead |
| Deterministic output | Yes | Partial | Partial | Partial | Partial | Ahead |

Nuance: our source coverage is PyPI, npm, crates.io, Dockerfile/Compose, plus optional Syft image cataloging; OSV-Scanner, Trivy, and Grype cover substantially more source ecosystems (Java, Go, Ruby, PHP, .NET, and others). Our `yarn.lock` and Cargo workspaces are partial. Grype consumes Syft catalogers, so SBOM generation belongs to Syft, not Grype. pip-audit audits installed environments and project/requirements resolution but does not parse every Python lockfile, and its `--ignore-vuln` is ID-based only. "Reachability" here means a path exists in the resolved dependency graph, not that vulnerable code is invoked at runtime; Trivy's and OSV-Scanner's partial marks reflect dependency-tree/group output, not path queries. Determinism cells marked Partial mean "not documented in the inspected docs", not proof that output is non-deterministic.

### Gaps that matter (ranked)

1. **Advisory breadth and source redundancy** — we consume OSV only, while Trivy combines GHSA, OSV, and OS vendor feeds with NVD severity fallback. A missed or delayed OSV record becomes a false clean result for our users; adding providers is S/M effort behind the existing `AdvisoryProvider` interface.
2. **No guided remediation** — we report fix candidates but cannot produce or apply an upgrade plan. OSV-Scanner's `fix` and pip-audit `--fix` close the loop; a dry-run planner that edits lockfiles without executing package managers is M effort and fits our no-execution model.
3. **No waiver or exception policy** — enterprises need scoped, expiring suppressions and VEX-aware decisions. Trivy offers ignore rules and VEX; OSV-Scanner offers config overrides; we have none, so users must filter output downstream. S/M effort.
4. **Container scanning is delegated, not owned** — the Syft adapter is real but requires an external binary and inherits Syft's cataloging gaps; OSV-Scanner and Trivy scan images natively, including OS packages. This limits air-gapped image scans and distro advisory accuracy. M/L effort.
5. **Ecosystem coverage is narrow** — Java, Go, Ruby, PHP, and .NET projects cannot use the canonical graph at all. That is a credible reason to choose Trivy or OSV-Scanner for polyglot estates; each added ecosystem is S/M, but parity is L overall.
6. **Distribution is thinner than the feature set** — PyPI 0.1.1 is live, but there is no official GitHub Action, pre-commit hook, or container image, while OSV-Scanner and Trivy publish all three. S/M effort with outsized adoption impact.

### Where we are differentiated

- A single canonical graph spans Python, Rust, Node.js, and container manifests with per-node/edge provenance and resolution confidence, enabling path and reverse-dependency questions the scanners answer only per artifact.
- Explicit `confirmed`/`potential`/`unmatched`/`unavailable`/`error` states make absence of evidence visible; competitors generally report only matches.
- Offline-first operation with an explicit `--online` opt-in, deterministic byte-identical output, and no execution of scanned code or lifecycle scripts.
- A self-contained, JavaScript-free HTML graph plus SARIF and CycloneDX from the same analysis result.

### Disposition

- **Build:** additional advisory providers (GHSA/NVD/vendor feeds), a scoped waiver/exception engine, and a dry-run remediation planner that never runs package managers.
- **Integrate/reuse:** keep Syft as the container cataloger; add OSV database snapshots rather than reimplementing feeds; ship an official GitHub Action and pre-commit hook around the existing CLI.
- **Defer/reject:** native image-layer scanning, broad ecosystem parity, and any claim of runtime exploitability or true code reachability. Reject merging with PyDependencyCheck until ownership is decided.

### Sources

- https://github.com/google/osv-scanner and https://google.github.io/osv-scanner/usage/ (accessed 2026-10-24)
- https://github.com/aquasecurity/trivy and https://aquasecurity.github.io/trivy/latest/docs/scanner/vulnerability/ (accessed 2026-10-24)
- https://github.com/anchore/grype (accessed 2026-10-24)
- https://github.com/pypa/pip-audit and its README CLI reference (accessed 2026-10-24)
- Repo files inspected: `README.md`, `COMPETITIVE_INTELLIGENCE.md`, `AUDIT_FINDINGS.md`, `ARCHITECTURE.md`, `SUPPORT_MATRIX.md`, `pyproject.toml`, `src/pydeepmesh/integrations/syft.py`, `src/pydeepmesh/cli/main.py`
