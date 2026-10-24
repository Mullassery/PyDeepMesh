# Audit findings — 2026-10-19

This file records the repository-specific findings from the portfolio audit
conducted on 2026-10-19. It is documentation only; no code or release artifacts
were changed in this pass unless explicitly noted under "Implementation status".

Sources: the repository's own README/source/workflows, GitHub metadata and
Actions runs, PyPI metadata, and official competitor documentation. Claims are
marked as verified, inferred, or open questions. "Absent" means not found in the
inspected repository/docs, not proof that it cannot exist.

## What it is

Cross-ecosystem dependency-graph, vulnerability, and attack-surface intelligence for Python, Rust, Node.js, and container projects.

## Verified strengths

- Python/Rust/Node/container manifests and lockfiles; canonical graph; PEP 440/SemVer matching; offline OSV snapshot; reachability paths; SARIF 2.1.0; CycloneDX 1.5; self-contained HTML; explicit confirmed/potential/unmatched outcomes; 17 test files.
- Offline/air-gapped operation and reachability are real differentiators.

## Verified gaps and user-facing risks

- `pip install pydeepmesh` returns 404 — the documented install path does not work.
- `main` CI failed on 2026-10-18; no release/tag; no container image scanning; no guided remediation; no benchmark vs OSV/Trivy.
- Overlaps PyDependencyCheck without a clear boundary.

## Direct competitors

- OSV-Scanner (multi-ecosystem, guided remediation, containers), Syft/Grype, Trivy, Dependabot.

## Ranked next actions

- P1: publish PyPI + tag/release + GitHub Action (S).
- P1: define boundary/merge with PyDependencyCheck (M).
- P2: container image scanning + reachability precision/recall (L).

## Do not build

- Another dependency-provenance tool; consolidate with PyDependencyCheck.

## Evidence gaps / validation needed

- No benchmark; no container-image verification; no air-gapped user validation.

## Recommended disposition

Invest as the portfolio's dependency-intelligence engine after distribution is fixed.

## Implementation status

No code changes in this pass.
