# Bundle role — Repo health / CI

This repository is part of the **Repo health / CI** bundle. Portfolio-level rationale,
reuse map, and phases are in [`Mullassery/BUNDLES.md`](https://github.com/Mullassery/Mullassery/blob/main/BUNDLES.md).

- **Role:** Dependency graph, advisories, SBOM, SARIF
- **Upstream/downstream:** All repos, PyDependencyCheck
- **Next integration step:** Publish PyPI + Action; define/merge the PyDependencyCheck boundary; add container scanning.
- **Non-goal:** Duplicate provenance/unused-dependency features.

## Contract checklist

- [ ] Versioned interface (package/crate/API), not an unpinned git URL.
- [ ] Optional extra or separate service; standalone use remains possible.
- [ ] Shared event/profile/observation contract documented where relevant.
- [ ] Integration test or demo proves the boundary.
- [ ] Competitive context recorded in `AUDIT_FINDINGS.md`.

See `COMPETITIVE_INTELLIGENCE.md` for the required check before roadmap or
feature work on this bundle.
