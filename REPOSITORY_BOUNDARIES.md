# Repository Boundaries

PyDeepMesh is a **standalone product**. It must install, run, test, build, and release
without any other Mullassery repository being present. This document defines the
hard boundaries that keep it independent, and the one-way, artifact-based
interoperability that is permitted.

## 1. Forbidden coupling

PyDeepMesh MUST NOT, at any time:

- import, copy, vendor, or depend at runtime on source code from any sibling
  repository, including but not limited to:
  `PyDependencyCheck`, `PyNetworkIntel`, `StatGuardian`, `TaskWire`/`CronMesh`,
  `PyDBTGuard`, `PyBlastGuard`, `PyAirflowTester`, `PyTokenCalc`,
  `PyVectorHound`, `PyAgentHound`, `PyRoboSimulator`, `PyTerrainMap`,
  `PyTagManager`.
- add a sibling repository as a Git submodule, editable install, path
  dependency, workspace member, or mandatory service.
- create symlinks pointing into a sibling source directory.
- create cross-repository scripts that mutate a sibling repository.
- require a sibling repository to be present for its own tests, CI, build, or
  release.

## 2. Permitted interoperability (optional, one-way, artifact-based)

Interoperability is allowed only when it is:

1. **Optional** — PyDeepMesh works fully without it.
2. **One-way** — PyDeepMesh produces artifacts; it does not reach into another
   project's internals.
3. **Artifact-based** — the only interface is a documented, versioned file or
   standard format (JSON, SARIF, CycloneDX, SPDX).

PyDeepMesh's stable interchange surfaces are:

| Artifact | Format | Stability |
| --- | --- | --- |
| Scan/report output | PyDeepMesh JSON (`schema_version`) | Versioned |
| Security findings | SARIF 2.1.0 | Standard |
| Software bill of materials | CycloneDX 1.5 JSON | Standard |
| Dependency graph export | PyDeepMesh JSON graph | Versioned |

A consumer may ingest these artifacts without importing PyDeepMesh internals, and
without calling PyDeepMesh as a service. PyDeepMesh never requires a consumer to be
present.

### Approved tooling

CodeAtlas is an approved, first-party architecture-analysis tool. PyDeepMesh may
depend on its published package (`codeatlas-rs`) and commit its generated
artifacts (`codeatlas.json`, `docs/codeatlas/`, `.codeatlas/`). This is a
dependency on a released artifact, not source-level coupling to a sibling
repository, so CodeAtlas is not treated as a sibling repo.

## 3. Automated enforcement

`scripts/check_boundaries.py` enforces the rules above and runs in CI and the
local quality suite. It fails the build if it finds:

- source files that import a sibling repository package (detected structurally
  via the embedded CodeAtlas engine when installed; a text scan is used as a
  fallback so the check still runs before installation);
- references to sibling repository names in config or build files (except this
  document, the boundary checker itself, and tests that assert the checker
  works);
- local path dependencies (`file:` / `path =` pointing outside the repository)
  in `pyproject.toml`;
- Git submodules or nested Git repositories inside the project tree;
- symlinks escaping the repository root.

Run it directly with:

```bash
python scripts/check_boundaries.py
```

## 4. Naming note

The `TaskWire` directory observed under the working directory at project
initialization is an unrelated, untracked directory that is **not** part of
PyDeepMesh. It is excluded via `.gitignore` and is never read, imported, modified,
or executed by PyDeepMesh. PyDeepMesh contains no code that references it.
