# Quickstart

> Commands below were run against this repository on 2026-10-19. Output is
> illustrative; your project's numbers will differ.

## 1. Install

```bash
pip install pydeepmesh
pydeepmesh --version
```

Requires Python 3.10+. See [Install](INSTALL.md).

## 2. Scan the project graph

```bash
pydeepmesh scan . --format json
```

This discovers manifests/lockfiles (Python, Rust, Node, Docker/Compose), parses
them defensively, and prints the canonical graph as versioned JSON. Use
`--format terminal` for a summary.

## 3. Audit for vulnerabilities and exposure

Offline (uses a local advisory snapshot if provided):

```bash
pydeepmesh audit . --offline
```

Online (queries the configured advisory provider):

```bash
pydeepmesh audit . --online --fail-on high
```

Output distinguishes **confirmed**, **potential**, **unmatched**,
**unavailable**, and **error**. `unmatched` is **not** a clean bill of health.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success; no finding met `--fail-on` |
| 1 | A finding met `--fail-on` |
| 2 | Usage/configuration error |
| 3 | Input error prevented analysis |
| 4 | Advisory data unavailable when required |

## 4. Emit an SBOM

```bash
pydeepmesh sbom . --output sbom.cdx.json
```

The output must stay inside the output root (default: the scanned project). To
write elsewhere, add `--output-root`:

```bash
pydeepmesh sbom . --output /tmp/sbom.cdx.json --output-root /tmp
```

CycloneDX 1.5 is implemented; SPDX export is planned.

## 5. Inspect the graph

```bash
# Static HTML graph (no JavaScript, no CDN, no telemetry)
pydeepmesh graph . --format html --output graph.html

# Paths between packages, reverse dependencies, cycles
pydeepmesh graph . --paths requests urllib3
pydeepmesh graph . --reverse urllib3
```

## 6. Container images (optional)

Image cataloging requires the Apache-2.0 Syft binary (not vendored):

```bash
brew install syft
pydeepmesh image ghcr.io/example/app:latest --format json
```

If Syft is missing, the command raises `SyftUnavailable` instead of reporting an
empty image.

## Next

- [Install](INSTALL.md)
- [Project status](STATUS.md)
- [Comparison](COMPARISON.md)
- [Architecture](../ARCHITECTURE.md)
