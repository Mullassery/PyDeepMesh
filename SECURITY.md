# Security Policy

## Threat model

PyDeepMesh reads untrusted files and network responses. Its security model assumes:

- **Scanned inputs are hostile.** Manifests, lockfiles, Dockerfiles, Compose
  files, and advisory responses may be malformed, oversized, or crafted to
  trigger path traversal, resource exhaustion, or code execution.
- **The environment is trusted** in the sense that the user chooses what to
  scan; PyDeepMesh does not sandbox an adversary-controlled host.

### Guarantees

PyDeepMesh enforces the following, verified by tests:

1. **No execution of scanned code.** PyDeepMesh statically parses text/TOML/YAML/
   JSON. It never runs package managers, lifecycle scripts, Docker builds,
   `make`, or any command from a scanned file.
2. **No writes outside the output directory.** All output paths are resolved and
   checked to stay within an explicitly configured output root (default: the
   current directory) or the advisory cache directory.
3. **Bounded input.** File reads are capped (`config.max_file_bytes`), parsed
   structures are depth- and size-limited, and network responses are capped.
4. **Safe network behavior.** Network access is opt-in (`--online`). Requests
   use explicit timeouts, bounded retries with backoff, and a response size cap.
   No credentials are read from, or sent to, providers.
5. **Secret hygiene.** Reports never include environment variables, tokens, or
   local filesystem paths beyond the scanned root unless explicitly requested.
   Logs are redacted.
6. **Safe temp files.** Temporary files are created with `tempfile` in
   restricted locations and cleaned up; no unsafe archive extraction is
   performed (PyDeepMesh does not extract archives).
7. **Path traversal protection.** Discovered paths are confined to the scan
   root; symlinks that escape the root are not followed.

### Explicit non-goals

- PyDeepMesh does not determine *runtime exploitability*; it reports graph
  reachability and advisory evidence only.
- PyDeepMesh does not guarantee completeness of vulnerability data; missing data is
  surfaced as `unavailable`, never as "clean".

## Dependency hygiene

- Runtime dependencies are deliberately few (`packaging`, `PyYAML`, and `tomli`
  on older Pythons) and version-constrained.
- Development tooling is pinned via `pyproject.toml`.
- CI runs the boundary checker, linting, type checking, and tests on every push.

## Reporting a vulnerability

Report suspected vulnerabilities privately via GitHub Security Advisories on
`https://github.com/Mullassery/PyDeepMesh`, or by opening a minimal issue that does
not disclose exploit details. Please include: affected version, a reproducer
(sample input file and command), and the observed vs. expected behavior.

We aim to acknowledge reports within 5 business days.
