# Queue status — 2026-10-19

This file records what was shipped, what is blocked/failed, and what is rejected for this repository. It complements `AUDIT_FINDINGS.md`.

## Shipped
- Ruff formatting fix for CI; audit docs.

## Blocked / failed
- `pip install pydeepmesh` still 404; publish PyPI + Action.
- Container image scanning; reachability precision.

## Rejected / deferred
- Another dependency-provenance tool; merge with PyDependencyCheck.

## Policy

Any future feature or upgrade must check `AUDIT_FINDINGS.md` and this file before implementation. A blocked item is retried only when its external dependency is available; a rejected item needs new user evidence or a design change to reopen.
