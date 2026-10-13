"""Filesystem discovery of dependency manifests and lockfiles.

Discovery is read-only and bounded. It never executes anything and never
follows symlinks that escape the scan root.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

from pydeepmesh.diagnostics import Diagnostic, DiagnosticCollector
from pydeepmesh.io import ensure_within
from pydeepmesh.parsers.registry import default_parsers, parsers_for

DEFAULT_IGNORED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".pydeepmesh-cache",
        "site-packages",
    }
)


@dataclass
class DiscoveredFile:
    """A file matched by a parser, with the parsers that claim it."""

    path: Path
    rel_path: str
    parser_ids: tuple[str, ...]


@dataclass
class DiscoveryResult:
    files: list[DiscoveredFile] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    scanned_dirs: int = 0
    truncated: bool = False


def discover(
    root: Path,
    *,
    include: tuple[str, ...] = (),
    exclude: tuple[str, ...] = (),
    ignored_dirs: frozenset[str] | None = None,
    max_files: int = 20000,
    max_depth: int = 64,
) -> DiscoveryResult:
    """Walk ``root`` and return files claimed by at least one parser."""

    root = root.resolve()
    ignored = ignored_dirs if ignored_dirs is not None else DEFAULT_IGNORED_DIRS
    parsers = default_parsers()
    result = DiscoveryResult()
    collector = DiagnosticCollector()

    if not root.exists():
        collector.error("discovery.missing_root", f"scan root does not exist: {root}")
        result.diagnostics = collector.sorted()
        return result
    if not root.is_dir():
        collector.error("discovery.not_dir", f"scan root is not a directory: {root}")
        result.diagnostics = collector.sorted()
        return result

    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        result.scanned_dirs += 1
        if depth > max_depth:
            collector.warning("discovery.max_depth", f"max depth reached at {directory}")
            continue
        try:
            entries = sorted(directory.iterdir(), key=lambda p: p.name)
        except OSError as exc:
            collector.warning("discovery.unreadable_dir", f"cannot read {directory}: {exc}")
            continue
        for entry in entries:
            name = entry.name
            if entry.is_symlink():
                try:
                    resolved = entry.resolve()
                    ensure_within(resolved, root)
                except Exception:
                    collector.warning(
                        "discovery.symlink_escape",
                        f"skipping symlink escaping root: {entry}",
                    )
                    continue
            if entry.is_dir():
                if name in ignored:
                    continue
                if _is_excluded(name, exclude):
                    continue
                stack.append((entry, depth + 1))
                continue
            if not entry.is_file():
                continue
            if include and not any(fnmatch.fnmatch(name, pattern) for pattern in include):
                continue
            if _is_excluded(name, exclude):
                continue
            matched = parsers_for(entry, parsers)
            if not matched:
                continue
            if len(result.files) >= max_files:
                result.truncated = True
                collector.warning(
                    "discovery.max_files", f"file limit of {max_files} reached; results truncated"
                )
                break
            try:
                rel = str(entry.resolve().relative_to(root))
            except ValueError:
                rel = entry.name
            result.files.append(
                DiscoveredFile(
                    path=entry,
                    rel_path=rel,
                    parser_ids=tuple(p.parser_id for p in matched),
                )
            )
        if result.truncated:
            break

    result.files.sort(key=lambda f: f.rel_path)
    result.diagnostics = collector.sorted()
    return result


def _is_excluded(name: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatch(name, pattern) for pattern in patterns)


def severity_counts(diagnostics: list[Diagnostic]) -> dict[str, int]:
    counts = {"info": 0, "warning": 0, "error": 0}
    for diagnostic in diagnostics:
        counts[diagnostic.severity.label] += 1
    return counts
