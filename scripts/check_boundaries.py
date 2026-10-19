#!/usr/bin/env python3
"""Enforce PyDeepMesh repository-boundary rules.

This script fails (exit code 1) if it detects coupling to sibling repositories
or other boundary violations described in REPOSITORY_BOUNDARIES.md.

It is intentionally dependency-free so it can run before installation.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

SIBLING_NAMES = [
    "PyDependencyCheck",
    "PyNetworkIntel",
    "StatGuardian",
    "TaskWire",
    "CronMesh",
    "CodeAtlas",
    "PyDBTGuard",
    "PyBlastGuard",
    "PyAirflowTester",
    "PyTokenCalc",
    "PyVectorHound",
    "PyAgentHound",
    "PyRoboSimulator",
    "PyTerrainMap",
    "PyTagManager",
]

_SIBLING_LOWER = {name.lower() for name in SIBLING_NAMES}


def _skip_dir(name: str) -> bool:
    """Caches and unrelated build dirs are never part of this repo.

    Sibling-repository *names* are deliberately NOT skipped here: a directory
    named after a sibling must be scanned (and is separately flagged by
    :func:`check_sibling_directories`), otherwise vendoring a sibling under a
    sibling-named directory would silently evade the boundary checks.
    """

    return name in SKIP_DIRS


TEXT_SUFFIXES = {
    ".py",
    ".toml",
    ".cfg",
    ".ini",
    ".txt",
    ".json",
    ".yaml",
    ".yml",
    ".md",
    ".rst",
    ".sh",
    ".bash",
    ".zsh",
}

# Prose documentation is exempt from the sibling-name rule. The rule exists to
# catch real coupling (imports, path dependencies, vendoring) in source, config,
# or build files; portfolio/bundle docs legitimately name sibling projects to
# describe positioning, which is not coupling. See REPOSITORY_BOUNDARIES.md §3.
PROSE_SUFFIXES = {".md", ".rst"}

SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "build",
    "dist",
    ".eggs",
    "node_modules",
}

# Files allowed to mention sibling names: this checker, the boundary docs, the
# support matrix, and the boundary tests that assert the checker behaves.
ALLOWED_REFERENCES = {
    Path("scripts/check_boundaries.py"),
    Path("REPOSITORY_BOUNDARIES.md"),
    Path("SUPPORT_MATRIX.md"),
    Path("tests/security/test_repository_boundaries.py"),
    Path(".gitignore"),
}


@dataclass
class Violation:
    rule: str
    path: str
    detail: str

    def __str__(self) -> str:
        return f"[{self.rule}] {self.path}: {self.detail}"


def _iter_files() -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(REPO_ROOT):
        dirnames[:] = [d for d in dirnames if not _skip_dir(d)]
        for name in filenames:
            files.append(Path(dirpath) / name)
    return files


def check_sibling_references() -> list[Violation]:
    violations: list[Violation] = []
    patterns = [(name, re.compile(re.escape(name), re.IGNORECASE)) for name in SIBLING_NAMES]
    for path in _iter_files():
        rel = path.relative_to(REPO_ROOT)
        if rel in ALLOWED_REFERENCES:
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if path.suffix.lower() in PROSE_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for name, pattern in patterns:
            if pattern.search(text):
                violations.append(
                    Violation(
                        "sibling-reference",
                        str(rel),
                        f"references sibling repository name '{name}'",
                    )
                )
    return violations


def check_path_dependencies() -> list[Violation]:
    violations: list[Violation] = []
    pyproject = REPO_ROOT / "pyproject.toml"
    if not pyproject.exists():
        return violations
    text = pyproject.read_text(encoding="utf-8")
    for match in re.finditer(r'(?i)(path|file)\s*=\s*"([^"]+)"', text):
        target = match.group(2)
        if target.startswith("..") or Path(target).is_absolute():
            violations.append(
                Violation("path-dependency", "pyproject.toml", f"local path dependency '{target}'")
            )
    for match in re.finditer(r"(?i)(-e|--editable)\s+\.\.", text):
        violations.append(
            Violation(
                "path-dependency", "pyproject.toml", f"editable parent install '{match.group(0)}'"
            )
        )
    return violations


def check_sibling_directories() -> list[Violation]:
    violations: list[Violation] = []
    for dirpath, dirnames, _ in os.walk(REPO_ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in list(dirnames):
            if name.lower() in _SIBLING_LOWER:
                candidate = Path(dirpath) / name
                violations.append(
                    Violation(
                        "sibling-directory",
                        str(candidate.relative_to(REPO_ROOT)),
                        f"directory named after sibling repository '{name}'",
                    )
                )
    return violations


def check_submodules_and_nested_repos() -> list[Violation]:
    violations: list[Violation] = []
    gitmodules = REPO_ROOT / ".gitmodules"
    if gitmodules.exists():
        violations.append(Violation("submodule", ".gitmodules", "submodules are not permitted"))
    for dirpath, dirnames, _ in os.walk(REPO_ROOT):
        dirnames[:] = [d for d in dirnames if d == ".git" or not _skip_dir(d)]
        for name in dirnames:
            if name != ".git":
                continue
            candidate = Path(dirpath) / name
            if candidate == REPO_ROOT / ".git":
                continue
            violations.append(
                Violation(
                    "nested-repo",
                    str(candidate.relative_to(REPO_ROOT)),
                    "nested Git repository",
                )
            )
    return violations


def check_escaping_symlinks() -> list[Violation]:
    violations: list[Violation] = []
    root = REPO_ROOT.resolve()
    for dirpath, dirnames, filenames in os.walk(REPO_ROOT):
        dirnames[:] = [d for d in dirnames if not _skip_dir(d)]
        for name in list(dirnames) + list(filenames):
            p = Path(dirpath) / name
            if p.is_symlink():
                try:
                    resolved = p.resolve()
                except OSError:
                    continue
                if not resolved.is_relative_to(root):
                    violations.append(
                        Violation(
                            "escaping-symlink",
                            str(p.relative_to(REPO_ROOT)),
                            f"symlink escapes repository root -> {resolved}",
                        )
                    )
    return violations


def main() -> int:
    all_violations: list[Violation] = []
    all_violations += check_sibling_references()
    all_violations += check_sibling_directories()
    all_violations += check_path_dependencies()
    all_violations += check_submodules_and_nested_repos()
    all_violations += check_escaping_symlinks()

    if all_violations:
        print("Repository boundary violations detected:\n", file=sys.stderr)
        for violation in all_violations:
            print(f"  {violation}", file=sys.stderr)
        return 1

    print("Repository boundaries OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
