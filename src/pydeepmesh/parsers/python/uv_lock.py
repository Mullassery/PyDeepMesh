"""Parser for ``uv.lock``."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydeepmesh._compat import tomllib
from pydeepmesh.diagnostics import Severity, make_diagnostic
from pydeepmesh.io import safe_read_text
from pydeepmesh.models.ecosystem import Ecosystem
from pydeepmesh.models.provenance import SourceLocation
from pydeepmesh.models.scope import Scope
from pydeepmesh.parsers.base import DependencyRef, ParsedManifest, Parser, ResolvedPackage
from pydeepmesh.parsers.python.helpers import find_line


class UvLockParser(Parser):
    parser_id = "python.uv_lock"
    ecosystem = Ecosystem.PYPI
    file_names = ("uv.lock",)
    is_root = False

    def parse(self, path: Path, rel_path: str, *, max_bytes: int, root: Path) -> ParsedManifest:
        manifest = self._manifest(path, rel_path)
        read = safe_read_text(path, max_bytes=max_bytes, root=root)
        if read.diagnostic is not None:
            manifest.diagnostics.append(read.diagnostic)
            return manifest
        text = read.text or ""
        try:
            data = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, ValueError) as exc:
            manifest.diagnostics.append(
                make_diagnostic(
                    Severity.ERROR, "toml.invalid", f"invalid TOML: {exc}", path=path, root=root
                )
            )
            return manifest

        packages = data.get("package")
        if not isinstance(packages, list):
            manifest.diagnostics.append(
                make_diagnostic(
                    Severity.WARNING,
                    "uv_lock.no_packages",
                    "lockfile contains no [[package]] entries",
                    path=path,
                    root=root,
                )
            )
            return manifest

        for entry in packages:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            version = entry.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                continue
            scope = Scope.RUNTIME
            if entry.get("source", {}).get("editable") or entry.get("source", {}).get("virtual"):
                scope = Scope.DEVELOPMENT
            refs = _dependency_refs(entry.get("dependencies"))
            refs += _dependency_refs_flat(entry.get("optional-dependencies"))
            refs += _dependency_refs_flat(entry.get("dev-dependencies"))
            manifest.packages.append(
                ResolvedPackage(
                    ecosystem=Ecosystem.PYPI,
                    name=name,
                    version=version,
                    scope=scope,
                    dependencies=tuple(
                        sorted(set(refs), key=lambda r: (r.name, r.constraint or ""))
                    ),
                    origin=SourceLocation(rel_path, find_line(text, f'name = "{name}"')),
                )
            )
        return manifest


def _dependency_refs(deps: Any) -> tuple[DependencyRef, ...]:
    if not isinstance(deps, list):
        return ()
    refs: list[DependencyRef] = []
    for item in deps:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not isinstance(name, str):
            continue
        refs.append(
            DependencyRef(
                name=name,
                constraint=_as_version(item.get("version")),
                optional=bool(item.get("optional", False)),
            )
        )
    return tuple(refs)


def _dependency_refs_flat(groups: Any) -> tuple[DependencyRef, ...]:
    if not isinstance(groups, dict):
        return ()
    refs: list[DependencyRef] = []
    for deps in groups.values():
        refs.extend(_dependency_refs(deps))
    return tuple(refs)


def _as_version(value: Any) -> str | None:
    return value if isinstance(value, str) else None
