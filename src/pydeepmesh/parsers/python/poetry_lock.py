"""Parser for ``poetry.lock``."""

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

_CATEGORY_SCOPES = {
    "main": Scope.RUNTIME,
    "dev": Scope.DEVELOPMENT,
    "test": Scope.TEST,
}


class PoetryLockParser(Parser):
    parser_id = "python.poetry_lock"
    ecosystem = Ecosystem.PYPI
    file_names = ("poetry.lock",)
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
                    "poetry_lock.no_packages",
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
                manifest.diagnostics.append(
                    make_diagnostic(
                        Severity.WARNING,
                        "poetry_lock.missing_fields",
                        "a [[package]] entry is missing name or version",
                        path=path,
                        root=root,
                    )
                )
                continue
            scope = _scope_from_entry(entry)
            refs = _dependency_refs(entry.get("dependencies"))
            manifest.packages.append(
                ResolvedPackage(
                    ecosystem=Ecosystem.PYPI,
                    name=name,
                    version=version,
                    scope=scope,
                    dependencies=refs,
                    origin=SourceLocation(rel_path, find_line(text, f'name = "{name}"')),
                )
            )
        return manifest


def _scope_from_entry(entry: dict[str, Any]) -> Scope:
    groups = entry.get("groups")
    if isinstance(groups, list) and groups:
        if any(g == "main" for g in groups):
            return Scope.RUNTIME
        if any(g in ("dev", "develop") for g in groups):
            return Scope.DEVELOPMENT
        if any(g in ("test", "tests") for g in groups):
            return Scope.TEST
    category = entry.get("category")
    if isinstance(category, str):
        return _CATEGORY_SCOPES.get(category, Scope.RUNTIME)
    return Scope.RUNTIME


def _dependency_refs(deps: Any) -> tuple[DependencyRef, ...]:
    if not isinstance(deps, dict):
        return ()
    refs: list[DependencyRef] = []
    for name, spec in deps.items():
        if isinstance(spec, str):
            refs.append(DependencyRef(name=name, constraint=spec))
        elif isinstance(spec, dict):
            refs.append(
                DependencyRef(
                    name=name,
                    constraint=_as_version(spec.get("version")),
                    optional=bool(spec.get("optional", False)),
                )
            )
        elif isinstance(spec, list):
            for item in spec:
                if isinstance(item, dict):
                    refs.append(
                        DependencyRef(
                            name=name,
                            constraint=_as_version(item.get("version")),
                            optional=bool(item.get("optional", False)),
                        )
                    )
    return tuple(sorted(refs, key=lambda r: (r.name, r.constraint or "")))


def _as_version(value: Any) -> str | None:
    return value if isinstance(value, str) else None
