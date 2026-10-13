"""Parser for ``package-lock.json`` (lockfile versions 1, 2 and 3)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydeepmesh.diagnostics import Severity, make_diagnostic
from pydeepmesh.io import safe_read_text
from pydeepmesh.models.ecosystem import Ecosystem
from pydeepmesh.models.provenance import SourceLocation
from pydeepmesh.models.scope import Scope
from pydeepmesh.parsers.base import (
    Dependency,
    DependencyRef,
    ParsedManifest,
    Parser,
    ResolvedPackage,
)


class PackageLockParser(Parser):
    parser_id = "node.package_lock"
    ecosystem = Ecosystem.NPM
    file_names = ("package-lock.json", "npm-shrinkwrap.json")
    is_root = False

    def parse(self, path: Path, rel_path: str, *, max_bytes: int, root: Path) -> ParsedManifest:
        manifest = self._manifest(path, rel_path)
        read = safe_read_text(path, max_bytes=max_bytes, root=root)
        if read.diagnostic is not None:
            manifest.diagnostics.append(read.diagnostic)
            return manifest
        try:
            data = json.loads(read.text or "")
        except json.JSONDecodeError as exc:
            manifest.diagnostics.append(
                make_diagnostic(
                    Severity.ERROR,
                    "json.invalid",
                    f"invalid JSON: {exc.msg} (line {exc.lineno})",
                    path=path,
                    root=root,
                    line=exc.lineno,
                )
            )
            return manifest
        if not isinstance(data, dict):
            manifest.diagnostics.append(
                make_diagnostic(
                    Severity.ERROR,
                    "json.unexpected",
                    "root value is not an object",
                    path=path,
                    root=root,
                )
            )
            return manifest

        lock_version = data.get("lockfileVersion")
        packages = data.get("packages")
        if isinstance(packages, dict) and packages:
            self._parse_packages(packages, rel_path, manifest)
        elif isinstance(data.get("dependencies"), dict):
            self._parse_v1(data["dependencies"], rel_path, manifest, depth=0)
        else:
            manifest.diagnostics.append(
                make_diagnostic(
                    Severity.WARNING,
                    "package_lock.no_entries",
                    f"lockfile (version {lock_version}) has no recognized package entries",
                    path=path,
                    root=root,
                )
            )
        return manifest

    def _parse_packages(
        self, packages: dict[str, Any], rel_path: str, manifest: ParsedManifest
    ) -> None:
        for location, info in packages.items():
            if not isinstance(info, dict):
                continue
            if location == "":
                self._root_declarations(info, rel_path, manifest)
                continue
            name = _name_from_location(location)
            if name is None:
                continue
            version = info.get("version")
            if not isinstance(version, str):
                continue
            manifest.packages.append(
                ResolvedPackage(
                    ecosystem=Ecosystem.NPM,
                    name=name,
                    version=version,
                    scope=_scope(info),
                    dependencies=_refs(info),
                    origin=SourceLocation(rel_path, None),
                )
            )

    def _root_declarations(
        self, info: dict[str, Any], rel_path: str, manifest: ParsedManifest
    ) -> None:
        sections = {
            "dependencies": Scope.RUNTIME,
            "devDependencies": Scope.DEVELOPMENT,
            "optionalDependencies": Scope.OPTIONAL,
            "peerDependencies": Scope.PEER,
        }
        for section, scope in sections.items():
            deps = info.get(section)
            if not isinstance(deps, dict):
                continue
            for name, constraint in deps.items():
                manifest.declarations.append(
                    Dependency(
                        ecosystem=Ecosystem.NPM,
                        name=name,
                        scope=scope,
                        constraint=constraint if isinstance(constraint, str) else None,
                        optional=section == "optionalDependencies",
                        origin=SourceLocation(rel_path, None),
                        source_role="lockfile",
                    )
                )

    def _parse_v1(
        self, deps: dict[str, Any], rel_path: str, manifest: ParsedManifest, *, depth: int
    ) -> None:
        if depth > 64:
            return
        for name, info in deps.items():
            if not isinstance(info, dict):
                continue
            version = info.get("version")
            if isinstance(version, str):
                manifest.packages.append(
                    ResolvedPackage(
                        ecosystem=Ecosystem.NPM,
                        name=name,
                        version=version,
                        scope=_scope(info),
                        dependencies=_refs(info),
                        origin=SourceLocation(rel_path, None),
                    )
                )
            nested = info.get("dependencies")
            if isinstance(nested, dict):
                self._parse_v1(nested, rel_path, manifest, depth=depth + 1)


def _name_from_location(location: str) -> str | None:
    marker = "node_modules/"
    if marker in location:
        tail = location.rsplit(marker, 1)[1]
        return tail or None
    if location:
        return location.split("/")[-1]
    return None


def _scope(info: dict[str, Any]) -> Scope:
    if info.get("dev"):
        return Scope.DEVELOPMENT
    if info.get("optional"):
        return Scope.OPTIONAL
    if info.get("peer"):
        return Scope.PEER
    return Scope.RUNTIME


def _refs(info: dict[str, Any]) -> tuple[DependencyRef, ...]:
    refs: list[DependencyRef] = []
    deps = info.get("dependencies")
    if isinstance(deps, dict):
        for name, constraint in deps.items():
            refs.append(
                DependencyRef(
                    name=name, constraint=constraint if isinstance(constraint, str) else None
                )
            )
    optional = info.get("optionalDependencies")
    if isinstance(optional, dict):
        for name, constraint in optional.items():
            refs.append(
                DependencyRef(
                    name=name,
                    constraint=constraint if isinstance(constraint, str) else None,
                    optional=True,
                )
            )
    return tuple(sorted(refs, key=lambda r: (r.name, r.constraint or "")))
