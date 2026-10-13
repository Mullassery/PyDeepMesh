"""Parser for ``pnpm-lock.yaml`` (lockfile v6 and v9)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

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

_IMPORTER_SECTIONS = {
    "dependencies": Scope.RUNTIME,
    "devDependencies": Scope.DEVELOPMENT,
    "optionalDependencies": Scope.OPTIONAL,
}


class PnpmLockParser(Parser):
    parser_id = "node.pnpm_lock"
    ecosystem = Ecosystem.NPM
    file_names = ("pnpm-lock.yaml",)
    is_root = False

    def parse(self, path: Path, rel_path: str, *, max_bytes: int, root: Path) -> ParsedManifest:
        manifest = self._manifest(path, rel_path)
        read = safe_read_text(path, max_bytes=max_bytes, root=root)
        if read.diagnostic is not None:
            manifest.diagnostics.append(read.diagnostic)
            return manifest
        try:
            data = yaml.safe_load(read.text or "")
        except yaml.YAMLError as exc:
            manifest.diagnostics.append(
                make_diagnostic(
                    Severity.ERROR, "yaml.invalid", f"invalid YAML: {exc}", path=path, root=root
                )
            )
            return manifest
        if not isinstance(data, dict):
            manifest.diagnostics.append(
                make_diagnostic(
                    Severity.ERROR,
                    "yaml.unexpected",
                    "root value is not a mapping",
                    path=path,
                    root=root,
                )
            )
            return manifest

        importers = data.get("importers")
        if isinstance(importers, dict):
            root_importer = importers.get(".") if isinstance(importers.get("."), dict) else None
            if root_importer is not None:
                self._parse_importer(root_importer, rel_path, manifest)

        packages = data.get("packages")
        if isinstance(packages, dict):
            self._parse_packages(packages, rel_path, manifest, include_deps=True)

        snapshots = data.get("snapshots")
        if isinstance(snapshots, dict):
            self._parse_packages(snapshots, rel_path, manifest, include_deps=True)

        if not manifest.packages and not manifest.declarations:
            manifest.diagnostics.append(
                make_diagnostic(
                    Severity.WARNING,
                    "pnpm_lock.no_entries",
                    "no importers or packages found",
                    path=path,
                    root=root,
                )
            )
        return manifest

    def _parse_importer(
        self, importer: dict[str, Any], rel_path: str, manifest: ParsedManifest
    ) -> None:
        for section, scope in _IMPORTER_SECTIONS.items():
            deps = importer.get(section)
            if not isinstance(deps, dict):
                continue
            for name, spec in deps.items():
                constraint = None
                version = None
                if isinstance(spec, dict):
                    constraint = _as_str(spec.get("specifier"))
                    version = _clean_version(_as_str(spec.get("version")))
                elif isinstance(spec, str):
                    constraint = spec
                manifest.declarations.append(
                    Dependency(
                        ecosystem=Ecosystem.NPM,
                        name=name,
                        scope=scope,
                        constraint=constraint,
                        version=version,
                        origin=SourceLocation(rel_path, None),
                        source_role="lockfile",
                    )
                )

    def _parse_packages(
        self,
        packages: dict[str, Any],
        rel_path: str,
        manifest: ParsedManifest,
        *,
        include_deps: bool,
    ) -> None:
        for key, info in packages.items():
            if not isinstance(info, dict):
                continue
            parsed = _name_version(key)
            if parsed is None:
                continue
            name, version = parsed
            refs = _refs(info.get("dependencies")) if include_deps else ()
            scope = Scope.DEVELOPMENT if info.get("dev") else Scope.RUNTIME
            manifest.packages.append(
                ResolvedPackage(
                    ecosystem=Ecosystem.NPM,
                    name=name,
                    version=version,
                    scope=scope,
                    dependencies=refs,
                    origin=SourceLocation(rel_path, None),
                )
            )


def _name_version(key: str) -> tuple[str, str] | None:
    trimmed = key.strip()
    if trimmed.startswith("/"):
        trimmed = trimmed[1:]
    if "(" in trimmed:
        trimmed = trimmed.split("(", 1)[0]
    if "@" not in trimmed:
        return None
    name, _, version = trimmed.rpartition("@")
    if not name or not version:
        return None
    return name, version


def _refs(deps: Any) -> tuple[DependencyRef, ...]:
    if not isinstance(deps, dict):
        return ()
    refs = [
        DependencyRef(name=name, constraint=_clean_version(_as_str(spec)))
        for name, spec in deps.items()
    ]
    return tuple(sorted(refs, key=lambda r: (r.name, r.constraint or "")))


def _clean_version(value: str | None) -> str | None:
    if value is None:
        return None
    for prefix in ("npm:", "link:", "workspace:", "file:"):
        if value.startswith(prefix):
            return value
    return value


def _as_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None
