"""Parser for ``Cargo.lock``."""

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


class CargoLockParser(Parser):
    parser_id = "rust.cargo_lock"
    ecosystem = Ecosystem.CRATES
    file_names = ("Cargo.lock",)
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
                    "cargo_lock.no_packages",
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
            refs = tuple(_parse_dep_ref(dep) for dep in _as_list(entry.get("dependencies")))
            manifest.packages.append(
                ResolvedPackage(
                    ecosystem=Ecosystem.CRATES,
                    name=name,
                    version=version,
                    scope=Scope.RUNTIME,
                    dependencies=tuple(sorted(refs, key=lambda r: (r.name, r.version or ""))),
                    origin=SourceLocation(rel_path, find_line(text, f'name = "{name}"')),
                )
            )
        return manifest


def _parse_dep_ref(dep: Any) -> DependencyRef:
    if not isinstance(dep, str):
        return DependencyRef(name=str(dep))
    parts = dep.split()
    if not parts:
        return DependencyRef(name="")
    if len(parts) == 1:
        return DependencyRef(name=parts[0])
    return DependencyRef(name=parts[0], version=parts[1])


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []
