"""Parser for ``Cargo.toml``."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydeepmesh._compat import tomllib
from pydeepmesh.diagnostics import Diagnostic, Severity, make_diagnostic
from pydeepmesh.io import safe_read_text
from pydeepmesh.models.ecosystem import Ecosystem
from pydeepmesh.models.provenance import SourceLocation
from pydeepmesh.models.scope import Scope
from pydeepmesh.parsers.base import Dependency, ParsedManifest, Parser
from pydeepmesh.parsers.python.helpers import find_line

_DEP_TABLES = {
    "dependencies": Scope.RUNTIME,
    "dev-dependencies": Scope.DEVELOPMENT,
    "build-dependencies": Scope.BUILD,
}


class CargoManifestParser(Parser):
    parser_id = "rust.cargo_manifest"
    ecosystem = Ecosystem.CRATES
    file_names = ("Cargo.toml",)
    is_root = True

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

        package = data.get("package")
        if isinstance(package, dict):
            manifest.project_name = _as_str(package.get("name"))
            manifest.project_version = _as_str(package.get("version"))

        workspace = data.get("workspace")
        if isinstance(workspace, dict):
            self._parse_workspace(workspace, text, manifest)
            if manifest.project_name is None:
                manifest.project_name = "workspace"

        for table, scope in _DEP_TABLES.items():
            deps = data.get(table)
            self._parse_deps(deps, scope, text, manifest)
            if isinstance(deps, dict) and manifest.project_name is None:
                manifest.project_name = "package"

        targets = data.get("target")
        if isinstance(targets, dict):
            for _cfg, tables in targets.items():
                if not isinstance(tables, dict):
                    continue
                for table, scope in _DEP_TABLES.items():
                    self._parse_deps(tables.get(table), scope, text, manifest)

        return manifest

    def _parse_workspace(
        self, workspace: dict[str, Any], text: str, manifest: ParsedManifest
    ) -> None:
        deps = workspace.get("dependencies")
        self._parse_deps(deps, Scope.RUNTIME, text, manifest)
        members = workspace.get("members")
        if isinstance(members, list):
            manifest.diagnostics.append(
                Diagnostic(
                    Severity.INFO,
                    "cargo.workspace_members",
                    f"workspace declares {len(members)} member(s)",
                    file=manifest.rel_path,
                )
            )

    def _parse_deps(
        self,
        deps: Any,
        scope: Scope,
        text: str,
        manifest: ParsedManifest,
    ) -> None:
        if not isinstance(deps, dict):
            return
        for name, spec in deps.items():
            constraint: str | None = None
            optional = False
            if isinstance(spec, str):
                constraint = spec
            elif isinstance(spec, dict):
                if spec.get("workspace") is True:
                    manifest.diagnostics.append(
                        Diagnostic(
                            Severity.INFO,
                            "cargo.workspace_dependency",
                            f"'{name}' inherits a workspace dependency",
                            file=manifest.rel_path,
                            line=find_line(text, name),
                        )
                    )
                version = spec.get("version")
                constraint = version if isinstance(version, str) else None
                optional = bool(spec.get("optional", False))
                if constraint is None and isinstance(spec.get("path"), str):
                    constraint = f"path+{spec['path']}"
                elif constraint is None and isinstance(spec.get("git"), str):
                    constraint = f"git+{spec['git']}"
            else:
                manifest.diagnostics.append(
                    Diagnostic(
                        Severity.WARNING,
                        "cargo.unsupported_spec",
                        f"unsupported dependency spec for '{name}'",
                        file=manifest.rel_path,
                    )
                )
                continue
            manifest.declarations.append(
                Dependency(
                    ecosystem=Ecosystem.CRATES,
                    name=name,
                    scope=scope,
                    constraint=constraint,
                    optional=optional,
                    origin=SourceLocation(manifest.rel_path, find_line(text, name)),
                )
            )


def _as_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None
