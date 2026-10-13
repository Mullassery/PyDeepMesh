"""Parser for ``pyproject.toml`` (PEP 621 and Poetry)."""

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
from pydeepmesh.parsers.python.helpers import (
    find_line,
    requirement_to_dependency,
    scope_for_group,
)


class PyprojectParser(Parser):
    parser_id = "python.pyproject"
    ecosystem = Ecosystem.PYPI
    file_names = ("pyproject.toml",)
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
                    Severity.ERROR,
                    "toml.invalid",
                    f"invalid TOML: {exc}",
                    path=path,
                    root=root,
                )
            )
            return manifest

        project = data.get("project")
        if isinstance(project, dict):
            manifest.project_name = _as_str(project.get("name"))
            manifest.project_version = _as_str(project.get("version"))
            self._parse_pep621(project, text, manifest)

        poetry = data.get("tool", {}).get("poetry") if isinstance(data.get("tool"), dict) else None
        if isinstance(poetry, dict):
            manifest.project_name = manifest.project_name or _as_str(poetry.get("name"))
            manifest.project_version = manifest.project_version or _as_str(poetry.get("version"))
            self._parse_poetry(poetry, text, manifest)

        build_system = data.get("build-system")
        if isinstance(build_system, dict):
            for requirement in _as_list(build_system.get("requires")):
                if not isinstance(requirement, str):
                    continue
                dep = requirement_to_dependency(
                    requirement,
                    scope=Scope.BUILD,
                    optional=False,
                    origin=SourceLocation(rel_path, find_line(text, requirement)),
                )
                if dep is not None:
                    manifest.declarations.append(dep)

        return manifest

    def _parse_pep621(self, project: dict[str, Any], text: str, manifest: ParsedManifest) -> None:
        for requirement in _as_list(project.get("dependencies")):
            if not isinstance(requirement, str):
                continue
            dep = requirement_to_dependency(
                requirement,
                scope=Scope.RUNTIME,
                optional=False,
                origin=SourceLocation(manifest.rel_path, find_line(text, requirement)),
            )
            if dep is not None:
                manifest.declarations.append(dep)
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for group, requirements in optional.items():
                scope = scope_for_group(str(group))
                for requirement in _as_list(requirements):
                    if not isinstance(requirement, str):
                        continue
                    dep = requirement_to_dependency(
                        requirement,
                        scope=scope,
                        optional=True,
                        origin=SourceLocation(manifest.rel_path, find_line(text, requirement)),
                    )
                    if dep is not None:
                        manifest.declarations.append(dep)

    def _parse_poetry(self, poetry: dict[str, Any], text: str, manifest: ParsedManifest) -> None:
        deps = poetry.get("dependencies")
        if isinstance(deps, dict):
            for name, spec in deps.items():
                if name.lower() == "python":
                    continue
                self._add_poetry_dep(name, spec, Scope.RUNTIME, text, manifest)
        legacy_dev = poetry.get("dev-dependencies")
        if isinstance(legacy_dev, dict):
            for name, spec in legacy_dev.items():
                self._add_poetry_dep(name, spec, Scope.DEVELOPMENT, text, manifest)
        groups = poetry.get("group")
        if isinstance(groups, dict):
            for group_name, group in groups.items():
                if not isinstance(group, dict):
                    continue
                group_deps = group.get("dependencies")
                if isinstance(group_deps, dict):
                    scope = scope_for_group(str(group_name))
                    for name, spec in group_deps.items():
                        self._add_poetry_dep(name, spec, scope, text, manifest)

    def _add_poetry_dep(
        self,
        name: str,
        spec: Any,
        scope: Scope,
        text: str,
        manifest: ParsedManifest,
    ) -> None:
        constraint: str | None = None
        optional = False
        extras: tuple[str, ...] = ()
        if isinstance(spec, str):
            constraint = spec
        elif isinstance(spec, dict):
            version = spec.get("version")
            constraint = version if isinstance(version, str) else None
            optional = bool(spec.get("optional", False))
            raw_extras = spec.get("extras")
            if isinstance(raw_extras, list):
                extras = tuple(sorted(str(e) for e in raw_extras))
            if constraint is None and spec.get("git"):
                constraint = f"git+{spec.get('git')}"
        else:
            manifest.diagnostics.append(
                Diagnostic(
                    Severity.WARNING,
                    "pyproject.unsupported_spec",
                    f"unsupported dependency spec for '{name}'",
                    file=manifest.rel_path,
                )
            )
            return
        manifest.declarations.append(
            Dependency(
                ecosystem=Ecosystem.PYPI,
                name=name,
                scope=scope,
                constraint=constraint,
                optional=optional,
                extras=extras,
                origin=SourceLocation(manifest.rel_path, find_line(text, name)),
            )
        )


def _as_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []
