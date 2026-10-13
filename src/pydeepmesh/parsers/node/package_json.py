"""Parser for ``package.json``."""

from __future__ import annotations

import json
from pathlib import Path

from pydeepmesh.diagnostics import Diagnostic, Severity, make_diagnostic
from pydeepmesh.io import safe_read_text
from pydeepmesh.models.ecosystem import Ecosystem
from pydeepmesh.models.provenance import SourceLocation
from pydeepmesh.models.scope import Scope
from pydeepmesh.parsers.base import Dependency, ParsedManifest, Parser

_SECTIONS = {
    "dependencies": (Scope.RUNTIME, False),
    "devDependencies": (Scope.DEVELOPMENT, False),
    "peerDependencies": (Scope.PEER, False),
    "optionalDependencies": (Scope.OPTIONAL, True),
}


class PackageJsonParser(Parser):
    parser_id = "node.package_json"
    ecosystem = Ecosystem.NPM
    file_names = ("package.json",)
    is_root = True

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

        name = data.get("name")
        if isinstance(name, str):
            manifest.project_name = name
        version = data.get("version")
        if isinstance(version, str):
            manifest.project_version = version

        text = read.text or ""
        for section, (scope, optional) in _SECTIONS.items():
            deps = data.get(section)
            if not isinstance(deps, dict):
                continue
            for dep_name, spec in deps.items():
                if not isinstance(spec, str):
                    manifest.diagnostics.append(
                        Diagnostic(
                            Severity.WARNING,
                            "package_json.unsupported_spec",
                            f"unsupported spec for '{dep_name}' in {section}",
                            file=rel_path,
                        )
                    )
                    continue
                manifest.declarations.append(
                    Dependency(
                        ecosystem=Ecosystem.NPM,
                        name=dep_name,
                        scope=scope,
                        constraint=spec,
                        optional=optional or section == "optionalDependencies",
                        origin=SourceLocation(rel_path, _find_line(text, dep_name)),
                    )
                )
        return manifest


def _find_line(text: str, needle: str) -> int | None:
    quoted = f'"{needle}"'
    for index, line in enumerate(text.splitlines(), start=1):
        if quoted in line:
            return index
    return None
