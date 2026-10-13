"""Parser for ``yarn.lock`` (classic v1 and Berry v2+)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from pydeepmesh.diagnostics import Diagnostic, Severity, make_diagnostic
from pydeepmesh.io import safe_read_text
from pydeepmesh.models.ecosystem import Ecosystem
from pydeepmesh.models.provenance import SourceLocation
from pydeepmesh.models.scope import Scope
from pydeepmesh.parsers.base import DependencyRef, ParsedManifest, Parser, ResolvedPackage

_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"|(\S+)')
_PAIR = re.compile(r'^\s*(".*?"|\S+)\s+(".*?"|\S+)\s*$')


class YarnLockParser(Parser):
    parser_id = "node.yarn_lock"
    ecosystem = Ecosystem.NPM
    file_names = ("yarn.lock",)
    is_root = False

    def parse(self, path: Path, rel_path: str, *, max_bytes: int, root: Path) -> ParsedManifest:
        manifest = self._manifest(path, rel_path)
        read = safe_read_text(path, max_bytes=max_bytes, root=root)
        if read.diagnostic is not None:
            manifest.diagnostics.append(read.diagnostic)
            return manifest
        text = read.text or ""
        if "__metadata:" in text:
            self._parse_berry(text, rel_path, manifest)
        else:
            self._parse_classic(text, rel_path, manifest)
        if not manifest.packages:
            manifest.diagnostics.append(
                make_diagnostic(
                    Severity.WARNING,
                    "yarn_lock.no_entries",
                    "no lock entries could be parsed",
                    path=path,
                    root=root,
                )
            )
        return manifest

    def _parse_classic(self, text: str, rel_path: str, manifest: ParsedManifest) -> None:
        lines = text.splitlines()
        index = 0
        count = len(lines)
        while index < count:
            line = lines[index]
            stripped = line.strip()
            if not stripped or line.startswith("#"):
                index += 1
                continue
            if line[0].isspace() or not line.rstrip().endswith(":"):
                index += 1
                continue
            names = _extract_descriptor_names(line.rstrip()[:-1])
            index += 1
            version: str | None = None
            refs: list[DependencyRef] = []
            section: str | None = None
            while index < count:
                body = lines[index]
                if body and not body[0].isspace():
                    break
                s = body.strip()
                if body.startswith("    ") and s:
                    if section == "dependencies":
                        pair = _split_pair(s)
                        if pair is not None:
                            refs.append(DependencyRef(name=pair[0], constraint=pair[1]))
                    index += 1
                    continue
                if body.startswith("  ") and s and not body.startswith("    "):
                    if s.startswith("version"):
                        values = _quoted_values(s[len("version") :])
                        if values:
                            version = values[0]
                        section = None
                    elif s.startswith("dependencies:") or s.startswith("optionalDependencies:"):
                        section = "dependencies"
                    else:
                        section = None
                index += 1
            if names and version:
                name = names[0]
                manifest.packages.append(
                    ResolvedPackage(
                        ecosystem=Ecosystem.NPM,
                        name=name,
                        version=version,
                        scope=Scope.RUNTIME,
                        dependencies=tuple(
                            sorted(refs, key=lambda r: (r.name, r.constraint or ""))
                        ),
                        origin=SourceLocation(rel_path, None),
                    )
                )

    def _parse_berry(self, text: str, rel_path: str, manifest: ParsedManifest) -> None:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            manifest.diagnostics.append(
                Diagnostic(Severity.ERROR, "yaml.invalid", f"invalid YAML: {exc}", file=rel_path)
            )
            return
        if not isinstance(data, dict):
            return
        for key, entry in data.items():
            if key == "__metadata" or not isinstance(entry, dict):
                continue
            names = _extract_descriptor_names(str(key))
            version = entry.get("version")
            if not names or not isinstance(version, str):
                continue
            refs = _berry_refs(entry.get("dependencies"))
            refs += _berry_refs(entry.get("optionalDependencies"))
            manifest.packages.append(
                ResolvedPackage(
                    ecosystem=Ecosystem.NPM,
                    name=names[0],
                    version=version,
                    scope=Scope.RUNTIME,
                    dependencies=tuple(
                        sorted(set(refs), key=lambda r: (r.name, r.constraint or ""))
                    ),
                    origin=SourceLocation(rel_path, None),
                )
            )


def _berry_refs(deps: Any) -> list[DependencyRef]:
    if not isinstance(deps, dict):
        return []
    result: list[DependencyRef] = []
    for name, constraint in deps.items():
        result.append(
            DependencyRef(
                name=str(name), constraint=constraint if isinstance(constraint, str) else None
            )
        )
    return result


def _extract_descriptor_names(header: str) -> list[str]:
    names: list[str] = []
    for descriptor in _quoted_values(header):
        name = descriptor.rsplit("@", 1)[0] if "@" in descriptor else descriptor
        name = name.strip().strip('"')
        if name and not name.startswith("__"):
            names.append(name)
    return names


def _quoted_values(text: str) -> list[str]:
    values: list[str] = []
    for line_part in text.split(","):
        for match in _QUOTED.finditer(line_part):
            value = match.group(1) if match.group(1) is not None else match.group(2)
            if value is not None:
                values.append(value.strip())
    return values


def _split_pair(line: str) -> tuple[str, str | None] | None:
    match = _PAIR.match(line)
    if not match:
        return None
    name = match.group(1).strip().strip('"')
    constraint = match.group(2).strip().strip('"')
    return name, constraint
