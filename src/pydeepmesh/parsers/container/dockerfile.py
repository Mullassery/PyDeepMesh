"""Parser for ``Dockerfile`` (static, never executed)."""

from __future__ import annotations

import re
from pathlib import Path

from pydeepmesh.diagnostics import Diagnostic, Severity
from pydeepmesh.io import safe_read_text
from pydeepmesh.models.ecosystem import Ecosystem
from pydeepmesh.models.provenance import SourceLocation
from pydeepmesh.models.scope import Scope
from pydeepmesh.parsers.base import Dependency, ParsedManifest, Parser

_FROM = re.compile(
    r"^\s*FROM\s+(?:--platform=(?P<platform>\S+)\s+)?(?P<image>\S+)(?:\s+AS\s+(?P<stage>\S+))?\s*$",
    re.IGNORECASE,
)
_ARG = re.compile(
    r"^\s*ARG\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?:=(?P<value>\S+))?\s*$", re.IGNORECASE
)
_VAR = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")


class DockerfileParser(Parser):
    parser_id = "container.dockerfile"
    ecosystem = Ecosystem.DOCKER
    file_names = ("Dockerfile",)
    file_suffixes = ("Dockerfile", ".dockerfile")
    is_root = True

    def parse(self, path: Path, rel_path: str, *, max_bytes: int, root: Path) -> ParsedManifest:
        manifest = self._manifest(path, rel_path)
        read = safe_read_text(path, max_bytes=max_bytes, root=root)
        if read.diagnostic is not None:
            manifest.diagnostics.append(read.diagnostic)
            return manifest
        text = read.text or ""
        args: dict[str, str] = {}
        stages: set[str] = set()
        manifest.project_name = path.parent.name or "."

        for line_no, raw in _logical_lines(text):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            arg_match = _ARG.match(raw)
            if arg_match and arg_match.group("value"):
                args[arg_match.group("name")] = arg_match.group("value")
                continue
            from_match = _FROM.match(raw)
            if not from_match:
                continue
            image = from_match.group("image")
            stage = from_match.group("stage")
            resolved_image = _substitute(image, args)
            if resolved_image is None:
                manifest.diagnostics.append(
                    Diagnostic(
                        Severity.WARNING,
                        "dockerfile.unresolved_arg",
                        f"base image '{image}' uses an unresolved build argument",
                        file=rel_path,
                        line=line_no,
                    )
                )
                if stage:
                    stages.add(stage.lower())
                continue
            if resolved_image.lower() in stages:
                manifest.metadata.append(
                    ("docker.stage." + (stage or resolved_image), resolved_image)
                )
                if stage:
                    stages.add(stage.lower())
                continue
            name, version = _split_image(resolved_image)
            if stage:
                stages.add(stage.lower())
            manifest.declarations.append(
                Dependency(
                    ecosystem=Ecosystem.DOCKER,
                    name=name,
                    scope=Scope.CONTAINER,
                    constraint=version,
                    version=version,
                    origin=SourceLocation(rel_path, line_no),
                )
            )
        return manifest


def _substitute(value: str, args: dict[str, str]) -> str | None:
    def replace(match: re.Match[str]) -> str:
        return args.get(match.group(1), match.group(0))

    replaced = _VAR.sub(replace, value)
    if _VAR.search(replaced):
        return None
    return replaced


def _split_image(reference: str) -> tuple[str, str | None]:
    digest: str | None = None
    name_part = reference
    if "@" in reference:
        name_part, _, digest = reference.partition("@")
    tag: str | None = None
    last_colon = name_part.rfind(":")
    if last_colon != -1 and "/" not in name_part[last_colon + 1 :]:
        tag = name_part[last_colon + 1 :]
        name_part = name_part[:last_colon]
    version = digest or tag
    return name_part, version


def _logical_lines(text: str) -> list[tuple[int, str]]:
    result: list[tuple[int, str]] = []
    buffer = ""
    start = 1
    for index, physical in enumerate(text.splitlines(), start=1):
        if not buffer:
            start = index
        buffer += physical.rstrip("\\")
        if physical.endswith("\\"):
            continue
        result.append((start, buffer))
        buffer = ""
    if buffer:
        result.append((start, buffer))
    return result
