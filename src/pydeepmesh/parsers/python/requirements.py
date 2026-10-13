"""Parser for ``requirements*.txt`` and compatible pinned requirement files."""

from __future__ import annotations

import re
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

from pydeepmesh.diagnostics import Diagnostic, Severity, make_diagnostic
from pydeepmesh.io import ensure_within, safe_read_text
from pydeepmesh.models.ecosystem import Ecosystem
from pydeepmesh.models.provenance import SourceLocation
from pydeepmesh.models.scope import ResolutionStatus, Scope
from pydeepmesh.parsers.base import Dependency, ParsedManifest, Parser
from pydeepmesh.parsers.python.helpers import is_pinned_specifier

_MAX_INCLUDE_DEPTH = 8
_EGG_FRAGMENT = re.compile(r"[#&]egg=([^&]+)")


class RequirementsParser(Parser):
    parser_id = "python.requirements"
    ecosystem = Ecosystem.PYPI
    file_names = ("requirements.txt",)
    file_suffixes = ("requirements.txt", "requirements-dev.txt", "requirements-test.txt")
    is_root = True

    def parse(self, path: Path, rel_path: str, *, max_bytes: int, root: Path) -> ParsedManifest:
        manifest = self._manifest(path, rel_path)
        self._parse_file(path, rel_path, manifest, max_bytes, root, depth=0, seen={path.resolve()})
        return manifest

    def _parse_file(
        self,
        path: Path,
        rel_path: str,
        manifest: ParsedManifest,
        max_bytes: int,
        root: Path,
        *,
        depth: int,
        seen: set[Path],
    ) -> None:
        read = safe_read_text(path, max_bytes=max_bytes, root=root)
        if read.diagnostic is not None:
            manifest.diagnostics.append(read.diagnostic)
            return
        lines = _logical_lines(read.text or "")
        for line_no, raw in lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("-"):
                self._handle_option(
                    line, path, rel_path, line_no, manifest, max_bytes, root, depth, seen
                )
                continue
            self._handle_requirement(_strip_comment(line), rel_path, line_no, manifest)

    def _handle_option(
        self,
        line: str,
        path: Path,
        rel_path: str,
        line_no: int,
        manifest: ParsedManifest,
        max_bytes: int,
        root: Path,
        depth: int,
        seen: set[Path],
    ) -> None:
        stripped = _strip_inline_hash_comment(line)
        include_match = re.match(r"^(?:-r|--requirement)[=\s]+(\S+)", stripped)
        if include_match:
            self._include(
                include_match.group(1),
                path,
                rel_path,
                line_no,
                manifest,
                max_bytes,
                root,
                depth,
                seen,
            )
            return
        if re.match(r"^(?:-c|--constraint)\b", stripped):
            manifest.diagnostics.append(
                make_diagnostic(
                    Severity.INFO,
                    "requirements.constraint_ignored",
                    "-c/--constraint files are recorded but not expanded",
                    path=path,
                    root=root,
                    line=line_no,
                )
            )
            return
        editable = re.match(r"^(?:-e|--editable)[=\s]+(\S+)", stripped)
        if editable:
            target = editable.group(1)
            egg = _EGG_FRAGMENT.search(target)
            if egg:
                manifest.declarations.append(
                    Dependency(
                        ecosystem=Ecosystem.PYPI,
                        name=egg.group(1),
                        scope=Scope.RUNTIME,
                        constraint=target,
                        origin=SourceLocation(rel_path, line_no),
                    )
                )
            else:
                manifest.diagnostics.append(
                    make_diagnostic(
                        Severity.WARNING,
                        "requirements.editable_local",
                        f"editable local dependency '{target}' cannot be resolved statically",
                        path=path,
                        root=root,
                        line=line_no,
                    )
                )
            return

    def _include(
        self,
        target: str,
        path: Path,
        rel_path: str,
        line_no: int,
        manifest: ParsedManifest,
        max_bytes: int,
        root: Path,
        depth: int,
        seen: set[Path],
    ) -> None:
        if depth >= _MAX_INCLUDE_DEPTH:
            manifest.diagnostics.append(
                make_diagnostic(
                    Severity.WARNING,
                    "requirements.include_depth",
                    f"include depth limit reached for '{target}'",
                    path=path,
                    root=root,
                    line=line_no,
                )
            )
            return
        child = (path.parent / target).resolve()
        try:
            ensure_within(child, root)
        except Exception:
            manifest.diagnostics.append(
                make_diagnostic(
                    Severity.ERROR,
                    "requirements.include_escape",
                    f"included file '{target}' escapes scan root",
                    path=path,
                    root=root,
                    line=line_no,
                )
            )
            return
        if child in seen:
            manifest.diagnostics.append(
                make_diagnostic(
                    Severity.WARNING,
                    "requirements.include_cycle",
                    f"cyclic include of '{target}'",
                    path=path,
                    root=root,
                    line=line_no,
                )
            )
            return
        if not child.exists():
            manifest.diagnostics.append(
                make_diagnostic(
                    Severity.ERROR,
                    "requirements.include_missing",
                    f"included file '{target}' not found",
                    path=path,
                    root=root,
                    line=line_no,
                )
            )
            return
        seen.add(child)
        child_rel = str(child.relative_to(root))
        self._parse_file(child, child_rel, manifest, max_bytes, root, depth=depth + 1, seen=seen)

    def _handle_requirement(
        self, line: str, rel_path: str, line_no: int, manifest: ParsedManifest
    ) -> None:
        try:
            parsed = Requirement(line)
        except InvalidRequirement:
            manifest.diagnostics.append(
                Diagnostic(
                    Severity.WARNING,
                    "requirements.unparseable",
                    f"could not parse requirement: {line!r}",
                    file=rel_path,
                    line=line_no,
                )
            )
            return
        constraint = str(parsed.specifier) or None
        pinned = is_pinned_specifier(constraint)
        resolution = ResolutionStatus.RESOLVED if pinned else ResolutionStatus.DECLARED
        manifest.declarations.append(
            Dependency(
                ecosystem=Ecosystem.PYPI,
                name=parsed.name,
                scope=Scope.RUNTIME,
                constraint=constraint,
                version=pinned,
                resolution=resolution,
                extras=tuple(sorted(parsed.extras)),
                origin=SourceLocation(rel_path, line_no),
            )
        )


def _logical_lines(text: str) -> list[tuple[int, str]]:
    result: list[tuple[int, str]] = []
    buffer = ""
    start_line = 1
    for index, physical in enumerate(text.splitlines(), start=1):
        if not buffer:
            start_line = index
        buffer += physical.rstrip("\\")
        if physical.endswith("\\"):
            continue
        result.append((start_line, buffer))
        buffer = ""
    if buffer:
        result.append((start_line, buffer))
    return result


def _strip_comment(line: str) -> str:
    hash_index = line.find(" #")
    if hash_index != -1:
        return line[:hash_index].strip()
    return line


def _strip_inline_hash_comment(line: str) -> str:
    match = re.match(r"^(.*?)\s+#", line)
    if match:
        return match.group(1).strip()
    return line.strip()
