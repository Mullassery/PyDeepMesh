"""End-to-end scan pipeline: discover, parse, and build the canonical graph."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from pydeepmesh.config import Config
from pydeepmesh.diagnostics import Diagnostic
from pydeepmesh.discovery import DiscoveryResult, discover
from pydeepmesh.graph import BuildResult, GraphBuilder
from pydeepmesh.models.graph import DependencyGraph
from pydeepmesh.parsers.base import ParsedManifest
from pydeepmesh.parsers.registry import default_parsers, parsers_for


@dataclass
class ScanResult:
    root: Path
    discovery: DiscoveryResult
    manifests: list[ParsedManifest] = field(default_factory=list)
    graph: DependencyGraph = field(default_factory=DependencyGraph)
    diagnostics: list[Diagnostic] = field(default_factory=list)

    @property
    def parse_diagnostics(self) -> list[Diagnostic]:
        result: list[Diagnostic] = []
        for manifest in self.manifests:
            result.extend(manifest.diagnostics)
        return result


def scan(root: Path, config: Config | None = None) -> ScanResult:
    """Discover, parse, and build a graph for ``root``.

    This function reads files only; it never executes scanned code or writes to
    the scanned tree.
    """

    config = config or Config()
    root = root.resolve()
    discovery = discover(
        root,
        include=config.include,
        exclude=config.exclude,
        max_files=config.max_files,
        max_depth=config.max_depth,
    )
    result = ScanResult(root=root, discovery=discovery)
    result.diagnostics.extend(discovery.diagnostics)

    parsers = default_parsers()
    for discovered in discovery.files:
        matched = parsers_for(discovered.path, parsers)
        for parser in matched:
            manifest = parser.parse(
                discovered.path,
                discovered.rel_path,
                max_bytes=config.max_file_bytes,
                root=root,
            )
            result.manifests.append(manifest)
            result.diagnostics.extend(manifest.diagnostics)

    builder = GraphBuilder(root)
    for manifest in result.manifests:
        directory = _directory_of(manifest.rel_path)
        builder.add_manifest(manifest, directory)
    build: BuildResult = builder.build()
    result.graph = build.graph
    result.diagnostics.extend(build.diagnostics)
    result.manifests.sort(key=lambda m: (m.rel_path, m.parser_id))
    result.diagnostics = sorted(
        result.diagnostics,
        key=lambda d: (d.file or "", d.line or 0, int(d.severity), d.code, d.message),
    )
    return result


def _directory_of(rel_path: str) -> str:
    parent = str(Path(rel_path).parent)
    return "" if parent == "." else parent
