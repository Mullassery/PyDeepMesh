"""Build a canonical :class:`DependencyGraph` from parsed manifests."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from pydeepmesh.diagnostics import Diagnostic
from pydeepmesh.models.ecosystem import Ecosystem
from pydeepmesh.models.graph import DependencyGraph, Edge, EdgeKind, Node, NodeKind
from pydeepmesh.models.package import PackageKey, normalize_name, package_url
from pydeepmesh.models.provenance import SourceLocation
from pydeepmesh.models.scope import ResolutionStatus, Scope
from pydeepmesh.parsers.base import Dependency, ParsedManifest, ResolvedPackage


@dataclass
class BuildResult:
    graph: DependencyGraph
    diagnostics: list[Diagnostic] = field(default_factory=list)


@dataclass
class _NodeAcc:
    id: str
    kind: NodeKind
    display_name: str
    version: str | None = None
    key: PackageKey | None = None
    scopes: set[Scope] = field(default_factory=set)
    resolution: ResolutionStatus = ResolutionStatus.UNKNOWN
    origins: list[SourceLocation] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)

    def to_node(self) -> Node:
        purl = None
        if self.key is not None:
            purl = package_url(self.key.ecosystem, self.key.name, self.version)
        return Node(
            id=self.id,
            kind=self.kind,
            display_name=self.display_name,
            version=self.version,
            key=self.key,
            scopes=frozenset(self.scopes),
            resolution=self.resolution,
            origins=tuple(sorted(set(self.origins))),
            metadata=tuple(sorted(self.metadata.items())),
            purl=purl,
        )


@dataclass
class _EdgeAcc:
    source: str
    target: str
    kind: EdgeKind
    scope: Scope
    constraint: str | None
    confidence: float
    origins: set[SourceLocation] = field(default_factory=set)


_RESOLUTION_ORDER = {
    ResolutionStatus.UNKNOWN: 0,
    ResolutionStatus.UNRESOLVED: 1,
    ResolutionStatus.DECLARED: 2,
    ResolutionStatus.RESOLVED: 3,
}


class GraphBuilder:
    """Accumulates nodes and edges, then produces a deterministic graph."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._nodes: dict[str, _NodeAcc] = {}
        self._edges: dict[tuple[str, str, str, str, str], _EdgeAcc] = {}
        self._diagnostics: list[Diagnostic] = []
        self._dir_packages: dict[str, dict[tuple[Ecosystem, str], set[str | None]]] = {}
        self._dir_primary_version: dict[str, dict[tuple[Ecosystem, str], str]] = {}
        self._manifests: list[tuple[ParsedManifest, str]] = []

    # -- node helpers -------------------------------------------------------
    def _project_id(self, directory: str) -> str:
        display = directory if directory else "."
        return f"project:{display}"

    def _ensure_project(self, directory: str, manifest: ParsedManifest) -> str:
        pid = self._project_id(directory)
        display = directory if directory else "."
        acc = self._nodes.get(pid)
        if acc is None:
            acc = _NodeAcc(
                id=pid,
                kind=NodeKind.PROJECT,
                display_name=display,
                resolution=ResolutionStatus.RESOLVED,
            )
            self._nodes[pid] = acc
        acc.metadata.setdefault("manifest", manifest.rel_path)
        if manifest.project_name:
            acc.metadata.setdefault("project.name", manifest.project_name)
        if manifest.project_version:
            acc.metadata.setdefault("project.version", manifest.project_version)
        return pid

    def _ensure_package(
        self,
        ecosystem: Ecosystem,
        name: str,
        version: str | None,
        *,
        scope: Scope,
        resolution: ResolutionStatus,
        origin: SourceLocation | None,
        metadata: tuple[tuple[str, str], ...] = (),
        package_id: str | None = None,
    ) -> str:
        key = PackageKey.create(ecosystem, name, version) if package_id is None else None
        if package_id is not None:
            node_id = package_id
            key = PackageKey(ecosystem, normalize_name(ecosystem, name), version)
        else:
            assert key is not None
            node_id = key.stable_id()
        acc = self._nodes.get(node_id)
        if acc is None:
            acc = _NodeAcc(
                id=node_id,
                kind=NodeKind.PACKAGE,
                display_name=name,
                version=version,
                key=key,
                resolution=resolution,
            )
            self._nodes[node_id] = acc
        else:
            if _RESOLUTION_ORDER[resolution] > _RESOLUTION_ORDER[acc.resolution]:
                acc.resolution = resolution
            if version and not acc.version:
                acc.version = version
                acc.key = PackageKey(ecosystem, normalize_name(ecosystem, name), version)
        acc.scopes.add(scope)
        if origin is not None:
            acc.origins.append(origin)
        for mk, mv in metadata:
            acc.metadata.setdefault(mk, mv)
        return node_id

    def _add_edge(
        self,
        source: str,
        target: str,
        *,
        kind: EdgeKind,
        scope: Scope,
        constraint: str | None,
        confidence: float,
        origin: SourceLocation | None,
    ) -> None:
        key = (source, target, kind.value, scope.value, constraint or "")
        acc = self._edges.get(key)
        if acc is None:
            acc = _EdgeAcc(
                source=source,
                target=target,
                kind=kind,
                scope=scope,
                constraint=constraint,
                confidence=confidence,
            )
            self._edges[key] = acc
        elif confidence > acc.confidence:
            acc.confidence = confidence
        if origin is not None:
            acc.origins.add(origin)

    def _note(self, diagnostic: Diagnostic) -> None:
        self._diagnostics.append(diagnostic)

    # -- public API ---------------------------------------------------------
    def add_manifest(self, manifest: ParsedManifest, directory: str) -> None:
        """Queue a manifest. Linking happens in :meth:`build` after all
        resolved packages are known, so lockfiles and manifests may be supplied
        in any order."""

        self._manifests.append((manifest, directory))

    def _prepare(self) -> None:
        for manifest, directory in self._manifests:
            pid = self._ensure_project(directory, manifest)
            for mk, mv in manifest.metadata:
                self._nodes[pid].metadata.setdefault(mk, mv)
            for package in manifest.packages:
                self._register_resolved(directory, package)

    def _link_all(self) -> None:
        for manifest, directory in self._manifests:
            pid = self._project_id(directory)
            for declaration in manifest.declarations:
                target = self._link_declaration(directory, declaration)
                self._add_edge(
                    pid,
                    target,
                    kind=EdgeKind.RESOLVED if self._nodes[target].version else EdgeKind.DECLARED,
                    scope=declaration.scope,
                    constraint=declaration.constraint,
                    confidence=1.0 if self._nodes[target].version else 0.9,
                    origin=declaration.origin,
                )
            for package in manifest.packages:
                self._link_resolved_edges(directory, package)

    def _register_resolved(self, directory: str, package: ResolvedPackage) -> None:
        self._ensure_package(
            package.ecosystem,
            package.name,
            package.version,
            scope=package.scope,
            resolution=ResolutionStatus.RESOLVED,
            origin=package.origin,
            metadata=package.metadata,
        )
        index = self._dir_packages.setdefault(directory, {})
        key = (package.ecosystem, normalize_name(package.ecosystem, package.name))
        index.setdefault(key, set()).add(package.version)
        self._dir_primary_version.setdefault(directory, {}).setdefault(key, package.version)

    def _link_declaration(self, directory: str, declaration: Dependency) -> str:
        version = declaration.version
        if version is None:
            version = self._find_primary_version(directory, declaration.ecosystem, declaration.name)
        resolution = ResolutionStatus.RESOLVED if version else declaration.resolution
        if version is None and declaration.resolution is ResolutionStatus.RESOLVED:
            resolution = ResolutionStatus.UNRESOLVED
        return self._ensure_package(
            declaration.ecosystem,
            declaration.name,
            version,
            scope=declaration.scope,
            resolution=resolution,
            origin=declaration.origin,
        )

    def _find_primary_version(self, directory: str, ecosystem: Ecosystem, name: str) -> str | None:
        key = (ecosystem, normalize_name(ecosystem, name))
        versions = self._dir_packages.get(directory, {}).get(key)
        if not versions:
            return None
        if len(versions) == 1:
            return next(iter(versions))
        return self._dir_primary_version.get(directory, {}).get(key)

    def _link_resolved_edges(self, directory: str, package: ResolvedPackage) -> None:
        source_id = PackageKey.create(package.ecosystem, package.name, package.version).stable_id()
        for ref in package.dependencies:
            key = (package.ecosystem, normalize_name(package.ecosystem, ref.name))
            versions = self._dir_packages.get(directory, {}).get(key)
            target_version: str | None = None
            confidence = 0.5
            if ref.version and versions and ref.version in versions:
                target_version = ref.version
                confidence = 0.95
            elif ref.version and versions and len(versions) == 1:
                target_version = next(iter(versions))
                confidence = 0.9
            elif versions and len(versions) == 1:
                target_version = next(iter(versions))
                confidence = 0.8
            elif versions:
                target_version = self._dir_primary_version.get(directory, {}).get(key)
                confidence = 0.6
            if target_version is None:
                confidence = 0.4
            target_id = self._ensure_package(
                package.ecosystem,
                ref.name,
                target_version,
                scope=package.scope,
                resolution=ResolutionStatus.RESOLVED
                if target_version
                else ResolutionStatus.UNRESOLVED,
                origin=package.origin,
            )
            self._add_edge(
                source_id,
                target_id,
                kind=EdgeKind.RESOLVED if target_version else EdgeKind.DECLARED,
                scope=package.scope,
                constraint=ref.constraint,
                confidence=confidence,
                origin=package.origin,
            )

    def build(self) -> BuildResult:
        self._prepare()
        self._link_all()
        graph = DependencyGraph()
        for node_id, acc in self._nodes.items():
            graph.nodes[node_id] = acc.to_node()
        graph.edges = [
            Edge(
                source=acc.source,
                target=acc.target,
                kind=acc.kind,
                scope=acc.scope,
                constraint=acc.constraint,
                confidence=acc.confidence,
                origins=tuple(sorted(acc.origins)),
            )
            for acc in self._edges.values()
        ]
        graph.reindex()
        return BuildResult(
            graph=graph, diagnostics=sorted(self._diagnostics, key=lambda d: (d.code, d.message))
        )


def build_graph(manifests: list[ParsedManifest], root: Path) -> BuildResult:
    """Convenience wrapper: build a graph from parsed manifests."""

    builder = GraphBuilder(root)
    for manifest in manifests:
        directory = _directory_of(manifest.rel_path)
        builder.add_manifest(manifest, directory)
    return builder.build()


def _directory_of(rel_path: str) -> str:
    parent = str(Path(rel_path).parent)
    return "" if parent == "." else parent
