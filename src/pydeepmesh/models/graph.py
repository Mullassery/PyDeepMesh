"""Canonical dependency graph types."""

from __future__ import annotations

import enum
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

from pydeepmesh.models.package import PackageKey
from pydeepmesh.models.provenance import SourceLocation
from pydeepmesh.models.scope import ResolutionStatus, Scope


class NodeKind(str, enum.Enum):
    PROJECT = "project"
    PACKAGE = "package"


class EdgeKind(str, enum.Enum):
    """Semantics of a dependency edge."""

    RESOLVED = "resolved"
    """Target version is resolved (from a lockfile or exact pin)."""

    DECLARED = "declared"
    """Target is a declared constraint without a resolved version."""

    CONTAINER_FROM = "container_from"
    """A Dockerfile ``FROM`` relationship to a base image."""

    COMPOSE_DEPENDS_ON = "compose_depends_on"
    """A Compose ``depends_on`` service relationship."""

    BUILD_DEPENDS_ON = "build_depends_on"
    """A Compose ``build`` relationship from a service to a Dockerfile."""


@dataclass(frozen=True)
class Node:
    """A vertex in the canonical graph (a project root or a package)."""

    id: str
    kind: NodeKind
    display_name: str
    version: str | None = None
    key: PackageKey | None = None
    scopes: frozenset[Scope] = frozenset()
    resolution: ResolutionStatus = ResolutionStatus.UNKNOWN
    origins: tuple[SourceLocation, ...] = ()
    metadata: tuple[tuple[str, str], ...] = ()
    purl: str | None = None

    @property
    def ecosystem(self) -> str | None:
        return self.key.ecosystem.value if self.key else None

    def metadata_dict(self) -> dict[str, str]:
        return dict(self.metadata)

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "id": self.id,
            "kind": self.kind.value,
            "name": self.display_name,
            "scopes": sorted(s.value for s in self.scopes),
            "resolution": self.resolution.value,
            "origins": [o.to_dict() for o in self.origins],
        }
        if self.key is not None:
            data["ecosystem"] = self.key.ecosystem.value
        if self.version is not None:
            data["version"] = self.version
        if self.purl is not None:
            data["purl"] = self.purl
        if self.metadata:
            data["metadata"] = self.metadata_dict()
        return data


@dataclass(frozen=True)
class Edge:
    """A directed dependency edge between two nodes."""

    source: str
    target: str
    kind: EdgeKind
    scope: Scope = Scope.RUNTIME
    constraint: str | None = None
    confidence: float = 1.0
    origins: tuple[SourceLocation, ...] = ()

    def sort_key(self) -> tuple[object, ...]:
        return (
            self.source,
            self.target,
            self.kind.value,
            self.scope.value,
            self.constraint or "",
            -self.confidence,
        )

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "source": self.source,
            "target": self.target,
            "kind": self.kind.value,
            "scope": self.scope.value,
            "confidence": round(self.confidence, 4),
        }
        if self.constraint is not None:
            data["constraint"] = self.constraint
        if self.origins:
            data["origins"] = [o.to_dict() for o in self.origins]
        return data


@dataclass
class DependencyGraph:
    """A canonical, deterministic dependency graph.

    The graph is immutable-by-convention after construction: build it with
    :class:`pydeepmesh.graph.builder.GraphBuilder`, then query it read-only.
    """

    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    roots: list[str] = field(default_factory=list)
    _out: dict[str, list[Edge]] = field(default_factory=lambda: defaultdict(list), repr=False)
    _in: dict[str, list[Edge]] = field(default_factory=lambda: defaultdict(list), repr=False)

    def reindex(self) -> None:
        out: dict[str, list[Edge]] = defaultdict(list)
        incoming: dict[str, list[Edge]] = defaultdict(list)
        for edge in self.edges:
            out[edge.source].append(edge)
            incoming[edge.target].append(edge)
        for bucket in out.values():
            bucket.sort(key=Edge.sort_key)
        for bucket in incoming.values():
            bucket.sort(key=Edge.sort_key)
        self._out = out
        self._in = incoming
        self.edges.sort(key=Edge.sort_key)
        for node in self.nodes.values():
            if node.kind is NodeKind.PROJECT and node.id not in self.roots:
                self.roots.append(node.id)
        self.roots.sort()

    def out_edges(self, node_id: str) -> list[Edge]:
        return list(self._out.get(node_id, ()))

    def in_edges(self, node_id: str) -> list[Edge]:
        return list(self._in.get(node_id, ()))

    def successors(self, node_id: str) -> list[str]:
        return [edge.target for edge in self._out.get(node_id, ())]

    def predecessors(self, node_id: str) -> list[str]:
        return [edge.source for edge in self._in.get(node_id, ())]

    def get(self, node_id: str) -> Node | None:
        return self.nodes.get(node_id)

    def node_by_key(self, key: PackageKey) -> Node | None:
        for node in self.nodes.values():
            if node.key == key:
                return node
        return None

    @property
    def package_nodes(self) -> list[Node]:
        return [n for n in self.nodes.values() if n.kind is NodeKind.PACKAGE]

    @property
    def project_nodes(self) -> list[Node]:
        return [n for n in self.nodes.values() if n.kind is NodeKind.PROJECT]

    def iter_nodes_sorted(self) -> Iterable[Node]:
        return (self.nodes[i] for i in sorted(self.nodes))

    def to_dict(self) -> dict[str, object]:
        return {
            "roots": list(self.roots),
            "nodes": [self.nodes[i].to_dict() for i in sorted(self.nodes)],
            "edges": [e.to_dict() for e in sorted(self.edges, key=Edge.sort_key)],
        }

    def __len__(self) -> int:
        return len(self.nodes)


def merge_scopes(existing: frozenset[Scope], new: Scope) -> frozenset[Scope]:
    return existing | {new}
