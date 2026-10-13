"""Graph algorithms and determinism."""

from __future__ import annotations

from helpers import scan_fixture
from pydeepmesh.graph.algorithms import (
    find_cycles,
    find_paths,
    reachable_from,
    reverse_dependencies,
    shortest_depth,
)
from pydeepmesh.models.ecosystem import Ecosystem
from pydeepmesh.models.package import PackageKey


def _ids(graph, ecosystem: Ecosystem, name: str, version: str) -> str:
    node = graph.node_by_key(PackageKey.create(ecosystem, name, version))
    assert node is not None
    return node.id


def test_cycle_detection() -> None:
    graph = scan_fixture("cycle_project").graph
    a = _ids(graph, Ecosystem.NPM, "a", "1.0.0")
    b = _ids(graph, Ecosystem.NPM, "b", "1.0.0")
    c = _ids(graph, Ecosystem.NPM, "c", "1.0.0")
    cycles = find_cycles(graph)
    assert cycles
    combined = {node for cycle in cycles for node in cycle}
    assert {a, b, c} <= combined


def test_reachability_and_reverse() -> None:
    graph = scan_fixture("cycle_project").graph
    root = graph.roots[0]
    a = _ids(graph, Ecosystem.NPM, "a", "1.0.0")
    b = _ids(graph, Ecosystem.NPM, "b", "1.0.0")
    c = _ids(graph, Ecosystem.NPM, "c", "1.0.0")

    depths = reachable_from(graph, root)
    assert depths[a] == 1
    assert depths[b] == 2
    assert depths[c] == 3

    assert shortest_depth(graph, root, c) == 3
    assert shortest_depth(graph, root, root) == 0

    reverse = reverse_dependencies(graph, c)
    assert {a, b} <= set(reverse)


def test_paths_are_deterministic() -> None:
    graph = scan_fixture("cycle_project").graph
    root = graph.roots[0]
    c = _ids(graph, Ecosystem.NPM, "c", "1.0.0")
    first = find_paths(graph, root, c)
    second = find_paths(graph, root, c)
    assert first == second
    assert first
    assert first[0][0] == root
    assert first[0][-1] == c


def test_graph_dict_is_stable() -> None:
    graph = scan_fixture("node_project").graph
    assert graph.to_dict() == scan_fixture("node_project").graph.to_dict()
    edges = graph.to_dict()["edges"]
    assert edges == sorted(edges, key=lambda e: (e["source"], e["target"]))
