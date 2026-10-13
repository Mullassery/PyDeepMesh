"""Deterministic graph algorithms over the canonical dependency graph."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterator

from pydeepmesh.models.graph import DependencyGraph


def reachable_from(
    graph: DependencyGraph, source: str, *, max_depth: int | None = None
) -> dict[str, int]:
    """Return node ids reachable from ``source`` mapped to their BFS depth."""

    depths: dict[str, int] = {}
    queue: deque[tuple[str, int]] = deque([(source, 0)])
    seen = {source}
    while queue:
        node, depth = queue.popleft()
        for successor in sorted(graph.successors(node)):
            if successor in seen:
                continue
            if max_depth is not None and depth + 1 > max_depth:
                continue
            seen.add(successor)
            depths[successor] = depth + 1
            queue.append((successor, depth + 1))
    return depths


def reverse_dependencies(graph: DependencyGraph, node_id: str) -> list[str]:
    """Return the transitive set of nodes that depend on ``node_id``."""

    result: set[str] = set()
    queue: deque[str] = deque([node_id])
    while queue:
        current = queue.popleft()
        for predecessor in sorted(graph.predecessors(current)):
            if predecessor not in result:
                result.add(predecessor)
                queue.append(predecessor)
    return sorted(result)


def shortest_depth(
    graph: DependencyGraph, source: str, target: str, *, max_depth: int = 64
) -> int | None:
    """Return the length (in edges) of the shortest path, or ``None``."""

    if source == target:
        return 0
    queue: deque[tuple[str, int]] = deque([(source, 0)])
    seen = {source}
    while queue:
        node, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for successor in sorted(graph.successors(node)):
            if successor == target:
                return depth + 1
            if successor not in seen:
                seen.add(successor)
                queue.append((successor, depth + 1))
    return None


def find_paths(
    graph: DependencyGraph,
    source: str,
    target: str,
    *,
    max_paths: int = 8,
    max_depth: int = 32,
) -> list[list[str]]:
    """Enumerate up to ``max_paths`` simple paths from ``source`` to ``target``.

    Results are deterministic: depth-first over sorted successors, returned in
    insertion order.
    """

    paths: list[list[str]] = []
    stack: list[tuple[str, list[str]]] = [(source, [source])]
    while stack and len(paths) < max_paths:
        node, path = stack.pop()
        if len(path) - 1 >= max_depth:
            continue
        for successor in sorted(graph.successors(node), reverse=True):
            if successor in path:
                continue
            new_path = [*path, successor]
            if successor == target:
                paths.append(new_path)
                if len(paths) >= max_paths:
                    break
            else:
                stack.append((successor, new_path))
    return paths


def find_cycles(graph: DependencyGraph, *, max_cycles: int = 32) -> list[list[str]]:
    """Return simple cycles (as node-id lists) using an iterative DFS.

    Only meaningful for resolved graphs; declared-only graphs are forests.
    """

    cycles: list[list[str]] = []
    color: dict[str, int] = {}
    for start in sorted(graph.nodes):
        if color.get(start, 0) != 0:
            continue
        path: list[str] = []
        on_path: dict[str, int] = {}
        stack: list[tuple[str, Iterator[str]]] = []
        stack.append((start, iter(sorted(graph.successors(start)))))
        color[start] = 1
        on_path[start] = 0
        path.append(start)
        while stack and len(cycles) < max_cycles:
            node, iterator = stack[-1]
            try:
                successor = next(iterator)
            except StopIteration:
                stack.pop()
                on_path.pop(node, None)
                path.pop()
                color[node] = 2
                continue
            state = color.get(successor, 0)
            if state == 1:
                index = on_path.get(successor)
                if index is not None:
                    cycles.append([*path[index:], successor])
            elif state == 0:
                color[successor] = 1
                on_path[successor] = len(path)
                path.append(successor)
                stack.append((successor, iter(sorted(graph.successors(successor)))))
    return cycles
