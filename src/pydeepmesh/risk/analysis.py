"""Turn matches into explainable, exposure-aware findings.

Reachability is a graph property. PyDeepMesh never asserts runtime exploitability
without supporting evidence; prioritization factors are explicit and reversible.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydeepmesh.advisories.matcher import MatchReport
from pydeepmesh.advisories.versioning import earliest_fixed_version
from pydeepmesh.graph.algorithms import find_paths, reachable_from, reverse_dependencies
from pydeepmesh.models.ecosystem import Ecosystem
from pydeepmesh.models.finding import (
    AnalysisResult,
    Exposure,
    Finding,
    MatchResult,
    Priority,
    Remediation,
)
from pydeepmesh.models.graph import DependencyGraph, NodeKind
from pydeepmesh.models.vulnerability import AffectedPackage


@dataclass
class RiskOptions:
    """Tunable, visible risk factors."""

    direct_escalation: bool = True
    deep_depth_threshold: int = 4
    deep_depth_downgrade: bool = True
    max_paths: int = 3
    max_path_depth: int = 32


def concentration(graph: DependencyGraph, *, top: int = 10) -> list[tuple[str, int]]:
    """Return package ids ordered by incoming dependency count (fan-in)."""

    counts: list[tuple[str, int]] = []
    for node in graph.package_nodes:
        fan_in = len({edge.source for edge in graph.in_edges(node.id)})
        counts.append((node.id, fan_in))
    counts.sort(key=lambda item: (-item[1], item[0]))
    return counts[:top]


def _exposure(graph: DependencyGraph, node_id: str, options: RiskOptions) -> Exposure:
    roots = graph.roots
    best_depth: int | None = None
    reachable_roots: list[str] = []
    sample_paths: list[tuple[str, ...]] = []
    for root in roots:
        depths = reachable_from(graph, root)
        if node_id in depths:
            reachable_roots.append(root)
            depth = depths[node_id]
            best_depth = depth if best_depth is None else min(best_depth, depth)
            for path in find_paths(
                graph, root, node_id, max_paths=options.max_paths, max_depth=options.max_path_depth
            ):
                sample_paths.append(tuple(path))
    direct = best_depth == 1
    node = graph.get(node_id)
    scopes = tuple(sorted(s.value for s in node.scopes)) if node else ()
    reverse = reverse_dependencies(graph, node_id)
    dependents: list[str] = []
    for rid in reverse:
        dependent = graph.get(rid)
        if dependent is not None and dependent.kind is NodeKind.PACKAGE:
            dependents.append(rid)
    paths_sorted = tuple(sorted(set(sample_paths))[: options.max_paths])
    return Exposure(
        direct=direct,
        depth=best_depth,
        root_projects=tuple(sorted(reachable_roots)),
        sample_paths=paths_sorted,
        dependent_count=len(dependents),
        scopes=scopes,
    )


def _prioritize(
    base: Priority,
    exposure: Exposure,
    options: RiskOptions,
) -> tuple[Priority, tuple[str, ...]]:
    rank = base.rank
    explanation: list[str] = [f"advisory severity maps to '{base.value}'"]
    if options.direct_escalation and exposure.direct:
        rank = min(rank + 1, Priority.CRITICAL.rank)
        explanation.append("direct dependency of a project root (+1)")
    elif exposure.depth is not None:
        explanation.append(f"transitive dependency at depth {exposure.depth}")
    if (
        options.deep_depth_downgrade
        and exposure.depth is not None
        and exposure.depth > options.deep_depth_threshold
    ):
        rank = max(rank - 1, Priority.INFO.rank)
        explanation.append(f"deep dependency at depth {exposure.depth} (-1)")
    priority = next(p for p in Priority if p.rank == rank)
    return priority, tuple(explanation)


def _remediation(
    graph: DependencyGraph, node_id: str, affected: AffectedPackage | None, version: str | None
) -> Remediation | None:
    node = graph.get(node_id)
    if node is None or node.key is None or version is None:
        return None
    if affected is None:
        return None
    fixed = earliest_fixed_version(node.key.ecosystem, version, affected)
    if fixed is None:
        return None
    return Remediation(
        current_version=version,
        fixed_versions=(fixed,),
        recommendation=f"upgrade {node.display_name} from {version} to {fixed}",
    )


def analyze(
    graph: DependencyGraph,
    report: MatchReport,
    options: RiskOptions | None = None,
) -> AnalysisResult:
    options = options or RiskOptions()
    result = AnalysisResult()
    result.unavailable_packages = list(report.unavailable)
    result.unmatched_count = len(report.unmatched)
    if report.provider_result is not None and report.provider_result.error:
        result.errors.append((report.provider_result.provider, report.provider_result.error))

    for match in report.results:
        if match.advisory is None:
            continue
        node = graph.get(match.package_id)
        if node is None:
            continue
        exposure = _exposure(graph, match.package_id, options)
        base = Priority.from_severity(match.advisory.severity)
        priority, explanation = _prioritize(base, exposure, options)
        affected = _matching_affected(node.key.ecosystem if node.key else None, match)
        remediation = (
            _remediation(graph, match.package_id, affected, node.version) if node.key else None
        )
        result.findings.append(
            Finding(
                advisory=match.advisory,
                package_id=match.package_id,
                package_name=node.display_name,
                ecosystem=node.key.ecosystem.value if node.key else "unknown",
                version=node.version,
                status=match.status,
                priority=priority,
                priority_explanation=explanation,
                exposure=exposure,
                remediation=remediation,
            )
        )
    return result


def _matching_affected(ecosystem: Ecosystem | None, match: MatchResult) -> AffectedPackage | None:
    if match.advisory is None:
        return None
    for affected in match.advisory.affected:
        if affected.ecosystem is ecosystem:
            return affected
    return match.advisory.affected[0] if match.advisory.affected else None


def analyze_graph(
    graph: DependencyGraph, report: MatchReport, options: RiskOptions | None = None
) -> AnalysisResult:
    return analyze(graph, report, options)
