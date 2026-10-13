"""Match graph packages against advisory data and classify outcomes."""

from __future__ import annotations

from dataclasses import dataclass, field

from pydeepmesh.advisories.base import AdvisoryProvider, AdvisoryQuery, ProviderResult
from pydeepmesh.advisories.versioning import version_in_affected
from pydeepmesh.models.finding import MatchResult, MatchStatus
from pydeepmesh.models.graph import DependencyGraph, NodeKind
from pydeepmesh.models.package import normalize_name
from pydeepmesh.models.vulnerability import Advisory


@dataclass
class MatchReport:
    results: list[MatchResult] = field(default_factory=list)
    unmatched: list[str] = field(default_factory=list)
    unavailable: list[tuple[str, str]] = field(default_factory=list)
    provider_result: ProviderResult | None = None
    queried: int = 0


def _queries_for_graph(graph: DependencyGraph) -> list[AdvisoryQuery]:
    queries: list[AdvisoryQuery] = []
    for node in graph.iter_nodes_sorted():
        if node.kind is not NodeKind.PACKAGE or node.key is None or not node.version:
            continue
        if node.key.ecosystem.osv_name is None:
            continue
        queries.append(
            AdvisoryQuery(ecosystem=node.key.ecosystem, name=node.key.name, version=node.version)
        )
    return queries


def match_graph(graph: DependencyGraph, provider: AdvisoryProvider) -> MatchReport:
    """Evaluate every resolvable package node against ``provider``."""

    queries = _queries_for_graph(graph)
    report = MatchReport()
    if not queries:
        report.provider_result = ProviderResult(provider=provider.name, queried_packages=0)
        return report

    provider_result = provider.query(queries)
    report.provider_result = provider_result
    report.queried = provider_result.queried_packages

    if not provider_result.available:
        reason = provider_result.error or "advisory source unavailable"
        for query in queries:
            report.unavailable.append((query.identifier, reason))
        return report

    index = _index_advisories(provider_result.advisories)
    for query in queries:
        advisories = index.get(
            (query.ecosystem.value, normalize_name(query.ecosystem, query.name)), []
        )
        matched = False
        for advisory in advisories:
            status, affected_match = _evaluate(query, advisory)
            if status is None:
                continue
            matched = True
            report.results.append(
                MatchResult(
                    package_id=f"{query.ecosystem.value}:{normalize_name(query.ecosystem, query.name)}@{query.version}",
                    status=status,
                    advisory=advisory,
                    reason=affected_match,
                    matched_version=query.version,
                )
            )
        if not matched:
            report.unmatched.append(query.identifier)

    report.results.sort(key=lambda r: (r.package_id, r.advisory.id if r.advisory else ""))
    report.unmatched.sort()
    report.unavailable.sort()
    return report


def _index_advisories(advisories: list[Advisory]) -> dict[tuple[str, str], list[Advisory]]:
    index: dict[tuple[str, str], list[Advisory]] = {}
    for advisory in advisories:
        for affected in advisory.affected:
            ecosystem = affected.ecosystem
            if ecosystem is None:
                continue
            key = (ecosystem.value, normalize_name(ecosystem, affected.name))
            bucket = index.setdefault(key, [])
            if advisory not in bucket:
                bucket.append(advisory)
    return index


def _evaluate(query: AdvisoryQuery, advisory: Advisory) -> tuple[MatchStatus | None, str]:
    for affected in advisory.affected:
        if affected.ecosystem != query.ecosystem:
            continue
        if normalize_name(query.ecosystem, affected.name) != normalize_name(
            query.ecosystem, query.name
        ):
            continue
        result = version_in_affected(query.ecosystem, query.version, affected)
        if result is True:
            return MatchStatus.CONFIRMED, f"{query.version} is within an affected range"
        if result is None:
            return (
                MatchStatus.POTENTIAL,
                "affected range could not be evaluated with available data",
            )
    return None, ""
