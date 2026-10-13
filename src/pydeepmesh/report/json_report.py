"""Deterministic, versioned JSON report document."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from pydeepmesh.advisories.matcher import MatchReport
from pydeepmesh.models.finding import AnalysisResult
from pydeepmesh.pipeline import ScanResult
from pydeepmesh.version import JSON_SCHEMA_VERSION, __version__


@dataclass
class ReportOptions:
    """Options controlling report content.

    ``generated_at`` is ``None`` by default so byte-for-byte determinism is
    preserved; set it only when a timestamp is explicitly wanted.
    """

    generated_at: str | None = None
    include_nodes: bool = True
    include_edges: bool = True
    include_diagnostics: bool = True


def build_report(
    scan: ScanResult,
    analysis: AnalysisResult | None = None,
    match_report: MatchReport | None = None,
    options: ReportOptions | None = None,
) -> dict[str, Any]:
    options = options or ReportOptions()
    graph = scan.graph
    document: dict[str, Any] = {
        "schema_version": JSON_SCHEMA_VERSION,
        "tool": {"name": "pydeepmesh", "version": __version__},
        "root": str(scan.root),
        "summary": _summary(scan, analysis, match_report),
    }
    if options.generated_at is not None:
        document["generated_at"] = options.generated_at
    if options.include_nodes:
        document["nodes"] = [graph.nodes[i].to_dict() for i in sorted(graph.nodes)]
        document["roots"] = list(graph.roots)
    if options.include_edges:
        document["edges"] = [edge.to_dict() for edge in graph.edges]
    ecosystems = _ecosystem_summary(scan)
    document["ecosystems"] = ecosystems
    if analysis is not None:
        document["findings"] = [f.to_dict() for f in analysis.sorted_findings()]
        document["unmatched_count"] = analysis.unmatched_count
    if match_report is not None and match_report.provider_result is not None:
        provider = match_report.provider_result
        document["advisory_data"] = {
            "provider": provider.provider,
            "source": provider.source,
            "available": provider.available,
            "error": provider.error,
            "queried_packages": provider.queried_packages,
            "advisories_returned": len(provider.advisories),
            "unavailable_packages": [
                {"package": p, "reason": r} for p, r in match_report.unavailable
            ],
        }
    if options.include_diagnostics:
        document["diagnostics"] = [d.to_dict() for d in scan.diagnostics]
    return document


def _summary(
    scan: ScanResult,
    analysis: AnalysisResult | None,
    match_report: MatchReport | None,
) -> dict[str, Any]:
    graph = scan.graph
    packages = graph.package_nodes
    resolution: dict[str, int] = {}
    for node in packages:
        resolution[node.resolution.value] = resolution.get(node.resolution.value, 0) + 1
    summary: dict[str, Any] = {
        "projects": len(graph.project_nodes),
        "packages": len(packages),
        "edges": len(graph.edges),
        "manifests": len(scan.manifests),
        "resolution": dict(sorted(resolution.items())),
        "diagnostics": {
            "info": sum(1 for d in scan.diagnostics if d.severity.label == "info"),
            "warning": sum(1 for d in scan.diagnostics if d.severity.label == "warning"),
            "error": sum(1 for d in scan.diagnostics if d.severity.label == "error"),
        },
    }
    if analysis is not None:
        priorities: dict[str, int] = {}
        for finding in analysis.findings:
            priorities[finding.priority.value] = priorities.get(finding.priority.value, 0) + 1
        summary["findings"] = {
            "total": len(analysis.findings),
            "by_priority": dict(sorted(priorities.items())),
            "unmatched": analysis.unmatched_count,
            "unavailable": len(analysis.unavailable_packages),
            "errors": len(analysis.errors),
        }
    if match_report is not None and match_report.provider_result is not None:
        summary["advisory_available"] = match_report.provider_result.available
    return summary


def _ecosystem_summary(scan: ScanResult) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for node in scan.graph.package_nodes:
        if node.key is None:
            continue
        counts[node.key.ecosystem.value] = counts.get(node.key.ecosystem.value, 0) + 1
    return [{"ecosystem": eco, "packages": count} for eco, count in sorted(counts.items())]


def render_json(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=False) + "\n"
