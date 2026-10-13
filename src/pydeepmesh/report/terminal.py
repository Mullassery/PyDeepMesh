"""Human-readable terminal report."""

from __future__ import annotations

from pydeepmesh.advisories.matcher import MatchReport
from pydeepmesh.models.finding import AnalysisResult, Priority
from pydeepmesh.pipeline import ScanResult
from pydeepmesh.version import __version__

_COLORS = {
    Priority.CRITICAL: "\033[1;31m",
    Priority.HIGH: "\033[31m",
    Priority.MEDIUM: "\033[33m",
    Priority.LOW: "\033[36m",
    Priority.INFO: "\033[2m",
}
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"


def render_terminal(
    scan: ScanResult,
    analysis: AnalysisResult | None = None,
    match_report: MatchReport | None = None,
    *,
    color: bool = False,
    max_findings: int = 100,
) -> str:
    def paint(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    lines: list[str] = []
    lines.append(paint(f"PyDeepMesh {__version__}", _BOLD))
    lines.append(f"Root: {scan.root}")
    graph = scan.graph
    lines.append(
        f"Projects: {len(graph.project_nodes)}  Packages: {len(graph.package_nodes)}  "
        f"Edges: {len(graph.edges)}  Manifests: {len(scan.manifests)}"
    )

    ecosystems: dict[str, int] = {}
    for node in graph.package_nodes:
        if node.key:
            ecosystems[node.key.ecosystem.value] = ecosystems.get(node.key.ecosystem.value, 0) + 1
    if ecosystems:
        summary = ", ".join(f"{eco}={count}" for eco, count in sorted(ecosystems.items()))
        lines.append(f"Ecosystems: {summary}")

    if match_report is not None and match_report.provider_result is not None:
        provider = match_report.provider_result
        status = "available" if provider.available else "UNAVAILABLE"
        lines.append(f"Advisory source: {provider.provider} ({provider.source}) [{status}]")
        if provider.error:
            lines.append(paint(f"  advisory error: {provider.error}", _DIM))

    if analysis is not None:
        findings = analysis.sorted_findings()
        lines.append("")
        if findings:
            lines.append(paint(f"Findings ({len(findings)}):", _BOLD))
            for finding in findings[:max_findings]:
                color_code = _COLORS.get(finding.priority, "")
                exposure = (
                    "direct"
                    if finding.exposure.direct
                    else f"transitive depth={finding.exposure.depth}"
                )
                header = (
                    f"  [{paint(finding.priority.value.upper(), color_code)}] "
                    f"{finding.package_name} {finding.version or '(unresolved)'} "
                    f"({finding.ecosystem}) via {finding.advisory.id}"
                )
                lines.append(header)
                lines.append(f"      exposure: {exposure}")
                if finding.remediation is not None:
                    lines.append(f"      fix: {finding.remediation.recommendation}")
            if len(findings) > max_findings:
                lines.append(f"  ... and {len(findings) - max_findings} more")
        else:
            lines.append("Findings: none matched the available advisory data")

        unavailable = len(analysis.unavailable_packages)
        lines.append("")
        lines.append(
            f"Unmatched packages: {analysis.unmatched_count}  "
            f"Unavailable (no advisory data): {unavailable}  Errors: {len(analysis.errors)}"
        )
        if unavailable:
            lines.append(
                paint(
                    "  note: unmatched is NOT a clean bill of health; "
                    "unavailable means no advisory data was consulted",
                    _DIM,
                )
            )

    warnings = [d for d in scan.diagnostics if d.severity.label == "warning"]
    errors = [d for d in scan.diagnostics if d.severity.label == "error"]
    if warnings or errors:
        lines.append("")
        lines.append(
            paint(f"Diagnostics: {len(errors)} error(s), {len(warnings)} warning(s)", _BOLD)
        )
        for diagnostic in (errors + warnings)[:20]:
            lines.append(f"  {diagnostic.render()}")

    return "\n".join(lines) + "\n"
