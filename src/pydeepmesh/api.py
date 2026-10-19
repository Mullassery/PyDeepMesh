"""Supported public Python API for PyDeepMesh.

This module is the stable Python surface. It is intentionally small. The CLI
and the versioned JSON output schema are the primary public interfaces; this
facade exists for embedding and testing.

Stability: functions here follow semantic versioning. Their signatures and
returned document shapes change only on major releases.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydeepmesh.advisories.base import AdvisoryProvider
from pydeepmesh.advisories.matcher import MatchReport, match_graph
from pydeepmesh.advisories.registry import build_provider
from pydeepmesh.config import Config
from pydeepmesh.integrations import ImageScanResult, SyftScanner, SyftUnavailable, scan_image
from pydeepmesh.models.finding import AnalysisResult
from pydeepmesh.pipeline import ScanResult
from pydeepmesh.pipeline import scan as _scan
from pydeepmesh.report.json_report import ReportOptions, build_report, render_json
from pydeepmesh.report.sarif import build_sarif, render_sarif
from pydeepmesh.report.terminal import render_terminal
from pydeepmesh.report.viewer import build_viewer_document, render_viewer, render_viewer_json
from pydeepmesh.risk.analysis import RiskOptions, analyze
from pydeepmesh.sbom.cyclonedx import build_cyclonedx, render_cyclonedx

__all__ = [
    "Config",
    "ImageScanResult",
    "RiskOptions",
    "SyftScanner",
    "SyftUnavailable",
    "advisory_provider",
    "audit_directory",
    "make_cyclonedx",
    "make_report",
    "make_sarif",
    "make_viewer",
    "render_cyclonedx",
    "render_json",
    "render_sarif",
    "render_terminal",
    "render_viewer",
    "render_viewer_json",
    "scan_directory",
    "scan_image",
]


def scan_directory(root: str | Path, config: Config | None = None) -> ScanResult:
    """Discover, parse, and build the canonical graph for ``root``."""

    return _scan(Path(root), config)


def advisory_provider(config: Config) -> AdvisoryProvider:
    """Construct the configured advisory provider."""

    return build_provider(config)


def audit_directory(
    root: str | Path,
    config: Config | None = None,
    provider: AdvisoryProvider | None = None,
    options: RiskOptions | None = None,
) -> tuple[ScanResult, MatchReport, AnalysisResult]:
    """Scan ``root``, match advisories, and produce findings.

    ``provider`` may be supplied for offline or test use; otherwise the provider
    is built from ``config``.
    """

    config = config or Config()
    scan_result = scan_directory(root, config)
    provider = provider if provider is not None else build_provider(config)
    match_report = match_graph(scan_result.graph, provider)
    analysis = analyze(scan_result.graph, match_report, options)
    return scan_result, match_report, analysis


def make_report(
    scan_result: ScanResult,
    analysis: AnalysisResult | None = None,
    match_report: MatchReport | None = None,
    options: ReportOptions | None = None,
) -> dict[str, Any]:
    return build_report(scan_result, analysis, match_report, options)


def make_sarif(scan_result: ScanResult, analysis: AnalysisResult) -> dict[str, Any]:
    return build_sarif(scan_result, analysis)


def make_cyclonedx(scan_result: ScanResult, *, timestamp: str | None = None) -> dict[str, Any]:
    return build_cyclonedx(scan_result, timestamp=timestamp)


def make_viewer(scan_result: ScanResult) -> dict[str, Any]:
    return build_viewer_document(scan_result)
