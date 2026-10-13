"""Report serialization: JSON, terminal, and SARIF."""

from __future__ import annotations

from pydeepmesh.report.json_report import ReportOptions, build_report, render_json
from pydeepmesh.report.sarif import build_sarif, render_sarif
from pydeepmesh.report.terminal import render_terminal

__all__ = [
    "ReportOptions",
    "build_report",
    "build_sarif",
    "render_json",
    "render_sarif",
    "render_terminal",
]
