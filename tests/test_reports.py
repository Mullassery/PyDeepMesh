"""Report generation: JSON determinism, SARIF schema validity, terminal output."""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft7Validator

from helpers import FakeProvider, make_advisory, scan_fixture
from pydeepmesh.advisories.matcher import match_graph
from pydeepmesh.report.json_report import ReportOptions, build_report, render_json
from pydeepmesh.report.sarif import build_sarif
from pydeepmesh.report.terminal import render_terminal
from pydeepmesh.risk.analysis import analyze
from pydeepmesh.version import JSON_SCHEMA_VERSION

SCHEMAS = Path(__file__).parent / "schemas"


def _audit(fixture: str, advisories=None):
    scan = scan_fixture(fixture)
    provider = FakeProvider(advisories or [])
    report = match_graph(scan.graph, provider)
    analysis = analyze(scan.graph, report)
    return scan, analysis, report


def test_json_report_is_deterministic() -> None:
    scan, analysis, report = _audit(
        "python_project", [make_advisory("A", ecosystem="PyPI", name="requests", fixed="2.32.0")]
    )
    first = render_json(build_report(scan, analysis, report))
    second = render_json(build_report(scan, analysis, report))
    assert first == second


def test_json_report_contains_timestamp_when_requested() -> None:
    scan, analysis, report = _audit("node_project")
    document = build_report(
        scan, analysis, report, ReportOptions(generated_at="2024-01-01T00:00:00Z")
    )
    assert document["generated_at"] == "2024-01-01T00:00:00Z"


def test_json_report_shape() -> None:
    scan, analysis, report = _audit("node_project")
    document = build_report(scan, analysis, report)
    assert document["schema_version"] == JSON_SCHEMA_VERSION
    assert document["tool"]["name"] == "pydeepmesh"
    assert document["summary"]["packages"] >= 1
    assert "nodes" in document and "edges" in document
    json.loads(render_json(document))


def test_sarif_matches_schema() -> None:
    advisories = [
        make_advisory(
            "OSV-TEST-1", ecosystem="npm", name="express", fixed="4.19.0", range_type="SEMVER"
        )
    ]
    scan, analysis, _ = _audit("node_project", advisories)
    document = build_sarif(scan, analysis)
    schema = json.loads((SCHEMAS / "sarif-2.1.0.schema.json").read_text())
    Draft7Validator(schema).validate(document)


def test_sarif_level_mapping() -> None:
    advisories = [
        make_advisory(
            "HIGH-1", ecosystem="npm", name="express", fixed="4.19.0", range_type="SEMVER"
        )
    ]
    scan, analysis, _ = _audit("node_project", advisories)
    document = build_sarif(scan, analysis)
    results = document["runs"][0]["results"]
    assert results and results[0]["level"] in {"error", "warning", "note"}


def test_terminal_report_reports_unavailable() -> None:
    scan = scan_fixture("node_project")
    report = match_graph(scan.graph, FakeProvider([], available=False, error="offline"))
    analysis = analyze(scan.graph, report)
    text = render_terminal(scan, analysis, report)
    assert "UNAVAILABLE" in text
    assert "unmatched is NOT a clean bill of health" in text
