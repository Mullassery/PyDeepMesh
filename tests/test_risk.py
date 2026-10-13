"""Risk analysis: exposure, prioritization, remediation, concentration."""

from __future__ import annotations

from helpers import FakeProvider, make_advisory, scan_fixture
from pydeepmesh.advisories.matcher import match_graph
from pydeepmesh.models.finding import Priority
from pydeepmesh.models.vulnerability import VulnerabilitySeverity
from pydeepmesh.risk.analysis import RiskOptions, analyze, concentration


def _findings(fixture: str, advisories):
    graph = scan_fixture(fixture).graph
    report = match_graph(graph, FakeProvider(advisories))
    return graph, analyze(graph, report)


def test_direct_dependency_escalates_priority() -> None:
    advisory = make_advisory(
        "A", ecosystem="npm", name="express", fixed="4.19.0", range_type="SEMVER"
    )
    _, analysis = _findings("node_project", [advisory])
    finding = next(f for f in analysis.findings if f.advisory.id == "A")
    assert finding.exposure.direct is True
    assert any("direct dependency" in step for step in finding.priority_explanation)


def test_remediation_recommends_earliest_fixed() -> None:
    advisory = make_advisory("R", ecosystem="PyPI", name="requests", fixed="2.32.0")
    _, analysis = _findings("python_project", [advisory])
    finding = next(f for f in analysis.findings if f.advisory.id == "R")
    assert finding.remediation is not None
    assert finding.remediation.fixed_versions == ("2.32.0",)
    assert "2.32.0" in finding.remediation.recommendation


def test_no_remediation_when_no_fixed_version() -> None:
    advisory = make_advisory("G", ecosystem="crates.io", name="serde", fixed=None, range_type="GIT")
    _, analysis = _findings("rust_project", [advisory])
    finding = next(f for f in analysis.findings if f.advisory.id == "G")
    assert finding.remediation is None


def test_unavailable_packages_surface_in_analysis() -> None:
    graph = scan_fixture("node_project").graph
    report = match_graph(graph, FakeProvider([], available=False, error="offline"))
    analysis = analyze(graph, report)
    assert analysis.unavailable_packages
    assert analysis.errors and analysis.errors[0][0] == "fake"


def test_findings_are_sorted_by_priority() -> None:
    advisories = [
        make_advisory(
            "LOW",
            ecosystem="npm",
            name="lodash",
            fixed="0.0.1",
            severity=VulnerabilitySeverity.LOW,
            range_type="SEMVER",
        ),
        make_advisory("CRIT", ecosystem="npm", name="express", fixed="4.19.0", range_type="SEMVER"),
    ]
    _, analysis = _findings("node_project", advisories)
    ranks = [f.priority.rank for f in analysis.sorted_findings()]
    assert ranks == sorted(ranks, reverse=True)


def test_deep_depth_downgrade() -> None:
    graph = scan_fixture("cycle_project").graph
    advisory = make_advisory("D", ecosystem="npm", name="c", fixed="2.0.0", range_type="SEMVER")
    report = match_graph(graph, FakeProvider([advisory]))
    analysis = analyze(graph, report, RiskOptions(deep_depth_threshold=1))
    finding = next(f for f in analysis.findings if f.advisory.id == "D")
    assert any("deep dependency" in step for step in finding.priority_explanation)


def test_concentration_counts_fan_in() -> None:
    graph = scan_fixture("node_project").graph
    ranked = concentration(graph, top=5)
    assert ranked
    counts = [count for _, count in ranked]
    assert counts == sorted(counts, reverse=True)


def test_priority_remains_within_bounds() -> None:
    advisory = make_advisory(
        "C", ecosystem="npm", name="express", fixed="4.19.0", range_type="SEMVER"
    )
    _, analysis = _findings("node_project", [advisory])
    finding = next(f for f in analysis.findings if f.advisory.id == "C")
    assert Priority.INFO.rank <= finding.priority.rank <= Priority.CRITICAL.rank
