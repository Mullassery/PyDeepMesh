"""Advisory matching, status classification, and provider behavior."""

from __future__ import annotations

from pathlib import Path

import pytest

from helpers import FIXTURES, FakeProvider, make_advisory, scan_fixture
from pydeepmesh.advisories.matcher import match_graph
from pydeepmesh.advisories.snapshot import SnapshotProvider
from pydeepmesh.models.finding import MatchStatus
from pydeepmesh.models.vulnerability import VulnerabilitySeverity


def test_confirmed_match() -> None:
    graph = scan_fixture("node_project").graph
    advisory = make_advisory(
        "NPM-1", ecosystem="npm", name="express", fixed="4.19.0", range_type="SEMVER"
    )
    report = match_graph(graph, FakeProvider([advisory]))
    statuses = {(r.advisory.id, r.status) for r in report.results if r.advisory}
    assert ("NPM-1", MatchStatus.CONFIRMED) in statuses


def test_unaffected_package_is_unmatched_not_safe() -> None:
    graph = scan_fixture("node_project").graph
    advisory = make_advisory(
        "NPM-2", ecosystem="npm", name="lodash", fixed="4.17.21", range_type="SEMVER"
    )
    report = match_graph(graph, FakeProvider([advisory]))
    assert not report.results
    assert any("express" in entry for entry in report.unmatched)


def test_git_range_is_potential() -> None:
    graph = scan_fixture("rust_project").graph
    advisory = make_advisory(
        "CR-1", ecosystem="crates.io", name="serde", fixed=None, range_type="GIT"
    )
    report = match_graph(graph, FakeProvider([advisory]))
    assert any(r.status is MatchStatus.POTENTIAL for r in report.results)


def test_unavailable_provider_reports_unavailable() -> None:
    graph = scan_fixture("node_project").graph
    report = match_graph(graph, FakeProvider([], available=False, error="boom"))
    assert report.unavailable
    assert not report.results
    assert report.provider_result is not None
    assert report.provider_result.available is False


def test_snapshot_provider_offline() -> None:
    graph = scan_fixture("node_project").graph
    provider = SnapshotProvider(Path(FIXTURES) / "osv_snapshot")
    report = match_graph(graph, provider)
    confirmed = {
        r.advisory.id for r in report.results if r.advisory and r.status is MatchStatus.CONFIRMED
    }
    assert "OSV-2023-0002" in confirmed

    rust = scan_fixture("rust_project").graph
    rust_report = match_graph(rust, provider)
    potential = {r.advisory.id for r in rust_report.results if r.status is MatchStatus.POTENTIAL}
    assert "OSV-2023-0003" in potential


def test_snapshot_severity_normalization() -> None:
    graph = scan_fixture("node_project").graph
    provider = SnapshotProvider(Path(FIXTURES) / "osv_snapshot")
    report = match_graph(graph, provider)
    express = next(
        r.advisory for r in report.results if r.advisory and r.advisory.id == "OSV-2023-0002"
    )
    assert express is not None
    assert express.severity is VulnerabilitySeverity.MODERATE


def test_snapshot_missing_directory_is_unavailable() -> None:
    graph = scan_fixture("node_project").graph
    provider = SnapshotProvider(Path(FIXTURES) / "does-not-exist")
    report = match_graph(graph, provider)
    assert report.unavailable
    assert report.provider_result is not None and not report.provider_result.available


@pytest.mark.parametrize("fixture", ["python_project", "node_project", "rust_project"])
def test_match_never_raises(fixture: str) -> None:
    graph = scan_fixture(fixture).graph
    report = match_graph(graph, FakeProvider([], available=False))
    assert isinstance(report.unmatched, list)
