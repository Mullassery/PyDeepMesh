"""Public API facade, provider selection, and ``python -m pydeepmesh``."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from helpers import FIXTURES, make_advisory
from pydeepmesh.advisories.osv import OsvProvider
from pydeepmesh.advisories.registry import NullProvider
from pydeepmesh.advisories.snapshot import SnapshotProvider
from pydeepmesh.api import (
    advisory_provider,
    audit_directory,
    make_cyclonedx,
    make_report,
    make_sarif,
    scan_directory,
)
from pydeepmesh.config import Config

NODE = FIXTURES / "node_project"


def test_scan_directory() -> None:
    result = scan_directory(NODE)
    assert result.graph.project_nodes
    assert result.graph.package_nodes


def test_audit_directory_uses_snapshot() -> None:
    config = Config(advisory_dir=FIXTURES / "osv_snapshot")
    _, _, analysis = audit_directory(NODE, config)
    ids = {finding.advisory.id for finding in analysis.findings}
    assert "OSV-2023-0002" in ids


def test_make_report_and_sarif_and_cyclonedx() -> None:
    from helpers import FakeProvider
    from pydeepmesh.advisories.matcher import match_graph
    from pydeepmesh.risk.analysis import analyze

    scan = scan_directory(NODE)
    advisory = make_advisory(
        "A", ecosystem="npm", name="express", fixed="4.19.0", range_type="SEMVER"
    )
    report = match_graph(scan.graph, FakeProvider([advisory]))
    analysis = analyze(scan.graph, report)

    document = make_report(scan, analysis, report)
    assert document["schema_version"]
    sarif = make_sarif(scan, analysis)
    assert sarif["version"] == "2.1.0"
    sbom = make_cyclonedx(scan)
    assert sbom["bomFormat"] == "CycloneDX"


def test_advisory_provider_selection(tmp_path: Path) -> None:
    assert isinstance(advisory_provider(Config()), NullProvider)
    assert isinstance(advisory_provider(Config(advisory_dir=tmp_path)), SnapshotProvider)
    assert isinstance(advisory_provider(Config(online=True)), OsvProvider)


def test_python_dash_m() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "pydeepmesh", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "pydeepmesh" in result.stdout
