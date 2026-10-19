"""Syft adapter tests use a fake executable; no image pull or network."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from pydeepmesh.integrations import SyftScanner, SyftUnavailable


def _fake_syft(tmp_path: Path, sbom: dict) -> Path:
    script = tmp_path / "syft"
    payload = json.dumps(sbom)
    script.write_text(f"#!/usr/bin/env python3\nimport sys\nsys.stdout.write({payload!r})\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


SBOM = {
    "bomFormat": "CycloneDX",
    "components": [
        {
            "type": "library",
            "name": "requests",
            "version": "2.32.0",
            "purl": "pkg:pypi/requests@2.32.0",
            "bom-ref": "pkg:pypi/requests@2.32.0",
        },
        {
            "type": "library",
            "name": "lodash",
            "version": "4.17.21",
            "purl": "pkg:npm/lodash@4.17.21",
            "bom-ref": "pkg:npm/lodash@4.17.21",
        },
    ],
    "dependencies": [
        {
            "ref": "pkg:pypi/requests@2.32.0",
            "dependsOn": ["pkg:npm/lodash@4.17.21"],
        }
    ],
}


def test_scan_image_builds_graph(tmp_path):
    binary = _fake_syft(tmp_path, SBOM)
    result = SyftScanner(syft_path=str(binary)).scan("example/app:latest")
    assert len(result.components) == 2
    assert len(result.graph.nodes) == 3  # root + 2 packages
    assert len(result.graph.edges) == 3  # root->2 packages + package->package
    node = next(n for n in result.graph.nodes.values() if n.display_name == "requests")
    assert node.ecosystem == "pypi"
    assert node.version == "2.32.0"


def test_missing_syft_is_actionable(tmp_path):
    scanner = SyftScanner(syft_path=str(tmp_path / "missing"))
    with pytest.raises(SyftUnavailable, match="syft was not found"):
        scanner.scan("example/app:latest")


def test_invalid_sbom_shape_is_rejected(tmp_path):
    binary = _fake_syft(tmp_path, {"components": "not-a-list"})
    with pytest.raises(ValueError, match="components"):
        SyftScanner(syft_path=str(binary)).scan("x")
