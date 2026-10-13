"""CLI behavior and the exit-code contract."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from helpers import FIXTURES
from pydeepmesh.cli.main import (
    EXIT_INPUT,
    EXIT_OK,
    EXIT_UNAVAILABLE,
    EXIT_USAGE,
    main,
)

NODE = str(FIXTURES / "node_project")
PYTHON = str(FIXTURES / "python_project")
SNAPSHOT = str(FIXTURES / "osv_snapshot")


def test_scan_json(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["scan", NODE, "--format", "json"])
    assert code == EXIT_OK
    document = json.loads(capsys.readouterr().out)
    assert document["summary"]["packages"] >= 1


def test_scan_terminal(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", NODE]) == EXIT_OK
    assert "PyDeepMesh" in capsys.readouterr().out


def test_missing_path_is_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["scan", str(FIXTURES / "nope")])
    assert code == EXIT_USAGE
    assert "does not exist" in capsys.readouterr().err


def test_graph_cycles(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["graph", str(FIXTURES / "cycle_project"), "--cycles"])
    assert code == EXIT_OK
    assert "Cycles" in capsys.readouterr().out


def test_graph_roots_json(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["graph", NODE, "--roots", "--format", "json"])
    assert code == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["roots"]


def test_sbom_output(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["sbom", NODE]) == EXIT_OK
    document = json.loads(capsys.readouterr().out)
    assert document["bomFormat"] == "CycloneDX"


def test_audit_offline_without_source_requires_advisory(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["audit", NODE, "--require-advisory"])
    assert code == EXIT_UNAVAILABLE


def test_audit_with_snapshot_finds_express(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["audit", NODE, "--advisory-dir", SNAPSHOT, "--format", "json"])
    assert code == EXIT_OK
    document = json.loads(capsys.readouterr().out)
    ids = {finding["advisory"]["id"] for finding in document["findings"]}
    assert "OSV-2023-0002" in ids


def test_audit_fail_on_triggers_findings(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["audit", NODE, "--advisory-dir", SNAPSHOT, "--fail-on", "low"])
    assert code == 1


def test_audit_fail_on_never_returns_ok(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["audit", NODE, "--advisory-dir", SNAPSHOT, "--fail-on", "never"])
    assert code == EXIT_OK


def test_output_is_confined_to_output_root(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    outside = tmp_path / "escape.json"
    code = main(["scan", NODE, "--format", "json", "--output", str(outside)])
    assert code in {EXIT_USAGE, EXIT_INPUT}
    assert not outside.exists()


def test_output_within_root_writes_file(tmp_path: Path) -> None:
    target = tmp_path / "out" / "report.json"
    code = main(
        [
            "scan",
            NODE,
            "--format",
            "json",
            "--output-root",
            str(tmp_path),
            "--output",
            "out/report.json",
        ]
    )
    assert code == EXIT_OK
    assert target.exists()


def test_advisories_update_requires_online(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["advisories", "update", NODE])
    assert code == EXIT_USAGE
    assert "--online" in capsys.readouterr().err


def test_advisories_clear(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["advisories", "clear", "--cache-dir", str(tmp_path)])
    assert code == EXIT_OK
    assert "cleared" in capsys.readouterr().out
