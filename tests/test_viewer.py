"""Self-contained HTML graph viewer: determinism, safety, offline output."""

from __future__ import annotations

import json
from pathlib import Path

from helpers import FIXTURES, scan_fixture
from pydeepmesh.report.viewer import (
    build_viewer_document,
    render_viewer,
    render_viewer_json,
)


def test_viewer_document_shape() -> None:
    document = build_viewer_document(scan_fixture("node_project"))
    assert document["nodes"]
    assert "layout" in document and document["layout"]["width"] > 0
    for node in document["nodes"]:
        assert "x" in node and "y" in node
    json.loads(render_viewer_json(document))


def test_viewer_is_deterministic() -> None:
    first = render_viewer(build_viewer_document(scan_fixture("python_project")))
    second = render_viewer(build_viewer_document(scan_fixture("python_project")))
    assert first == second


def test_viewer_is_self_contained() -> None:
    output = render_viewer(build_viewer_document(scan_fixture("node_project")))
    assert output.startswith("<!DOCTYPE html>")
    assert "<script" not in output
    assert "<link" not in output
    assert "cdn" not in output.lower()
    assert "https://" not in output
    assert "<svg" in output and "</svg>" in output


def test_viewer_contains_nodes_and_edges() -> None:
    document = build_viewer_document(scan_fixture("node_project"))
    output = render_viewer(document)
    assert "express" in output
    assert output.count("<line") == len(document["edges"])


def test_viewer_escapes_untrusted_labels(tmp_path: Path) -> None:
    project = tmp_path / "evil"
    project.mkdir()
    (project / "package.json").write_text(
        json.dumps(
            {
                "name": "evil",
                "version": "1.0.0",
                "dependencies": {"<script>alert(1)</script>": "^1.0.0"},
            }
        )
    )
    from pydeepmesh.pipeline import scan

    document = build_viewer_document(scan(project))
    output = render_viewer(document)
    assert "<script>alert(1)</script>" not in output
    assert "&lt;script&gt;" in output


def test_cli_graph_html(capsys) -> None:
    from pydeepmesh.cli.main import EXIT_OK, main

    code = main(["graph", str(FIXTURES / "node_project"), "--format", "html"])
    assert code == EXIT_OK
    assert "<!DOCTYPE html>" in capsys.readouterr().out
