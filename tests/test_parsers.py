"""Parser and end-to-end scan coverage across every supported ecosystem."""

from __future__ import annotations

import pytest

from helpers import scan_fixture
from pydeepmesh.models.ecosystem import Ecosystem
from pydeepmesh.models.graph import NodeKind
from pydeepmesh.models.package import PackageKey
from pydeepmesh.models.scope import ResolutionStatus, Scope


def _node(graph, ecosystem: Ecosystem, name: str, version: str | None):
    return graph.node_by_key(PackageKey.create(ecosystem, name, version))


def test_python_graph_resolution() -> None:
    result = scan_fixture("python_project")
    graph = result.graph

    requests = _node(graph, Ecosystem.PYPI, "requests", "2.31.0")
    assert requests is not None
    assert requests.resolution is ResolutionStatus.RESOLVED
    assert requests.version == "2.31.0"

    flask = _node(graph, Ecosystem.PYPI, "flask", "2.3.0")
    assert flask is not None

    pyyaml = _node(graph, Ecosystem.PYPI, "pyyaml", "6.0.1")
    assert pyyaml is not None

    pytest_node = _node(graph, Ecosystem.PYPI, "pytest", None)
    assert pytest_node is not None
    assert pytest_node.resolution is ResolutionStatus.DECLARED
    assert Scope.DEVELOPMENT in pytest_node.scopes


def test_python_editable_and_constraint_diagnostics() -> None:
    result = scan_fixture("python_project")
    codes = {d.code for d in result.parse_diagnostics}
    assert "requirements.constraint_ignored" in codes
    foo = _node(result.graph, Ecosystem.PYPI, "foo", None)
    assert foo is not None


def test_rust_graph() -> None:
    result = scan_fixture("rust_project")
    graph = result.graph
    for name, version in [
        ("serde", "1.0.190"),
        ("rand", "0.8.5"),
        ("libc", "0.2.147"),
        ("cfg-if", "1.0.0"),
        ("tempfile", "3.8.0"),
    ]:
        assert _node(graph, Ecosystem.CRATES, name, version) is not None

    rand = _node(graph, Ecosystem.CRATES, "rand", "0.8.5")
    libc = _node(graph, Ecosystem.CRATES, "libc", "0.2.147")
    assert rand is not None and libc is not None
    targets = {edge.target for edge in graph.out_edges(rand.id)}
    assert libc.id in targets

    tempfile = _node(graph, Ecosystem.CRATES, "tempfile", "3.8.0")
    assert tempfile is not None and Scope.DEVELOPMENT in tempfile.scopes


def test_node_graph() -> None:
    result = scan_fixture("node_project")
    graph = result.graph
    assert _node(graph, Ecosystem.NPM, "lodash", "4.17.21") is not None
    express = _node(graph, Ecosystem.NPM, "express", "4.18.2")
    accepts = _node(graph, Ecosystem.NPM, "accepts", "1.3.8")
    assert express is not None and accepts is not None
    assert accepts.id in {edge.target for edge in graph.out_edges(express.id)}

    jest = _node(graph, Ecosystem.NPM, "jest", "29.7.0")
    assert jest is not None and Scope.DEVELOPMENT in jest.scopes

    fsevents = _node(graph, Ecosystem.NPM, "fsevents", "2.3.3")
    assert fsevents is not None and Scope.OPTIONAL in fsevents.scopes


def test_uv_lock_graph() -> None:
    result = scan_fixture("uv_project")
    graph = result.graph
    assert _node(graph, Ecosystem.PYPI, "requests", "2.31.0") is not None
    requests = _node(graph, Ecosystem.PYPI, "requests", "2.31.0")
    urllib3 = _node(graph, Ecosystem.PYPI, "urllib3", "2.0.7")
    assert requests is not None and urllib3 is not None
    assert urllib3.id in {edge.target for edge in graph.out_edges(requests.id)}


def test_yarn_classic_graph() -> None:
    result = scan_fixture("yarn_classic_project")
    graph = result.graph
    express = _node(graph, Ecosystem.NPM, "express", "4.18.2")
    accepts = _node(graph, Ecosystem.NPM, "accepts", "1.3.8")
    assert express is not None and accepts is not None
    assert accepts.id in {edge.target for edge in graph.out_edges(express.id)}


def test_yarn_berry_graph() -> None:
    result = scan_fixture("yarn_berry_project")
    graph = result.graph
    assert _node(graph, Ecosystem.NPM, "express", "4.18.2") is not None
    assert _node(graph, Ecosystem.NPM, "accepts", "1.3.8") is not None


def test_pnpm_graph_with_scoped_package() -> None:
    result = scan_fixture("pnpm_project")
    graph = result.graph
    assert _node(graph, Ecosystem.NPM, "lodash", "4.17.21") is not None
    jest = _node(graph, Ecosystem.NPM, "jest", "29.7.0")
    core = _node(graph, Ecosystem.NPM, "@jest/core", "29.7.0")
    assert jest is not None and core is not None
    assert core.id in {edge.target for edge in graph.out_edges(jest.id)}


def test_container_graph() -> None:
    result = scan_fixture("container_project")
    graph = result.graph
    images = {
        node.display_name: node.version
        for node in graph.package_nodes
        if node.key is not None and node.key.ecosystem is Ecosystem.DOCKER
    }
    assert "python" in images and images["python"] == "3.12-slim"
    assert "node" in images
    assert images.get("nginx") == "1.25"
    assert images.get("postgres") == "16"


def test_malformed_inputs_never_raise() -> None:
    result = scan_fixture("malformed")
    codes = {d.code for d in result.parse_diagnostics}
    assert codes

    packages = [n for n in result.graph.nodes.values() if n.kind is NodeKind.PACKAGE]
    assert any(p.key is not None and p.key.name == "requests" for p in packages)


def test_scan_is_deterministic() -> None:
    first = scan_fixture("python_project")
    second = scan_fixture("python_project")
    assert first.graph.to_dict() == second.graph.to_dict()


@pytest.mark.parametrize(
    "fixture",
    [
        "python_project",
        "rust_project",
        "node_project",
        "uv_project",
        "yarn_classic_project",
        "yarn_berry_project",
        "pnpm_project",
        "container_project",
    ],
)
def test_every_fixture_has_a_project_root(fixture: str) -> None:
    result = scan_fixture(fixture)
    assert result.graph.project_nodes
