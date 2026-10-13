"""CycloneDX 1.5 JSON SBOM generation."""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from pydeepmesh.models.graph import DependencyGraph, Node, NodeKind
from pydeepmesh.pipeline import ScanResult
from pydeepmesh.version import __version__

SPEC_VERSION = "1.5"
_SCHEMA = "http://cyclonedx.org/schema/bom-1.5.schema.json"


def _bom_ref(node: Node) -> str:
    if node.purl:
        return node.purl
    return f"pydeepmesh:{node.id}"


def _component_type(node: Node) -> str:
    if node.kind is NodeKind.PROJECT:
        return "application"
    if node.key is not None and node.key.ecosystem.value == "docker":
        return "container"
    return "library"


def _serial_number(graph: DependencyGraph) -> str:
    refs = sorted(_bom_ref(node) for node in graph.iter_nodes_sorted())
    digest = hashlib.sha256("\n".join(refs).encode("utf-8")).hexdigest()
    return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, digest)}"


def build_cyclonedx(scan: ScanResult, *, timestamp: str | None = None) -> dict[str, Any]:
    graph = scan.graph
    components: list[dict[str, Any]] = []
    for node in graph.iter_nodes_sorted():
        component: dict[str, Any] = {
            "type": _component_type(node),
            "bom-ref": _bom_ref(node),
            "name": node.display_name,
        }
        if node.version:
            component["version"] = node.version
        if node.purl:
            component["purl"] = node.purl
        if node.key is not None:
            component["properties"] = [
                {"name": "pydeepmesh:ecosystem", "value": node.key.ecosystem.value},
                {"name": "pydeepmesh:resolution", "value": node.resolution.value},
            ]
        components.append(component)

    dependencies = _dependencies(graph)

    metadata: dict[str, Any] = {
        "tools": [{"vendor": "PyDeepMesh", "name": "pydeepmesh", "version": __version__}],
        "component": {
            "type": "application",
            "bom-ref": f"pydeepmesh:root:{scan.root}",
            "name": scan.root.name or "root",
        },
    }
    if timestamp is not None:
        metadata["timestamp"] = timestamp

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": _serial_number(graph),
        "version": 1,
        "metadata": metadata,
        "components": components,
        "dependencies": dependencies,
    }


def _dependencies(graph: DependencyGraph) -> list[dict[str, Any]]:
    depends_on: dict[str, set[str]] = {}
    for edge in graph.edges:
        source = graph.get(edge.source)
        target = graph.get(edge.target)
        if source is None or target is None:
            continue
        depends_on.setdefault(_bom_ref(source), set()).add(_bom_ref(target))
    entries: list[dict[str, Any]] = []
    for ref in sorted({_bom_ref(n) for n in graph.iter_nodes_sorted()}):
        entries.append({"ref": ref, "dependsOn": sorted(depends_on.get(ref, set()))})
    return entries


def render_cyclonedx(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=False) + "\n"
