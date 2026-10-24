"""SPDX 2.3 JSON SBOM generation."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from pydeepmesh.models.graph import DependencyGraph, Node, NodeKind
from pydeepmesh.pipeline import ScanResult
from pydeepmesh.version import __version__

SPDX_VERSION = "SPDX-2.3"
_DOCUMENT_ID = "SPDXRef-DOCUMENT"
_ROOT_ID = "SPDXRef-RootPackage"
_DEFAULT_CREATED = "1970-01-01T00:00:00Z"


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9.-]+", "-", value).strip("-")
    return cleaned or "package"


def _package_id(node: Node) -> str:
    digest = hashlib.sha256(node.id.encode("utf-8")).hexdigest()[:8]
    return f"SPDXRef-Package-{_slug(node.display_name)}-{digest}"


def _purpose(node: Node) -> str:
    if node.kind is NodeKind.PROJECT:
        return "APPLICATION"
    if node.key is not None and node.key.ecosystem.value == "docker":
        return "CONTAINER"
    return "LIBRARY"


def _root_node(graph: DependencyGraph) -> Node | None:
    for node in graph.iter_nodes_sorted():
        if node.kind is NodeKind.PROJECT:
            return node
    return None


def _namespace(graph: DependencyGraph) -> str:
    refs = sorted(node.id for node in graph.iter_nodes_sorted())
    digest = hashlib.sha256("\n".join(refs).encode("utf-8")).hexdigest()
    return f"https://spdx.org/spdxdocs/pydeepmesh-{digest[:32]}"


def _package(node: Node) -> dict[str, Any]:
    package: dict[str, Any] = {
        "SPDXID": _package_id(node),
        "name": node.display_name,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": _purpose(node),
    }
    if node.version:
        package["versionInfo"] = node.version
    if node.purl:
        package["externalRefs"] = [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": node.purl,
            }
        ]
    return package


def build_spdx(scan: ScanResult, *, timestamp: str | None = None) -> dict[str, Any]:
    graph = scan.graph
    root = _root_node(graph)
    root_id = _package_id(root) if root is not None else _ROOT_ID
    packages = [_package(node) for node in graph.iter_nodes_sorted()]
    if root is None:
        packages.insert(
            0,
            {
                "SPDXID": _ROOT_ID,
                "name": scan.root.name or "root",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "primaryPackagePurpose": "APPLICATION",
            },
        )

    node_ids = {node.id: _package_id(node) for node in graph.iter_nodes_sorted()}
    relationships: list[dict[str, str]] = [
        {
            "spdxElementId": _DOCUMENT_ID,
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": root_id,
        }
    ]
    seen: set[tuple[str, str, str]] = set()
    for edge in graph.edges:
        source = node_ids.get(edge.source)
        target = node_ids.get(edge.target)
        if source is None or target is None:
            continue
        key = (source, "DEPENDS_ON", target)
        if key in seen:
            continue
        seen.add(key)
        relationships.append(
            {
                "spdxElementId": source,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": target,
            }
        )

    return {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": "CC0-1.0",
        "SPDXID": _DOCUMENT_ID,
        "name": f"PyDeepMesh SBOM for {scan.root.name or 'root'}",
        "documentNamespace": _namespace(graph),
        "creationInfo": {
            "created": timestamp or _DEFAULT_CREATED,
            "creators": [f"Tool: pydeepmesh-{__version__}"],
        },
        "packages": packages,
        "relationships": relationships,
    }


def render_spdx(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=False) + "\n"
