"""Deterministic, self-contained HTML dependency-graph viewer.

The viewer is intentionally static: the layout is computed in Python and the
document is plain HTML with inline CSS and inline SVG. There is no JavaScript,
no external stylesheet, no CDN, and no telemetry, so output is byte-for-byte
deterministic and renders with scripting disabled.
"""

from __future__ import annotations

import html
import json
from typing import Any

from pydeepmesh.graph.algorithms import reachable_from
from pydeepmesh.models.graph import NodeKind
from pydeepmesh.pipeline import ScanResult
from pydeepmesh.version import __version__

_X_GAP = 240
_Y_GAP = 44
_MARGIN = 40
_NODE_WIDTH = 172
_NODE_HEIGHT = 26

_KIND_LABEL = {
    NodeKind.PROJECT: "project",
    NodeKind.PACKAGE: "package",
}


def _layout(graph: Any) -> dict[str, Any]:
    """Compute a deterministic layered layout (depth on X, order on Y)."""

    depths: dict[str, int] = {}
    for root in graph.roots:
        depths[root] = 0
        for node_id, depth in reachable_from(graph, root).items():
            if node_id not in depths or depth < depths[node_id]:
                depths[node_id] = depth
    fallback = (max(depths.values()) + 1) if depths else 0

    layers: dict[int, list[str]] = {}
    for node in graph.iter_nodes_sorted():
        layer = depths.get(node.id, fallback)
        layers.setdefault(layer, []).append(node.id)

    positions: dict[str, tuple[int, int]] = {}
    max_rows = 0
    for layer in sorted(layers):
        ids = sorted(layers[layer])
        max_rows = max(max_rows, len(ids))
        for row, node_id in enumerate(ids):
            positions[node_id] = (_MARGIN + layer * _X_GAP, _MARGIN + row * _Y_GAP)

    return {
        "positions": positions,
        "width": _MARGIN * 2 + (max(layers) if layers else 0) * _X_GAP + _NODE_WIDTH,
        "height": _MARGIN * 2 + max(max_rows, 1) * _Y_GAP,
        "layer_count": (max(layers) + 1) if layers else 0,
    }


def build_viewer_document(scan: ScanResult) -> dict[str, Any]:
    """Build a serializable viewer document with a precomputed layout."""

    graph = scan.graph
    layout = _layout(graph)
    positions = layout["positions"]
    nodes: list[dict[str, Any]] = []
    for node in graph.iter_nodes_sorted():
        x, y = positions.get(node.id, (_MARGIN, _MARGIN))
        entry: dict[str, Any] = {
            "id": node.id,
            "label": node.display_name,
            "kind": node.kind.value,
            "version": node.version,
            "ecosystem": node.key.ecosystem.value if node.key else None,
            "x": x,
            "y": y,
        }
        nodes.append(entry)
    return {
        "tool": {"name": "pydeepmesh", "version": __version__},
        "root": str(scan.root),
        "layout": {"width": layout["width"], "height": layout["height"]},
        "nodes": nodes,
        "edges": [edge.to_dict() for edge in graph.edges],
    }


def _node_fill(node: dict[str, Any]) -> str:
    if node["kind"] == NodeKind.PROJECT.value:
        return "#1f6feb"
    if node["ecosystem"] == "docker":
        return "#8250df"
    return "#3fb950"


def _label(node: dict[str, Any]) -> str:
    label = str(node["label"])
    if node["version"]:
        label = f"{label} {node['version']}"
    return label


def render_viewer(document: dict[str, Any]) -> str:
    """Render a viewer document to a complete HTML string."""

    layout = document["layout"]
    width = int(layout["width"])
    height = int(layout["height"])
    nodes = document["nodes"]
    by_id = {node["id"]: node for node in nodes}

    parts: list[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en">')
    parts.append("<head>")
    parts.append('<meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    escaped_root = html.escape(document["root"])
    parts.append(f"<title>PyDeepMesh dependency graph - {escaped_root}</title>")
    parts.append("<style>")
    parts.append(
        "body{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;margin:0;"
        "background:#0d1117;color:#c9d1d9}"
        "header{padding:12px 16px;border-bottom:1px solid #30363d}"
        "main{overflow:auto;padding:0}"
        "svg{display:block}"
        ".edge{stroke:#484f58;stroke-width:1}"
        ".edge-container_from{stroke:#8250df}"
        ".edge-compose_depends_on{stroke:#d29922;stroke-dasharray:4 2}"
        ".node text{fill:#c9d1d9;font-size:11px}"
        ".node rect{stroke:#30363d;stroke-width:1}"
        "h1{font-size:14px;margin:0 0 4px}small{color:#8b949e}"
        "</style>"
    )
    parts.append("</head>")
    parts.append("<body>")
    parts.append("<header>")
    parts.append(f"<h1>PyDeepMesh dependency graph ({__version__})</h1>")
    parts.append(
        f"<small>root: {escaped_root} &middot; nodes: {len(nodes)} &middot; "
        f"edges: {len(document['edges'])} &middot; layers: {layout.get('layer_count', 0)}</small>"
    )
    parts.append("</header>")
    parts.append("<main>")
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-label="Dependency graph">'
    )
    for edge in document["edges"]:
        source = by_id.get(edge["source"])
        target = by_id.get(edge["target"])
        if source is None or target is None:
            continue
        kind = edge["kind"]
        css = f"edge edge-{kind}"
        parts.append(
            f'<line class="{css}" x1="{source["x"]}" y1="{source["y"]}" '
            f'x2="{target["x"]}" y2="{target["y"]}"/>'
        )
    for node in nodes:
        x = node["x"]
        y = node["y"]
        fill = _node_fill(node)
        text = html.escape(_label(node))
        tooltip = html.escape(f"{node['kind']}: {node['id']}")
        parts.append(f'<g class="node" transform="translate({x},{y})">')
        parts.append(f"<title>{tooltip}</title>")
        parts.append(
            f'<rect x="0" y="-14" width="{_NODE_WIDTH}" height="{_NODE_HEIGHT}" rx="4" '
            f'fill="{fill}" fill-opacity="0.18"/>'
        )
        parts.append(f'<circle cx="6" cy="0" r="4" fill="{fill}"/>')
        parts.append(f'<text x="16" y="4">{text}</text>')
        parts.append("</g>")
    parts.append("</svg>")
    parts.append("</main>")
    parts.append("</body>")
    parts.append("</html>")
    return "\n".join(parts) + "\n"


def render_viewer_json(document: dict[str, Any]) -> str:
    """Serialize the viewer document as JSON (for programmatic consumers)."""

    return json.dumps(document, indent=2, sort_keys=False) + "\n"
