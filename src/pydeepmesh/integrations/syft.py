"""Optional container-image scanning via Syft.

Syft (Apache-2.0) catalogs packages inside container images and emits a
CycloneDX SBOM. PyDeepMesh does not reimplement image-layer analysis; this
adapter consumes Syft's output and converts it into the canonical dependency
graph so existing graph/risk/SBOM/report code can operate on it.

Syft is a separate Go binary:

    https://github.com/anchore/syft

Install it on PATH, or pass ``syft_path=...``. The adapter fails with an
actionable error when the binary is missing; it never returns an empty graph
as if the image had no packages.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydeepmesh.discovery import DiscoveryResult
from pydeepmesh.models.ecosystem import Ecosystem
from pydeepmesh.models.graph import DependencyGraph, Edge, EdgeKind, Node, NodeKind
from pydeepmesh.models.package import PackageKey
from pydeepmesh.models.scope import ResolutionStatus, Scope
from pydeepmesh.pipeline import ScanResult


class SyftUnavailable(RuntimeError):  # noqa: N818
    """Raised when the Syft binary is not installed."""


@dataclass
class ImageScanResult:
    image: str
    graph: DependencyGraph
    components: list[dict[str, Any]] = field(default_factory=list)
    sbom: dict[str, Any] = field(default_factory=dict)

    def to_scan_result(self) -> ScanResult:
        """Wrap the image graph in the standard ``ScanResult`` shape."""
        return ScanResult(
            root=Path(self.image),
            discovery=DiscoveryResult(),
            manifests=[],
            graph=self.graph,
            diagnostics=[],
        )


def _ecosystem_from_purl(purl: str | None) -> Ecosystem:
    if not purl or not purl.startswith("pkg:"):
        return Ecosystem.GENERIC
    kind = purl[4:].split("/", 1)[0].lower()
    return {
        "pypi": Ecosystem.PYPI,
        "npm": Ecosystem.NPM,
        "cargo": Ecosystem.CRATES,
        "docker": Ecosystem.DOCKER,
    }.get(kind, Ecosystem.GENERIC)


class SyftScanner:
    """Run Syft and convert its CycloneDX output into a dependency graph."""

    def __init__(self, syft_path: str = "syft", timeout: int = 300):
        self.syft_path = syft_path
        self.timeout = timeout

    def is_available(self) -> bool:
        return shutil.which(self.syft_path) is not None

    def _require_binary(self) -> str:
        resolved = shutil.which(self.syft_path)
        if resolved is None:
            raise SyftUnavailable(
                "syft was not found on PATH. Install the Apache-2.0 Syft binary "
                "from https://github.com/anchore/syft (e.g. "
                "`brew install syft` or `curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh`) "
                "or pass syft_path=..."
            )
        return resolved

    def scan(self, image: str) -> ImageScanResult:
        if not image or not image.strip():
            raise ValueError("image reference must be non-empty")
        binary = self._require_binary()
        cmd = [binary, image, "-o", "cyclonedx-json", "-q"]
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"syft timed out after {self.timeout}s") from exc

        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "").strip()
            raise RuntimeError(f"syft failed ({completed.returncode}): {detail[:800]}")

        try:
            sbom = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"syft emitted invalid JSON: {exc}") from exc

        return self.from_sbom(image, sbom)

    def from_sbom(self, image: str, sbom: dict[str, Any]) -> ImageScanResult:
        components = sbom.get("components") or []
        if not isinstance(components, list):
            raise ValueError("CycloneDX components must be a list")

        graph = DependencyGraph()
        root_id = f"image:{image}"
        graph.nodes[root_id] = Node(
            id=root_id,
            kind=NodeKind.PROJECT,
            display_name=image,
            scopes=frozenset({Scope.RUNTIME}),
            resolution=ResolutionStatus.RESOLVED,
            metadata=(("source", "syft"), ("artifact", image)),
        )

        ref_to_id: dict[str, str] = {}
        normalized: list[dict[str, Any]] = []
        for component in components:
            if not isinstance(component, dict):
                continue
            name = str(component.get("name") or "").strip()
            if not name:
                continue
            version = str(component.get("version")) if component.get("version") else None
            purl = component.get("purl")
            ecosystem = _ecosystem_from_purl(purl)
            key = PackageKey.create(ecosystem, name, version)
            node_id = purl or f"component:{component.get('bom-ref') or key.stable_id()}"
            if node_id in graph.nodes:
                continue
            graph.nodes[node_id] = Node(
                id=node_id,
                kind=NodeKind.PACKAGE,
                display_name=name,
                version=version,
                key=key,
                scopes=frozenset({Scope.RUNTIME}),
                resolution=ResolutionStatus.RESOLVED if version else ResolutionStatus.UNKNOWN,
                metadata=(
                    ("source", "syft"),
                    ("component_type", str(component.get("type") or "library")),
                ),
                purl=purl,
            )
            for ref in (component.get("bom-ref"), purl, node_id):
                if ref:
                    ref_to_id[str(ref)] = node_id
            normalized.append(
                {
                    "name": name,
                    "version": version,
                    "purl": purl,
                    "type": component.get("type"),
                    "bom_ref": component.get("bom-ref"),
                    "node_id": node_id,
                }
            )
            graph.edges.append(
                Edge(
                    source=root_id,
                    target=node_id,
                    kind=EdgeKind.RESOLVED if version else EdgeKind.DECLARED,
                    scope=Scope.RUNTIME,
                    confidence=1.0,
                )
            )

        for dependency in sbom.get("dependencies") or []:
            if not isinstance(dependency, dict):
                continue
            source_ref = dependency.get("ref")
            source_id = ref_to_id.get(str(source_ref)) if source_ref else None
            if not source_id:
                continue
            for target_ref in dependency.get("dependsOn") or []:
                target_id = ref_to_id.get(str(target_ref))
                if target_id and target_id != source_id:
                    graph.edges.append(
                        Edge(
                            source=source_id,
                            target=target_id,
                            kind=EdgeKind.RESOLVED,
                            scope=Scope.RUNTIME,
                            confidence=1.0,
                        )
                    )

        graph.reindex()
        return ImageScanResult(
            image=image,
            graph=graph,
            components=normalized,
            sbom=sbom,
        )


def scan_image(
    image: str,
    *,
    syft_path: str = "syft",
    timeout: int = 300,
) -> ImageScanResult:
    """Convenience wrapper around :class:`SyftScanner`."""
    return SyftScanner(syft_path=syft_path, timeout=timeout).scan(image)


__all__ = [
    "ImageScanResult",
    "SyftScanner",
    "SyftUnavailable",
    "scan_image",
]
