"""Parser for Docker Compose manifests (``compose.yaml`` / ``docker-compose.yml``)."""

from __future__ import annotations

from pathlib import Path

import yaml

from pydeepmesh.diagnostics import Severity, make_diagnostic
from pydeepmesh.io import safe_read_text
from pydeepmesh.models.ecosystem import Ecosystem
from pydeepmesh.models.provenance import SourceLocation
from pydeepmesh.models.scope import Scope
from pydeepmesh.parsers.base import Dependency, ParsedManifest, Parser
from pydeepmesh.parsers.container.dockerfile import _split_image


class ComposeParser(Parser):
    parser_id = "container.compose"
    ecosystem = Ecosystem.DOCKER
    file_names = (
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    )
    is_root = True

    def parse(self, path: Path, rel_path: str, *, max_bytes: int, root: Path) -> ParsedManifest:
        manifest = self._manifest(path, rel_path)
        read = safe_read_text(path, max_bytes=max_bytes, root=root)
        if read.diagnostic is not None:
            manifest.diagnostics.append(read.diagnostic)
            return manifest
        try:
            data = yaml.safe_load(read.text or "")
        except yaml.YAMLError as exc:
            manifest.diagnostics.append(
                make_diagnostic(
                    Severity.ERROR, "yaml.invalid", f"invalid YAML: {exc}", path=path, root=root
                )
            )
            return manifest
        manifest.project_name = path.parent.name or "."
        if not isinstance(data, dict):
            return manifest
        services = data.get("services")
        if not isinstance(services, dict):
            manifest.diagnostics.append(
                make_diagnostic(
                    Severity.WARNING,
                    "compose.no_services",
                    "manifest has no 'services' mapping",
                    path=path,
                    root=root,
                )
            )
            return manifest

        for service_name, service in services.items():
            if not isinstance(service, dict):
                continue
            image = service.get("image")
            if isinstance(image, str):
                name, version = _split_image(image)
                manifest.declarations.append(
                    Dependency(
                        ecosystem=Ecosystem.DOCKER,
                        name=name,
                        scope=Scope.CONTAINER,
                        constraint=version,
                        version=version,
                        origin=SourceLocation(rel_path, None),
                        source_role="compose",
                    )
                )
            build = service.get("build")
            if isinstance(build, str):
                manifest.metadata.append((f"compose.service.{service_name}.build", build))
            elif isinstance(build, dict):
                context = build.get("context", ".")
                dockerfile = build.get("dockerfile", "Dockerfile")
                manifest.metadata.append(
                    (f"compose.service.{service_name}.build", f"{context}/{dockerfile}")
                )
            depends_on = service.get("depends_on")
            if isinstance(depends_on, list):
                manifest.metadata.append(
                    (
                        f"compose.service.{service_name}.depends_on",
                        ",".join(str(d) for d in depends_on),
                    )
                )
            elif isinstance(depends_on, dict):
                manifest.metadata.append(
                    (f"compose.service.{service_name}.depends_on", ",".join(depends_on.keys()))
                )
            manifest.metadata.append((f"compose.service.{service_name}.present", "true"))
        return manifest
