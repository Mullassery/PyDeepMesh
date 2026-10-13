"""Parser framework: declaration/resolution records and the ``Parser`` protocol."""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from pathlib import Path

from pydeepmesh.diagnostics import Diagnostic
from pydeepmesh.models.ecosystem import Ecosystem
from pydeepmesh.models.provenance import SourceLocation
from pydeepmesh.models.scope import ResolutionStatus, Scope

# File roles within a project.
ROLE_MANIFEST = "manifest"
ROLE_LOCKFILE = "lockfile"
ROLE_CONTAINER = "container"


@dataclass(frozen=True)
class Dependency:
    """A declared or resolved dependency record."""

    ecosystem: Ecosystem
    name: str
    scope: Scope = Scope.RUNTIME
    constraint: str | None = None
    version: str | None = None
    resolution: ResolutionStatus = ResolutionStatus.DECLARED
    optional: bool = False
    extras: tuple[str, ...] = ()
    origin: SourceLocation | None = None
    source_role: str = ROLE_MANIFEST

    @property
    def is_resolved(self) -> bool:
        return self.version is not None and self.resolution is ResolutionStatus.RESOLVED


@dataclass(frozen=True)
class DependencyRef:
    """A reference from one resolved package to another (a lockfile edge)."""

    name: str
    constraint: str | None = None
    version: str | None = None
    optional: bool = False


@dataclass(frozen=True)
class ResolvedPackage:
    """A package captured from a lockfile, with its own dependency edges."""

    ecosystem: Ecosystem
    name: str
    version: str
    scope: Scope = Scope.RUNTIME
    dependencies: tuple[DependencyRef, ...] = ()
    origin: SourceLocation | None = None
    metadata: tuple[tuple[str, str], ...] = ()


@dataclass
class ParsedManifest:
    """Everything one parser extracted from one file."""

    rel_path: str
    abs_path: Path
    ecosystem: Ecosystem
    parser_id: str
    role: str = ROLE_MANIFEST
    is_root: bool = False
    project_name: str | None = None
    project_version: str | None = None
    declarations: list[Dependency] = field(default_factory=list)
    packages: list[ResolvedPackage] = field(default_factory=list)
    metadata: list[tuple[str, str]] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)


class Parser(abc.ABC):
    """Base class for ecosystem parsers.

    Implementations must not raise for malformed input. They should append
    diagnostics and return a :class:`ParsedManifest` with whatever was parsed.
    """

    parser_id: str
    ecosystem: Ecosystem
    file_names: tuple[str, ...] = ()
    file_suffixes: tuple[str, ...] = ()
    role: str = ROLE_MANIFEST
    is_root: bool = True

    def matches(self, path: Path) -> bool:
        if path.name in self.file_names:
            return True
        return any(path.name.endswith(suffix) for suffix in self.file_suffixes)

    @abc.abstractmethod
    def parse(self, path: Path, rel_path: str, *, max_bytes: int, root: Path) -> ParsedManifest:
        """Parse ``path`` into a :class:`ParsedManifest`."""

    def _manifest(self, path: Path, rel_path: str) -> ParsedManifest:
        return ParsedManifest(
            rel_path=rel_path,
            abs_path=path,
            ecosystem=self.ecosystem,
            parser_id=self.parser_id,
            role=self.role,
            is_root=self.is_root,
        )
