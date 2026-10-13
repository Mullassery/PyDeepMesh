"""Canonical domain models shared across PyDeepMesh layers."""

from __future__ import annotations

from pydeepmesh.models.ecosystem import Ecosystem
from pydeepmesh.models.finding import (
    Finding,
    MatchResult,
    MatchStatus,
    Priority,
    Remediation,
)
from pydeepmesh.models.graph import DependencyGraph, Edge, EdgeKind, Node, NodeKind
from pydeepmesh.models.package import PackageKey, normalize_name, package_url
from pydeepmesh.models.provenance import SourceLocation
from pydeepmesh.models.scope import ResolutionStatus, Scope
from pydeepmesh.models.vulnerability import (
    Advisory,
    AffectedPackage,
    VersionRange,
    VulnerabilitySeverity,
)

__all__ = [
    "Advisory",
    "AffectedPackage",
    "DependencyGraph",
    "Ecosystem",
    "Edge",
    "EdgeKind",
    "Finding",
    "MatchResult",
    "MatchStatus",
    "Node",
    "NodeKind",
    "PackageKey",
    "Priority",
    "Remediation",
    "ResolutionStatus",
    "Scope",
    "SourceLocation",
    "VersionRange",
    "VulnerabilitySeverity",
    "normalize_name",
    "package_url",
]
