"""Dependency scope and resolution status."""

from __future__ import annotations

import enum


class Scope(str, enum.Enum):
    """The role a dependency plays in a project."""

    RUNTIME = "runtime"
    DEVELOPMENT = "development"
    BUILD = "build"
    TEST = "test"
    OPTIONAL = "optional"
    PEER = "peer"
    CONTAINER = "container"
    OS = "os"
    UNKNOWN = "unknown"


class ResolutionStatus(str, enum.Enum):
    """How confidently a package version is known."""

    RESOLVED = "resolved"
    """A concrete version was taken from a lockfile."""

    DECLARED = "declared"
    """Only a constraint (e.g. ``^1.2``) was declared; no concrete version."""

    UNRESOLVED = "unresolved"
    """Resolution was attempted and failed."""

    UNKNOWN = "unknown"
    """Status could not be determined from the input."""
