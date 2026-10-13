"""Shared helpers for Python ecosystem parsers."""

from __future__ import annotations

import re

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from pydeepmesh.models.ecosystem import Ecosystem
from pydeepmesh.models.provenance import SourceLocation
from pydeepmesh.models.scope import ResolutionStatus, Scope
from pydeepmesh.parsers.base import Dependency

_DEV_GROUP_NAMES = {"dev", "develop", "development"}
_TEST_GROUP_NAMES = {"test", "tests", "testing"}

_VERSION_OPERATORS = re.compile(r"[<>=!~^]|@")


def find_line(text: str, needle: str) -> int | None:
    """Best-effort 1-based line number of the first line containing ``needle``."""

    for index, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return index
    return None


def scope_for_group(group: str) -> Scope:
    lowered = group.lower()
    if lowered in _DEV_GROUP_NAMES:
        return Scope.DEVELOPMENT
    if lowered in _TEST_GROUP_NAMES:
        return Scope.TEST
    return Scope.OPTIONAL


def requirement_to_dependency(
    requirement: str,
    *,
    scope: Scope,
    optional: bool,
    origin: SourceLocation,
) -> Dependency | None:
    """Convert a PEP 508 requirement string into a :class:`Dependency`."""

    try:
        parsed = Requirement(requirement)
    except InvalidRequirement:
        return None
    constraint = str(parsed.specifier) or None
    pinned = is_pinned_specifier(constraint)
    return Dependency(
        ecosystem=Ecosystem.PYPI,
        name=parsed.name,
        scope=scope,
        constraint=constraint,
        version=pinned,
        resolution=ResolutionStatus.RESOLVED if pinned else ResolutionStatus.DECLARED,
        optional=optional,
        extras=tuple(sorted(parsed.extras)),
        origin=origin,
    )


def is_pinned_specifier(specifier: str | None) -> str | None:
    """Return the exact version from an ``==``-only specifier, else ``None``."""

    if not specifier:
        return None
    match = re.fullmatch(r"==\s*([^\s,;]+)", specifier.strip())
    if match:
        return match.group(1)
    return None


def resolved_dependency(
    name: str,
    version: str,
    *,
    scope: Scope,
    origin: SourceLocation,
) -> Dependency:
    return Dependency(
        ecosystem=Ecosystem.PYPI,
        name=name,
        scope=scope,
        version=version,
        resolution=ResolutionStatus.RESOLVED,
        origin=origin,
    )


def canonical(name: str) -> str:
    return canonicalize_name(name)
