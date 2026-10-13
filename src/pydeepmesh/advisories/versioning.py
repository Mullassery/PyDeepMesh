"""Ecosystem-aware version comparison and advisory range matching.

PyDeepMesh never compares versions lexically. PyPI versions use PEP 440 semantics
(``packaging``); crates.io and npm use semantic versioning.
"""

from __future__ import annotations

import re

from packaging.version import InvalidVersion, Version

from pydeepmesh.models.ecosystem import Ecosystem
from pydeepmesh.models.vulnerability import AffectedPackage, VersionRange

_SEMVER = re.compile(
    r"^v?(?P<major>\d+)(?:\.(?P<minor>\d+))?(?:\.(?P<patch>\d+))?"
    r"(?:-(?P<pre>[0-9A-Za-z.\-]+))?(?:\+(?P<build>[0-9A-Za-z.\-]+))?$"
)


class SemVer:
    """A minimally complete semantic version, tolerant of partial versions."""

    __slots__ = ("major", "minor", "patch", "prerelease", "raw")

    def __init__(
        self, major: int, minor: int, patch: int, prerelease: tuple[object, ...], raw: str
    ) -> None:
        self.major = major
        self.minor = minor
        self.patch = patch
        self.prerelease = prerelease
        self.raw = raw

    @classmethod
    def parse(cls, value: str) -> SemVer | None:
        match = _SEMVER.match(value.strip())
        if not match:
            return None
        major = int(match.group("major"))
        minor = int(match.group("minor") or 0)
        patch = int(match.group("patch") or 0)
        pre: tuple[object, ...] = ()
        raw_pre = match.group("pre")
        if raw_pre:
            parts: list[object] = []
            for token in raw_pre.split("."):
                parts.append(int(token) if token.isdigit() else token)
            pre = tuple(parts)
        return cls(major, minor, patch, pre, value.strip())

    def _cmp_pre(self, other: SemVer) -> int:
        if not self.prerelease and not other.prerelease:
            return 0
        if not self.prerelease:
            return 1
        if not other.prerelease:
            return -1
        for left, right in zip(self.prerelease, other.prerelease, strict=False):
            if isinstance(left, int) and isinstance(right, int):
                if left != right:
                    return -1 if left < right else 1
            elif isinstance(left, int):
                return -1
            elif isinstance(right, int):
                return 1
            elif left != right:
                return -1 if str(left) < str(right) else 1
        if len(self.prerelease) != len(other.prerelease):
            return -1 if len(self.prerelease) < len(other.prerelease) else 1
        return 0

    def compare(self, other: SemVer) -> int:
        for left, right in (
            (self.major, other.major),
            (self.minor, other.minor),
            (self.patch, other.patch),
        ):
            if left != right:
                return -1 if left < right else 1
        return self._cmp_pre(other)


def compare_versions(ecosystem: Ecosystem, left: str, right: str) -> int | None:
    """Compare two versions. Returns -1/0/1, or ``None`` if not comparable."""

    if ecosystem is Ecosystem.PYPI:
        try:
            pep_left, pep_right = Version(left), Version(right)
        except InvalidVersion:
            return None
        return (pep_left > pep_right) - (pep_left < pep_right)

    sem_left = SemVer.parse(left)
    sem_right = SemVer.parse(right)
    if sem_left is None or sem_right is None:
        return None
    return sem_left.compare(sem_right)


def version_in_range(
    ecosystem: Ecosystem, version: str, range_type: str, events: tuple[tuple[str, str], ...]
) -> bool | None:
    """Return whether ``version`` is affected, per OSV event semantics.

    ``None`` means the range could not be evaluated (e.g. GIT ranges).
    """

    if range_type.upper() == "GIT":
        return None

    affected = False
    for kind, value in events:
        if value == "0" and kind == "introduced":
            affected = True
            continue
        comparison = compare_versions(ecosystem, version, value)
        if comparison is None:
            return None
        if kind == "introduced":
            if comparison >= 0:
                affected = True
        elif kind == "fixed":
            if comparison >= 0:
                affected = False
        elif kind == "last_affected":
            if comparison > 0:
                affected = False
        elif kind == "limit" and comparison >= 0:
            affected = False
    return affected


def version_in_affected(
    ecosystem: Ecosystem, version: str, affected: AffectedPackage
) -> bool | None:
    """Evaluate a version against all ranges and explicit versions of a package."""

    explicit = None
    for candidate in affected.versions:
        comparison = compare_versions(ecosystem, version, candidate)
        if comparison == 0:
            return True
        if comparison is None:
            explicit = None
    decided = False
    evaluated_any = False
    for version_range in affected.ranges:
        result = version_in_range(
            ecosystem, version, version_range.range_type, version_range.events
        )
        if result is None:
            continue
        evaluated_any = True
        if result:
            decided = True
    if evaluated_any:
        return decided
    if explicit is not None:
        return explicit
    if affected.versions:
        return False
    return None


def _fixed_versions(ecosystem: Ecosystem, affected: AffectedPackage) -> list[str]:
    fixed: list[str] = []
    for version_range in affected.ranges:
        for kind, value in version_range.events:
            if kind == "fixed":
                fixed.append(value)
    return fixed


def earliest_fixed_version(
    ecosystem: Ecosystem, current: str, affected: AffectedPackage
) -> str | None:
    """Return the smallest fixed version greater than ``current``, if any."""

    best: str | None = None
    for candidate in _fixed_versions(ecosystem, affected):
        comparison = compare_versions(ecosystem, candidate, current)
        if comparison is None or comparison <= 0:
            continue
        if best is None or (compare_versions(ecosystem, candidate, best) or 0) < 0:
            best = candidate
    return best


def parse_version_range_events(raw: object) -> tuple[tuple[str, str], ...]:
    """Normalize an OSV ``events`` list into ordered ``(kind, value)`` tuples."""

    if not isinstance(raw, list):
        return ()
    events: list[tuple[str, str]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        for kind in ("introduced", "fixed", "last_affected", "limit"):
            if kind in item and isinstance(item[kind], str):
                events.append((kind, item[kind]))
    return tuple(events)


def version_range_from(raw: dict[str, object]) -> VersionRange:
    range_type = str(raw.get("type", "ECOSYSTEM"))
    return VersionRange(range_type=range_type, events=parse_version_range_events(raw.get("events")))
