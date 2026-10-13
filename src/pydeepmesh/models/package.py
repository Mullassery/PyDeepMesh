"""Package identity and normalization."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import quote

from pydeepmesh.models.ecosystem import Ecosystem

_PYPI_SEPARATORS = re.compile(r"[-_.]+")


def normalize_name(ecosystem: Ecosystem, name: str) -> str:
    """Normalize a package name for equality comparisons within an ecosystem.

    Original names are always preserved on nodes; normalization is only used to
    build stable identifiers and to compare identities.
    """

    trimmed = name.strip()
    if ecosystem is Ecosystem.PYPI:
        return _PYPI_SEPARATORS.sub("-", trimmed).lower()
    if ecosystem is Ecosystem.NPM:
        return trimmed.lower()
    if ecosystem is Ecosystem.CRATES:
        return trimmed.lower()
    return trimmed


def package_url(ecosystem: Ecosystem, name: str, version: str | None) -> str | None:
    """Build a Package URL (purl) when the ecosystem supports one."""

    if ecosystem is Ecosystem.GENERIC:
        return None
    encoded = _encode_purl_name(ecosystem, name)
    base = f"pkg:{ecosystem.purl_type}/{encoded}"
    if version:
        return f"{base}@{quote(str(version), safe='.+~-')}"
    return base


def _encode_purl_name(ecosystem: Ecosystem, name: str) -> str:
    if ecosystem is Ecosystem.NPM and "/" in name:
        scope, _, bare = name.partition("/")
        return f"{quote(scope, safe='')}/{quote(bare, safe='')}"
    return quote(name, safe=".-_~")


@dataclass(frozen=True, order=True)
class PackageKey:
    """The identity of a package node: ecosystem + normalized name + version."""

    ecosystem: Ecosystem
    name: str
    version: str | None = None

    @classmethod
    def create(cls, ecosystem: Ecosystem, name: str, version: str | None = None) -> PackageKey:
        return cls(
            ecosystem=ecosystem,
            name=normalize_name(ecosystem, name),
            version=version or None,
        )

    @property
    def purl(self) -> str | None:
        return package_url(self.ecosystem, self.name, self.version)

    def stable_id(self) -> str:
        version = self.version or "*"
        return f"{self.ecosystem.value}:{self.name}@{version}"
