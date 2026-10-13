"""Supported ecosystems and their identifier mappings."""

from __future__ import annotations

import enum


class Ecosystem(str, enum.Enum):
    """A dependency ecosystem.

    Values are PyDeepMesh-canonical lowercase identifiers. :meth:`osv_name` and
    :meth:`purl_type` translate to the external vocabularies PyDeepMesh speaks.
    """

    PYPI = "pypi"
    CRATES = "crates.io"
    NPM = "npm"
    DOCKER = "docker"
    GENERIC = "generic"

    @property
    def osv_name(self) -> str | None:
        """Return the OSV ecosystem name, or ``None`` if not applicable."""

        return {
            Ecosystem.PYPI: "PyPI",
            Ecosystem.CRATES: "crates.io",
            Ecosystem.NPM: "npm",
            Ecosystem.DOCKER: "Docker",
            Ecosystem.GENERIC: None,
        }[self]

    @property
    def purl_type(self) -> str:
        """Return the Package URL type for this ecosystem."""

        return {
            Ecosystem.PYPI: "pypi",
            Ecosystem.CRATES: "cargo",
            Ecosystem.NPM: "npm",
            Ecosystem.DOCKER: "docker",
            Ecosystem.GENERIC: "generic",
        }[self]

    @property
    def display_name(self) -> str:
        return {
            Ecosystem.PYPI: "Python (PyPI)",
            Ecosystem.CRATES: "Rust (crates.io)",
            Ecosystem.NPM: "Node.js (npm)",
            Ecosystem.DOCKER: "Container (Docker)",
            Ecosystem.GENERIC: "Generic",
        }[self]

    @classmethod
    def from_osv_name(cls, name: str) -> Ecosystem | None:
        """Map an OSV ecosystem name to a PyDeepMesh ecosystem (best effort)."""

        lowered = name.strip().lower()
        mapping = {
            "pypi": cls.PYPI,
            "crates.io": cls.CRATES,
            "npm": cls.NPM,
            "docker": cls.DOCKER,
        }
        return mapping.get(lowered)
