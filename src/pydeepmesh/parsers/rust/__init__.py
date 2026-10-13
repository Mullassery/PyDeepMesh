"""Rust (crates.io) parsers."""

from __future__ import annotations

from pydeepmesh.parsers.rust.cargo_lock import CargoLockParser
from pydeepmesh.parsers.rust.cargo_manifest import CargoManifestParser

__all__ = ["CargoLockParser", "CargoManifestParser"]
