"""Compatibility shims for supported Python versions."""

from __future__ import annotations

import sys

if sys.version_info >= (3, 11):
    import tomllib as tomllib
else:  # pragma: no cover - exercised only on older interpreters
    import tomli as tomllib

__all__ = ["tomllib"]
