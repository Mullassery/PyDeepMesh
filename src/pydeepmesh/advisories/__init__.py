"""Advisory providers, caching, and ecosystem-aware version matching."""

from __future__ import annotations

from pydeepmesh.advisories.base import AdvisoryProvider, AdvisoryQuery, ProviderResult
from pydeepmesh.advisories.matcher import match_graph
from pydeepmesh.advisories.versioning import (
    compare_versions,
    earliest_fixed_version,
    version_in_affected,
)

__all__ = [
    "AdvisoryProvider",
    "AdvisoryQuery",
    "ProviderResult",
    "compare_versions",
    "earliest_fixed_version",
    "match_graph",
    "version_in_affected",
]
