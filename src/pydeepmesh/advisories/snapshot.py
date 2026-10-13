"""Offline advisory provider backed by a local OSV snapshot directory."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydeepmesh.advisories.base import AdvisoryProvider, AdvisoryQuery, ProviderResult
from pydeepmesh.advisories.normalize import advisory_from_osv
from pydeepmesh.models.package import normalize_name
from pydeepmesh.models.vulnerability import Advisory


class SnapshotProvider(AdvisoryProvider):
    """Load OSV-format JSON records from a directory and answer queries.

    Each ``*.json`` file may contain a single advisory object or a list of
    advisory objects. The snapshot is indexed by ecosystem + package name.
    """

    name = "snapshot"

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self._advisories: list[Advisory] | None = None
        self._index: dict[tuple[str, str], list[Advisory]] | None = None
        self.load_errors: list[str] = []

    def _load(self) -> None:
        if self._advisories is not None:
            return
        advisories: list[Advisory] = []
        if self.directory.exists():
            for path in sorted(self.directory.rglob("*.json")):
                advisories.extend(self._load_file(path))
        self._advisories = advisories
        index: dict[tuple[str, str], list[Advisory]] = {}
        for advisory in advisories:
            for affected in advisory.affected:
                ecosystem = affected.ecosystem
                if ecosystem is None:
                    continue
                key = (ecosystem.value, normalize_name(ecosystem, affected.name))
                index.setdefault(key, []).append(advisory)
        self._index = index

    def _load_file(self, path: Path) -> list[Advisory]:
        try:
            data: Any = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            self.load_errors.append(f"{path.name}: {exc}")
            return []
        records = data if isinstance(data, list) else [data]
        result: list[Advisory] = []
        for record in records:
            if isinstance(record, dict) and "id" in record:
                result.append(advisory_from_osv(record, source=f"snapshot:{self.directory.name}"))
        return result

    def query(self, queries: list[AdvisoryQuery]) -> ProviderResult:
        if not self.directory.exists():
            return ProviderResult.unavailable(
                self.name,
                f"snapshot directory not found: {self.directory}",
                source=str(self.directory),
            )
        self._load()
        assert self._index is not None
        found: dict[str, Advisory] = {}
        for query in queries:
            key = (query.ecosystem.value, normalize_name(query.ecosystem, query.name))
            for advisory in self._index.get(key, []):
                found[advisory.id] = advisory
        advisories = [found[key] for key in sorted(found)]
        return ProviderResult(
            provider=self.name,
            advisories=advisories,
            available=True,
            source=f"snapshot:{self.directory}",
            queried_packages=len(queries),
        )
