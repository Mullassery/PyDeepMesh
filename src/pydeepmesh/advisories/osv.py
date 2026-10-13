"""OSV (https://osv.dev) advisory provider."""

from __future__ import annotations

from typing import Any, Protocol

from pydeepmesh.advisories.base import AdvisoryProvider, AdvisoryQuery, ProviderResult
from pydeepmesh.advisories.cache import Cache
from pydeepmesh.advisories.normalize import advisory_from_osv
from pydeepmesh.errors import AdvisoryProviderError
from pydeepmesh.models.vulnerability import Advisory
from pydeepmesh.net import Transport

_BATCH_SIZE = 500


class SupportsRequest(Protocol):
    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        json_body: Any | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any: ...


class OsvProvider(AdvisoryProvider):
    """Query OSV's batch API and fetch full records for matching advisories."""

    name = "osv"
    base_url = "https://api.osv.dev"

    def __init__(
        self, transport: SupportsRequest | None = None, cache: Cache | None = None
    ) -> None:
        self.transport = transport if transport is not None else Transport()
        self.cache = cache

    def query(self, queries: list[AdvisoryQuery]) -> ProviderResult:
        supported = [q for q in queries if q.ecosystem.osv_name is not None]
        if not supported:
            return ProviderResult(provider=self.name, source=self.base_url, queried_packages=0)
        try:
            vuln_ids = self._query_batch(supported)
            advisories = self._fetch_many(vuln_ids)
        except AdvisoryProviderError as exc:
            return ProviderResult.unavailable(self.name, str(exc), source=self.base_url)
        return ProviderResult(
            provider=self.name,
            advisories=advisories,
            available=True,
            source=self.base_url,
            queried_packages=len(supported),
        )

    def _query_batch(self, queries: list[AdvisoryQuery]) -> set[str]:
        ids: set[str] = set()
        for start in range(0, len(queries), _BATCH_SIZE):
            chunk = queries[start : start + _BATCH_SIZE]
            body = {
                "queries": [
                    {
                        "package": {"name": q.name, "ecosystem": q.ecosystem.osv_name},
                        "version": q.version,
                    }
                    for q in chunk
                ]
            }
            response = self.transport.request(
                f"{self.base_url}/v1/querybatch", method="POST", json_body=body
            )
            data = response.json()
            results = data.get("results") if isinstance(data, dict) else None
            if not isinstance(results, list):
                raise AdvisoryProviderError("malformed querybatch response")
            for result in results:
                if not isinstance(result, dict):
                    continue
                vulns = result.get("vulns")
                if not isinstance(vulns, list):
                    continue
                for vuln in vulns:
                    if isinstance(vuln, dict) and isinstance(vuln.get("id"), str):
                        ids.add(vuln["id"])
        return ids

    def _fetch_many(self, ids: set[str]) -> list[Advisory]:
        advisories: list[Advisory] = []
        for vuln_id in sorted(ids):
            raw = self._fetch_one(vuln_id)
            if raw is not None:
                advisories.append(advisory_from_osv(raw, source="osv"))
        return advisories

    def _fetch_one(self, vuln_id: str) -> dict[str, Any] | None:
        if self.cache is not None:
            cached = self.cache.get("osv-vuln", vuln_id)
            if isinstance(cached, dict):
                return cached
        response = self.transport.request(f"{self.base_url}/v1/vulns/{vuln_id}")
        data = response.json()
        if not isinstance(data, dict):
            raise AdvisoryProviderError(f"malformed advisory record for {vuln_id}")
        if self.cache is not None:
            self.cache.set("osv-vuln", vuln_id, data)
        return data
