"""OSV provider behavior tested with a stub transport (no network)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydeepmesh.advisories.base import AdvisoryQuery
from pydeepmesh.advisories.cache import Cache
from pydeepmesh.advisories.osv import OsvProvider
from pydeepmesh.errors import AdvisoryProviderError
from pydeepmesh.models.ecosystem import Ecosystem

EXPRESS_ADVISORY: dict[str, Any] = {
    "id": "OSV-2024-0001",
    "summary": "express issue",
    "database_specific": {"severity": "MODERATE"},
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "express"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.19.0"}]}],
        }
    ],
}


class _Response:
    def __init__(self, payload: Any) -> None:
        self.payload = payload

    def json(self) -> Any:
        return self.payload


class StubTransport:
    def __init__(self, *, batch: Any, vulns: dict[str, Any], fail: str | None = None) -> None:
        self.batch = batch
        self.vulns = vulns
        self.fail = fail
        self.urls: list[str] = []

    def request(
        self, url: str, *, method: str = "GET", json_body: Any = None, headers=None
    ) -> _Response:
        if self.fail is not None:
            raise AdvisoryProviderError(self.fail)
        self.urls.append(url)
        if url.endswith("/querybatch"):
            return _Response(self.batch)
        return _Response(self.vulns[url.rsplit("/", 1)[-1]])


def _query() -> list[AdvisoryQuery]:
    return [AdvisoryQuery(ecosystem=Ecosystem.NPM, name="express", version="4.18.2")]


def test_osv_query_returns_normalized_advisories() -> None:
    transport = StubTransport(
        batch={"results": [{"vulns": [{"id": "OSV-2024-0001"}]}]},
        vulns={"OSV-2024-0001": EXPRESS_ADVISORY},
    )
    result = OsvProvider(transport=transport).query(_query())
    assert result.available is True
    assert [a.id for a in result.advisories] == ["OSV-2024-0001"]
    assert result.advisories[0].severity.value == "moderate"


def test_osv_passes_version_in_batch() -> None:
    captured: dict[str, Any] = {}

    class Capturing(StubTransport):
        def request(self, url, *, method="GET", json_body=None, headers=None):
            if json_body is not None:
                captured["body"] = json_body
            return super().request(url, method=method, json_body=json_body, headers=headers)

    transport = Capturing(
        batch={"results": [{"vulns": [{"id": "OSV-2024-0001"}]}]},
        vulns={"OSV-2024-0001": EXPRESS_ADVISORY},
    )
    OsvProvider(transport=transport).query(_query())
    assert captured["body"]["queries"][0]["version"] == "4.18.2"


def test_osv_uses_cache_for_records(tmp_path: Path) -> None:
    cache = Cache(tmp_path, ttl_seconds=-1)
    transport = StubTransport(
        batch={"results": [{"vulns": [{"id": "OSV-2024-0001"}]}]},
        vulns={"OSV-2024-0001": EXPRESS_ADVISORY},
    )
    provider = OsvProvider(transport=transport, cache=cache)
    provider.query(_query())
    fetches = [url for url in transport.urls if "/vulns/" in url]
    assert len(fetches) == 1

    second_transport = StubTransport(batch={}, vulns={})
    provider2 = OsvProvider(transport=second_transport, cache=cache)
    provider2._fetch_one("OSV-2024-0001")
    assert not second_transport.urls


def test_osv_unavailable_on_transport_error() -> None:
    transport = StubTransport(batch={}, vulns={}, fail="network down")
    result = OsvProvider(transport=transport).query(_query())
    assert result.available is False
    assert "network down" in (result.error or "")


def test_osv_malformed_batch_is_unavailable() -> None:
    transport = StubTransport(batch={"unexpected": True}, vulns={})
    result = OsvProvider(transport=transport).query(_query())
    assert result.available is False


def test_osv_no_supported_queries() -> None:
    query = [AdvisoryQuery(ecosystem=Ecosystem.GENERIC, name="thing", version="1.0.0")]
    result = OsvProvider(transport=StubTransport(batch={}, vulns={})).query(query)
    assert result.queried_packages == 0
    assert result.advisories == []


def test_osv_malformed_record_raises() -> None:
    transport = StubTransport(
        batch={"results": [{"vulns": [{"id": "OSV-2024-0001"}]}]},
        vulns={"OSV-2024-0001": "not-a-dict"},
    )
    result = OsvProvider(transport=transport).query(_query())
    assert result.available is False
