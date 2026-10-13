"""HTTPS transport: scheme enforcement, retries, size cap."""

from __future__ import annotations

import urllib.error
from typing import Any

import pytest

from pydeepmesh.errors import AdvisoryProviderError
from pydeepmesh.net import Transport


class FakeResponse:
    def __init__(self, body: bytes, status: int = 200) -> None:
        self.body = body
        self.status = status

    def read(self, n: int = -1) -> bytes:
        return self.body[:n] if n >= 0 else self.body

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *exc: Any) -> bool:
        return False


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("pydeepmesh.net.time.sleep", lambda *_: None)


def test_rejects_non_https() -> None:
    with pytest.raises(AdvisoryProviderError):
        Transport().request("http://example.com/data")


def test_successful_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "pydeepmesh.net.urllib.request.urlopen", lambda *a, **k: FakeResponse(b'{"ok": true}')
    )
    response = Transport().request("https://example.com/data")
    assert response.status == 200
    assert response.json() == {"ok": True}


def test_retries_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"count": 0}

    def flaky(request: Any, timeout: float) -> FakeResponse:
        calls["count"] += 1
        if calls["count"] == 1:
            raise urllib.error.HTTPError(request.full_url, 503, "busy", {}, None)
        return FakeResponse(b"{}")

    monkeypatch.setattr("pydeepmesh.net.urllib.request.urlopen", flaky)
    response = Transport(retries=2).request("https://example.com/data")
    assert response.status == 200
    assert calls["count"] == 2


def test_client_error_is_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"count": 0}

    def not_found(request: Any, timeout: float) -> FakeResponse:
        calls["count"] += 1
        raise urllib.error.HTTPError(request.full_url, 404, "missing", {}, None)

    monkeypatch.setattr("pydeepmesh.net.urllib.request.urlopen", not_found)
    with pytest.raises(AdvisoryProviderError):
        Transport(retries=3).request("https://example.com/data")
    assert calls["count"] == 1


def test_response_size_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "pydeepmesh.net.urllib.request.urlopen",
        lambda *a, **k: FakeResponse(b"x" * 1000),
    )
    with pytest.raises(AdvisoryProviderError):
        Transport(max_bytes=10).request("https://example.com/data")


def test_network_error_exhausts_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(request: Any, timeout: float) -> FakeResponse:
        raise urllib.error.URLError("unreachable")

    monkeypatch.setattr("pydeepmesh.net.urllib.request.urlopen", boom)
    with pytest.raises(AdvisoryProviderError):
        Transport(retries=1).request("https://example.com/data")
