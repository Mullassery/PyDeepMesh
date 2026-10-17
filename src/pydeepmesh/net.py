"""Bounded, safe HTTP helper for online advisory providers.

Only HTTPS is permitted. Requests have explicit timeouts, bounded retries with
backoff, and a response size cap. No credentials are ever sent.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from pydeepmesh.errors import AdvisoryProviderError


@dataclass
class HttpResponse:
    status: int
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8", errors="replace"))


class _HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse any redirect whose target is not HTTPS.

    ``urllib`` follows 3xx redirects automatically, so without this an HTTPS
    endpoint could bounce the transport to plain HTTP and silently defeat the
    module's HTTPS-only guarantee. Every redirect hop is re-validated here.
    """

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None:
            target = urlparse(redirected.full_url)
            if target.scheme != "https":
                raise AdvisoryProviderError(
                    f"refusing redirect to non-HTTPS URL "
                    f"'{target.scheme}://{target.netloc}'"
                )
        return redirected


class Transport:
    """A retrying HTTPS transport with a response size cap."""

    def __init__(
        self, *, timeout: float = 15.0, retries: int = 2, max_bytes: int = 32 * 1024 * 1024
    ) -> None:
        self.timeout = timeout
        self.retries = max(0, retries)
        self.max_bytes = max_bytes
        # An opener that enforces HTTPS on every redirect hop.
        self._opener = urllib.request.build_opener(_HttpsOnlyRedirectHandler)

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        json_body: Any | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise AdvisoryProviderError(
                f"refusing non-HTTPS request to '{parsed.scheme}://{parsed.netloc}'"
            )

        payload = None
        request_headers = {"User-Agent": "pydeepmesh", "Accept": "application/json"}
        if json_body is not None:
            payload = json.dumps(json_body).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        if headers:
            request_headers.update(headers)

        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            request = urllib.request.Request(
                url, data=payload, headers=request_headers, method=method
            )
            try:
                with self._opener.open(request, timeout=self.timeout) as response:
                    body = response.read(self.max_bytes + 1)
                    if len(body) > self.max_bytes:
                        raise AdvisoryProviderError("response exceeded size cap")
                    return HttpResponse(status=response.status, body=body)
            except urllib.error.HTTPError as exc:
                if 500 <= exc.code < 600 and attempt < self.retries:
                    last_error = exc
                    time.sleep(0.5 * (2**attempt))
                    continue
                raise AdvisoryProviderError(f"HTTP {exc.code} from {parsed.netloc}") from exc
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_error = exc
                if attempt < self.retries:
                    time.sleep(0.5 * (2**attempt))
                    continue
                raise AdvisoryProviderError(
                    f"network error contacting {parsed.netloc}: {exc}"
                ) from exc
        raise AdvisoryProviderError(f"request failed: {last_error}")
