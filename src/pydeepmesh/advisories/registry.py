"""Construct advisory providers from configuration."""

from __future__ import annotations

from pydeepmesh.advisories.base import AdvisoryProvider, AdvisoryQuery, ProviderResult
from pydeepmesh.advisories.cache import Cache
from pydeepmesh.advisories.osv import OsvProvider
from pydeepmesh.advisories.snapshot import SnapshotProvider
from pydeepmesh.config import Config
from pydeepmesh.net import Transport


class NullProvider(AdvisoryProvider):
    """A provider that is explicitly unavailable.

    Used when neither online access nor a snapshot is configured, so results are
    reported as *unavailable* rather than falsely clean.
    """

    name = "none"

    def __init__(self, reason: str) -> None:
        self.reason = reason

    def query(self, queries: list[AdvisoryQuery]) -> ProviderResult:
        return ProviderResult.unavailable(self.name, self.reason)


def build_provider(config: Config) -> AdvisoryProvider:
    if config.online:
        cache = Cache(config.cache_dir, ttl_seconds=config.cache_ttl_seconds)
        transport = Transport(
            timeout=config.network_timeout,
            retries=config.network_retries,
            max_bytes=config.network_max_bytes,
        )
        return OsvProvider(transport=transport, cache=cache)
    if config.advisory_dir is not None:
        return SnapshotProvider(config.advisory_dir)
    return NullProvider("no advisory source configured; pass --online or --advisory-dir <dir>")
