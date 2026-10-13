"""Shared test helpers (importable as top-level ``helpers``)."""

from __future__ import annotations

from pathlib import Path

from pydeepmesh.advisories.base import AdvisoryProvider, AdvisoryQuery, ProviderResult
from pydeepmesh.config import Config
from pydeepmesh.models.ecosystem import Ecosystem
from pydeepmesh.models.vulnerability import (
    Advisory,
    AffectedPackage,
    VersionRange,
    VulnerabilitySeverity,
)

FIXTURES = Path(__file__).parent / "fixtures"


def scan_fixture(name: str):
    from pydeepmesh.pipeline import scan

    return scan(FIXTURES / name, Config())


class FakeProvider(AdvisoryProvider):
    """A deterministic in-memory provider for tests."""

    name = "fake"

    def __init__(
        self, advisories: list[Advisory], *, available: bool = True, error: str | None = None
    ) -> None:
        self.advisories = advisories
        self.available = available
        self.error = error

    def query(self, queries: list[AdvisoryQuery]) -> ProviderResult:
        if not self.available:
            return ProviderResult.unavailable(self.name, self.error or "unavailable")
        return ProviderResult(
            provider=self.name,
            advisories=list(self.advisories),
            available=True,
            source="fake",
            queried_packages=len(queries),
        )


def make_advisory(
    advisory_id: str,
    *,
    ecosystem: str,
    name: str,
    introduced: str = "0",
    fixed: str | None = "9999.0.0",
    severity: VulnerabilitySeverity = VulnerabilitySeverity.HIGH,
    range_type: str = "ECOSYSTEM",
    last_affected: str | None = None,
) -> Advisory:
    events: list[tuple[str, str]] = []
    if introduced is not None:
        events.append(("introduced", introduced))
    if last_affected is not None:
        events.append(("last_affected", last_affected))
    elif fixed is not None:
        events.append(("fixed", fixed))
    return Advisory(
        id=advisory_id,
        source="fake",
        summary=f"advisory {advisory_id}",
        severity=severity,
        affected=(
            AffectedPackage(
                name=name,
                ecosystem_raw=ecosystem,
                ecosystem=Ecosystem.from_osv_name(ecosystem),
                ranges=(VersionRange(range_type, tuple(events)),),
            ),
        ),
    )
