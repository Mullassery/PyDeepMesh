"""Provider-neutral advisory interfaces."""

from __future__ import annotations

import abc
from dataclasses import dataclass, field

from pydeepmesh.models.ecosystem import Ecosystem
from pydeepmesh.models.vulnerability import Advisory


@dataclass(frozen=True)
class AdvisoryQuery:
    """A single package@version to evaluate."""

    ecosystem: Ecosystem
    name: str
    version: str

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem.value, self.name.lower(), self.version)

    @property
    def identifier(self) -> str:
        return f"{self.ecosystem.value}:{self.name}@{self.version}"


@dataclass
class ProviderResult:
    """The outcome of querying an advisory provider.

    ``available`` is ``False`` when the provider could not be consulted at all,
    which callers must surface as *unavailable*, never as *clean*.
    """

    provider: str
    advisories: list[Advisory] = field(default_factory=list)
    available: bool = True
    error: str | None = None
    source: str = ""
    queried_packages: int = 0

    @classmethod
    def unavailable(cls, provider: str, error: str, *, source: str = "") -> ProviderResult:
        return cls(provider=provider, advisories=[], available=False, error=error, source=source)


class AdvisoryProvider(abc.ABC):
    """Base class for advisory sources."""

    name: str = "provider"

    @abc.abstractmethod
    def query(self, queries: list[AdvisoryQuery]) -> ProviderResult:
        """Return advisories relevant to ``queries`` (filtered by package)."""
