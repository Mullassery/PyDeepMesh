"""Findings, exposure context, matching status, and remediation."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from pydeepmesh.models.vulnerability import Advisory, VulnerabilitySeverity


class MatchStatus(str, enum.Enum):
    """The outcome of evaluating a package against advisory data.

    ``UNMATCHED`` never means "safe"; it means no advisory matched the queried
    data. ``UNAVAILABLE`` means the advisory source could not be consulted.
    """

    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    UNMATCHED = "unmatched"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


class Priority(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {
            Priority.INFO: 0,
            Priority.LOW: 1,
            Priority.MEDIUM: 2,
            Priority.HIGH: 3,
            Priority.CRITICAL: 4,
        }[self]

    @classmethod
    def from_severity(cls, severity: VulnerabilitySeverity) -> Priority:
        return {
            VulnerabilitySeverity.CRITICAL: cls.CRITICAL,
            VulnerabilitySeverity.HIGH: cls.HIGH,
            VulnerabilitySeverity.MODERATE: cls.MEDIUM,
            VulnerabilitySeverity.LOW: cls.LOW,
            VulnerabilitySeverity.UNKNOWN: cls.INFO,
        }[severity]


@dataclass(frozen=True)
class Remediation:
    """A concrete, evidence-based remediation candidate."""

    current_version: str | None
    fixed_versions: tuple[str, ...]
    recommendation: str

    def to_dict(self) -> dict[str, object]:
        return {
            "current_version": self.current_version,
            "fixed_versions": list(self.fixed_versions),
            "recommendation": self.recommendation,
        }


@dataclass(frozen=True)
class Exposure:
    """How a vulnerable package is reachable in the graph.

    Reachability is a graph property and does not imply runtime exploitability.
    """

    direct: bool
    depth: int | None
    root_projects: tuple[str, ...] = ()
    sample_paths: tuple[tuple[str, ...], ...] = ()
    dependent_count: int = 0
    scopes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "direct": self.direct,
            "depth": self.depth,
            "root_projects": list(self.root_projects),
            "dependent_count": self.dependent_count,
            "scopes": list(self.scopes),
            "sample_paths": [list(p) for p in self.sample_paths],
        }


@dataclass(frozen=True)
class MatchResult:
    """A single package/advisory evaluation outcome, before prioritization."""

    package_id: str
    status: MatchStatus
    advisory: Advisory | None = None
    reason: str = ""
    matched_version: str | None = None

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "package_id": self.package_id,
            "status": self.status.value,
            "reason": self.reason,
        }
        if self.advisory is not None:
            data["advisory"] = self.advisory.to_dict()
        if self.matched_version is not None:
            data["matched_version"] = self.matched_version
        return data


@dataclass(frozen=True)
class Finding:
    """An explainable vulnerability finding for a package in the graph."""

    advisory: Advisory
    package_id: str
    package_name: str
    ecosystem: str
    version: str | None
    status: MatchStatus
    priority: Priority
    priority_explanation: tuple[str, ...]
    exposure: Exposure
    remediation: Remediation | None = None

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "advisory": self.advisory.to_dict(),
            "package_id": self.package_id,
            "package_name": self.package_name,
            "ecosystem": self.ecosystem,
            "version": self.version,
            "status": self.status.value,
            "priority": self.priority.value,
            "priority_explanation": list(self.priority_explanation),
            "exposure": self.exposure.to_dict(),
        }
        if self.remediation is not None:
            data["remediation"] = self.remediation.to_dict()
        return data


@dataclass
class AnalysisResult:
    """The aggregate output of an audit."""

    findings: list[Finding] = field(default_factory=list)
    unavailable_packages: list[tuple[str, str]] = field(default_factory=list)
    unmatched_count: int = 0
    errors: list[tuple[str, str]] = field(default_factory=list)

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (
                -f.priority.rank,
                -f.advisory.severity.rank,
                f.package_name,
                f.advisory.id,
            ),
        )
