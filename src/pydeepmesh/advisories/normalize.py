"""Normalize OSV-format records into PyDeepMesh :class:`Advisory` values."""

from __future__ import annotations

from typing import Any

from pydeepmesh.advisories.cvss import base_score
from pydeepmesh.advisories.versioning import version_range_from
from pydeepmesh.models.ecosystem import Ecosystem
from pydeepmesh.models.vulnerability import (
    Advisory,
    AffectedPackage,
    VulnerabilitySeverity,
)


def advisory_from_osv(data: dict[str, Any], *, source: str) -> Advisory:
    """Convert a single OSV record (dict) into a normalized advisory."""

    affected: list[AffectedPackage] = []
    raw_affected = data.get("affected")
    if isinstance(raw_affected, list):
        for entry in raw_affected:
            if not isinstance(entry, dict):
                continue
            affected.append(_affected_from_osv(entry))

    cvss_vector: str | None = None
    cvss_score: float | None = None
    label_severity = VulnerabilitySeverity.UNKNOWN
    raw_severity = data.get("severity")
    if isinstance(raw_severity, list):
        for item in raw_severity:
            if not isinstance(item, dict):
                continue
            score = item.get("score")
            if isinstance(score, str) and score.upper().startswith("CVSS:3"):
                cvss_vector = score
                cvss_score = base_score(score)

    database_specific = data.get("database_specific")
    if isinstance(database_specific, dict):
        label = database_specific.get("severity")
        if isinstance(label, str):
            label_severity = VulnerabilitySeverity.from_label(label)

    if cvss_score is not None:
        severity = VulnerabilitySeverity.from_cvss(cvss_score)
    elif label_severity is not VulnerabilitySeverity.UNKNOWN:
        severity = label_severity
    else:
        severity = VulnerabilitySeverity.UNKNOWN

    references = _references(data.get("references"))

    return Advisory(
        id=str(data.get("id", "")),
        source=source,
        aliases=tuple(sorted(str(a) for a in data.get("aliases", []) if isinstance(a, str))),
        summary=str(data.get("summary", "")),
        details=str(data.get("details", "")),
        severity=severity,
        cvss_vector=cvss_vector,
        cvss_score=cvss_score,
        affected=tuple(affected),
        references=references,
        published=_as_str(data.get("published")),
        modified=_as_str(data.get("modified")),
        withdrawn=_as_str(data.get("withdrawn")),
    )


def _affected_from_osv(entry: dict[str, Any]) -> AffectedPackage:
    raw_package = entry.get("package")
    package: dict[str, Any] = raw_package if isinstance(raw_package, dict) else {}
    name = str(package.get("name", ""))
    ecosystem_raw = str(package.get("ecosystem", ""))
    purl = _as_str(package.get("purl"))
    ranges = []
    raw_ranges = entry.get("ranges")
    if isinstance(raw_ranges, list):
        for item in raw_ranges:
            if isinstance(item, dict):
                ranges.append(version_range_from(item))
    versions = tuple(str(v) for v in entry.get("versions", []) if isinstance(v, str))
    return AffectedPackage(
        name=name,
        ecosystem_raw=ecosystem_raw,
        ecosystem=Ecosystem.from_osv_name(ecosystem_raw),
        ranges=tuple(ranges),
        versions=versions,
        purl=purl,
    )


def _references(raw: Any) -> tuple[str, ...]:
    if not isinstance(raw, list):
        return ()
    urls: set[str] = set()
    for item in raw:
        if isinstance(item, dict) and isinstance(item.get("url"), str):
            urls.add(item["url"])
        elif isinstance(item, str):
            urls.add(item)
    return tuple(sorted(urls))


def _as_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None
