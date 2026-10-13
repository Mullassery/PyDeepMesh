"""SARIF 2.1.0 serialization of findings."""

from __future__ import annotations

import json
from typing import Any

from pydeepmesh.models.finding import AnalysisResult, Finding, Priority
from pydeepmesh.pipeline import ScanResult
from pydeepmesh.version import __version__

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVELS = {
    Priority.CRITICAL: "error",
    Priority.HIGH: "error",
    Priority.MEDIUM: "warning",
    Priority.LOW: "note",
    Priority.INFO: "note",
}


def build_sarif(scan: ScanResult, analysis: AnalysisResult) -> dict[str, Any]:
    rules = _build_rules(analysis)
    rule_ids = {rule["id"] for rule in rules}
    results = [_result(scan, finding) for finding in analysis.sorted_findings()]
    results = [r for r in results if r["ruleId"] in rule_ids]
    results.sort(key=lambda r: (r["ruleId"], r["message"]["text"]))
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pydeepmesh",
                        "version": __version__,
                        "informationUri": "https://github.com/Mullassery/PyDeepMesh",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [{"executionSuccessful": True}],
            }
        ],
    }


def _build_rules(analysis: AnalysisResult) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    for finding in analysis.sorted_findings():
        advisory = finding.advisory
        if advisory.id in seen:
            continue
        rule: dict[str, Any] = {
            "id": advisory.id,
            "name": advisory.id,
            "shortDescription": {"text": advisory.summary or f"Advisory {advisory.id}"},
            "properties": {
                "security-severity": str(advisory.cvss_score)
                if advisory.cvss_score is not None
                else "",
                "severity": advisory.severity.value,
                "source": advisory.source,
            },
        }
        if advisory.references:
            rule["helpUri"] = advisory.references[0]
        if advisory.aliases:
            rule["properties"]["aliases"] = ", ".join(advisory.aliases)
        seen[advisory.id] = rule
    return [seen[key] for key in sorted(seen)]


def _result(scan: ScanResult, finding: Finding) -> dict[str, Any]:
    node = scan.graph.get(finding.package_id)
    location = _location(scan, node.origins if node else ())
    message = (
        f"{finding.package_name} {finding.version or '(unresolved)'} is affected by "
        f"{finding.advisory.id} ({finding.advisory.severity.value}); priority {finding.priority.value}"
    )
    if finding.remediation is not None:
        message += f"; fix: {finding.remediation.recommendation}"
    result: dict[str, Any] = {
        "ruleId": finding.advisory.id,
        "level": _LEVELS.get(finding.priority, "warning"),
        "message": {"text": message},
        "properties": {
            "priority": finding.priority.value,
            "status": finding.status.value,
            "direct": finding.exposure.direct,
            "depth": finding.exposure.depth,
            "ecosystem": finding.ecosystem,
            "package": finding.package_name,
            "version": finding.version,
            "priority_explanation": list(finding.priority_explanation),
        },
    }
    if location:
        result["locations"] = [location]
    return result


def _location(scan: ScanResult, origins: tuple[Any, ...]) -> dict[str, Any] | None:
    if not origins:
        return None
    origin = sorted(origins)[0]
    physical: dict[str, Any] = {
        "artifactLocation": {"uri": origin.file},
    }
    if origin.line is not None:
        physical["region"] = {"startLine": origin.line}
    return {"physicalLocation": physical}


def render_sarif(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=False) + "\n"
