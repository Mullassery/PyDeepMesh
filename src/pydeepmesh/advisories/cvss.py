"""Compact CVSS v3.x base-score calculator.

Only the base score is computed; this keeps PyDeepMesh free of an extra
dependency while allowing numeric severity from a CVSS vector. Vectors that
cannot be parsed return ``None`` rather than a fabricated score.
"""

from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_IMPACT = {"H": 0.56, "L": 0.22, "N": 0.0}


def _parse_vector(vector: str) -> dict[str, str] | None:
    parts = vector.strip().split("/")
    if not parts or not parts[0].upper().startswith("CVSS:3"):
        return None
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if ":" not in part:
            return None
        key, _, value = part.partition(":")
        metrics[key.upper()] = value.upper()
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if not required.issubset(metrics):
        return None
    return metrics


def _roundup(value: float) -> float:
    integer = int(value)
    if abs(value - integer) < 1e-9:
        return float(integer)
    return (math.floor(value * 10) + 1) / 10.0


def base_score(vector: str) -> float | None:
    """Return the CVSS v3 base score, or ``None`` if the vector is unusable."""

    metrics = _parse_vector(vector)
    if metrics is None:
        return None
    try:
        scope_changed = metrics["S"] == "C"
        pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        pr = pr_table[metrics["PR"]]
        ui = _UI[metrics["UI"]]
        confidentiality = _IMPACT[metrics["C"]]
        integrity = _IMPACT[metrics["I"]]
        availability = _IMPACT[metrics["A"]]
    except KeyError:
        return None

    iss = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability))
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    score = 1.08 * (impact + exploitability) if scope_changed else impact + exploitability
    return _roundup(min(score, 10.0))
