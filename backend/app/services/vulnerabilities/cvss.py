"""CVSS v3.0 / v3.1 base score computation and severity banding.

The base score formula is the one published in the CVSS v3.1 specification
(section 7.1).  v3.0 uses the same base equations; the only difference is
that v3.1 defines ``Roundup`` with integer arithmetic to avoid floating point
artefacts, which we use for both versions (it yields the intended value for
v3.0 vectors as well).

Only the eight base metrics are used.  Temporal / environmental metrics that
may follow in the vector string are ignored.
"""

from __future__ import annotations

import math
import re

from app.models.enums import Severity

CVSS_V3_PREFIX_RE = re.compile(r"^CVSS:3\.[01]/", re.IGNORECASE)

# Metric weights from the CVSS v3.1 specification, table 8.4.
_ATTACK_VECTOR = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_ATTACK_COMPLEXITY = {"L": 0.77, "H": 0.44}
_PRIVILEGES_REQUIRED_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PRIVILEGES_REQUIRED_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_USER_INTERACTION = {"N": 0.85, "R": 0.62}
_SCOPE = {"U", "C"}
_CIA_IMPACT = {"H": 0.56, "L": 0.22, "N": 0.0}

_BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def roundup(value: float) -> float:
    """Smallest number, specified to one decimal place, that is >= ``value``.

    Implemented with integer arithmetic exactly as in CVSS v3.1 Appendix A so
    that e.g. ``roundup(4.000000000000001)`` gives 4.0 and not 4.1.
    """
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def parse_cvss_v3_vector(vector: str | None) -> dict[str, str] | None:
    """Parse a CVSS v3.x vector into ``{metric: value}``.

    Returns ``None`` when the string is not a CVSS v3.0/3.1 vector or any of
    the eight base metrics is missing or has an unknown value.  Metrics that
    are not base metrics (temporal / environmental) are kept in the returned
    mapping but not validated.
    """
    if not vector or not isinstance(vector, str):
        return None
    text = vector.strip()
    if not CVSS_V3_PREFIX_RE.match(text):
        return None
    body = text.split("/", 1)[1]
    metrics: dict[str, str] = {}
    for part in body.split("/"):
        if not part:
            continue
        if ":" not in part:
            return None
        key, _, value = part.partition(":")
        key, value = key.strip().upper(), value.strip().upper()
        if not key or not value or key in metrics:
            return None
        metrics[key] = value
    if any(metric not in metrics for metric in _BASE_METRICS):
        return None
    valid = (
        metrics["AV"] in _ATTACK_VECTOR
        and metrics["AC"] in _ATTACK_COMPLEXITY
        and metrics["PR"] in _PRIVILEGES_REQUIRED_UNCHANGED
        and metrics["UI"] in _USER_INTERACTION
        and metrics["S"] in _SCOPE
        and metrics["C"] in _CIA_IMPACT
        and metrics["I"] in _CIA_IMPACT
        and metrics["A"] in _CIA_IMPACT
    )
    return metrics if valid else None


def cvss_v3_base_score(vector: str | None) -> float | None:
    """Compute the CVSS v3.0/v3.1 base score (0.0–10.0) for ``vector``.

    Returns ``None`` when the vector cannot be parsed, so callers can fall
    back to "score unavailable" instead of failing.
    """
    metrics = parse_cvss_v3_vector(vector)
    if metrics is None:
        return None

    scope_changed = metrics["S"] == "C"
    privileges = _PRIVILEGES_REQUIRED_CHANGED if scope_changed else _PRIVILEGES_REQUIRED_UNCHANGED

    iss = 1.0 - (
        (1.0 - _CIA_IMPACT[metrics["C"]])
        * (1.0 - _CIA_IMPACT[metrics["I"]])
        * (1.0 - _CIA_IMPACT[metrics["A"]])
    )
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    exploitability = (
        8.22
        * _ATTACK_VECTOR[metrics["AV"]]
        * _ATTACK_COMPLEXITY[metrics["AC"]]
        * privileges[metrics["PR"]]
        * _USER_INTERACTION[metrics["UI"]]
    )

    if impact <= 0:
        return 0.0
    if scope_changed:
        return roundup(min(1.08 * (impact + exploitability), 10.0))
    return roundup(min(impact + exploitability, 10.0))


def severity_from_score(score: float | None) -> Severity:
    """Map a CVSS score to the qualitative severity used across the app.

    ``None`` -> UNKNOWN; 0.0 (CVSS "None") is treated as LOW so that a scored
    vulnerability never disappears from severity-ordered views; 0.1–3.9 LOW,
    4.0–6.9 MEDIUM, 7.0–8.9 HIGH, 9.0–10.0 CRITICAL.  Values outside the
    CVSS range (or NaN) map to UNKNOWN.
    """
    if score is None:
        return Severity.UNKNOWN
    try:
        value = float(score)
    except (TypeError, ValueError):
        return Severity.UNKNOWN
    if math.isnan(value) or value < 0.0 or value > 10.0:
        return Severity.UNKNOWN
    if value >= 9.0:
        return Severity.CRITICAL
    if value >= 7.0:
        return Severity.HIGH
    if value >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW
