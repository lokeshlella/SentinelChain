"""Deterministic risk helpers shared by the vulnerability, analysis and report stages.

Two kinds of level live side by side:

* **provisional risk** — derived mechanically from the vulnerability's severity label.
  It is *not* an AI judgement; it exists so a finding has a usable ``risk_level`` before
  (or without) the LLM risk agent, and is documented as such wherever it is shown.
* **AI risk** — ``Finding.risk_level`` once the RiskEvaluationAgent has run; when set it
  takes precedence over the provisional value in every aggregate.
"""

from __future__ import annotations

from collections.abc import Iterable

from app.models.enums import RiskLevel, Severity
from app.models.finding import Finding

_RISK_RANK: dict[RiskLevel, int] = {
    RiskLevel.CRITICAL: 5,
    RiskLevel.HIGH: 4,
    RiskLevel.MEDIUM: 3,
    RiskLevel.LOW: 2,
    RiskLevel.UNKNOWN: 1,
    RiskLevel.NONE: 0,
}

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.UNKNOWN: 0,
}

#: Labels other sources use for the same bands (GHSA "MODERATE", CVSS "NONE").
_SEVERITY_ALIASES: dict[str, Severity] = {
    "MODERATE": Severity.MEDIUM,
    "IMPORTANT": Severity.HIGH,
    "NONE": Severity.LOW,  # a CVSS score of 0 is reported as LOW (see vulnerabilities/cvss.py)
    "INFORMATIONAL": Severity.LOW,
    "INFO": Severity.LOW,
}


def normalise_severity(severity: str | Severity | None) -> Severity:
    """Coerce any severity label (case-insensitive, with common aliases) to :class:`Severity`."""
    if severity is None:
        return Severity.UNKNOWN
    text = str(severity).strip().upper()
    if not text:
        return Severity.UNKNOWN
    try:
        return Severity(text)
    except ValueError:
        return _SEVERITY_ALIASES.get(text, Severity.UNKNOWN)


def normalise_risk_level(level: str | RiskLevel | None) -> RiskLevel:
    """Coerce a stored risk string to :class:`RiskLevel`; unrecognised values are UNKNOWN."""
    if level is None:
        return RiskLevel.UNKNOWN
    text = str(level).strip().upper()
    if not text:
        return RiskLevel.UNKNOWN
    try:
        return RiskLevel(text)
    except ValueError:
        return RiskLevel.UNKNOWN


def severity_rank(severity: str | Severity | None) -> int:
    """CRITICAL 4, HIGH 3, MEDIUM 2, LOW 1, UNKNOWN/None/other 0."""
    return _SEVERITY_RANK[normalise_severity(severity)]


def risk_rank(level: str | RiskLevel | None) -> int:
    """CRITICAL 5, HIGH 4, MEDIUM 3, LOW 2, UNKNOWN 1, NONE 0 (None/other count as UNKNOWN)."""
    return _RISK_RANK[normalise_risk_level(level)]


def provisional_risk_from_severity(severity: str | Severity | None) -> RiskLevel:
    """Map a vulnerability severity to a provisional (non-AI) risk level.

    CRITICAL/HIGH/MEDIUM/LOW map one-to-one; missing or unrecognised severities are
    UNKNOWN — never "no risk", because absence of a label is not evidence of safety.
    """
    sev = normalise_severity(severity)
    if sev is Severity.UNKNOWN:
        return RiskLevel.UNKNOWN
    return RiskLevel(sev.value)


def floor_risk_level(judged: str | RiskLevel | None, provisional: str | RiskLevel | None) -> RiskLevel:
    """The risk level to store for a finding once the AI has judged it (audit V2-01).

    The agent may *raise* the risk above the severity-derived level (application
    context can make a MEDIUM advisory HIGH) but never lower it: V1 has no
    reachability evidence — the usage scan finds direct imports only, transitive
    and dynamic use are not analysed — so "no source file references the package"
    can never prove that the vulnerable code does not run. A judged UNKNOWN keeps
    the provisional level.
    """
    judged_level = normalise_risk_level(judged)
    provisional_level = normalise_risk_level(provisional)
    if judged_level is RiskLevel.UNKNOWN:
        return provisional_level
    return judged_level if risk_rank(judged_level) >= risk_rank(provisional_level) else provisional_level


def effective_risk_level(finding: Finding) -> RiskLevel:
    """The risk a finding counts as: the stored level, never below the severity-derived one.

    The floor is applied on read as well as on write so that rows stored before the
    floor existed (audit V2-01) cannot lower an analysis' overall risk either.
    """
    vulnerability = getattr(finding, "vulnerability", None)
    provisional = provisional_risk_from_severity(getattr(vulnerability, "severity", None))
    if finding.risk_level:
        return floor_risk_level(finding.risk_level, provisional)
    return provisional


def aggregate_overall_risk(findings: Iterable[Finding]) -> RiskLevel:
    """Overall risk of an analysis: the highest effective risk across its findings.

    * no findings → NONE (nothing vulnerable was observed)
    * only UNKNOWN levels → UNKNOWN (something is vulnerable but unrated; never NONE)
    * otherwise the maximum by :func:`risk_rank`
    """
    best: RiskLevel | None = None
    for finding in findings:
        level = effective_risk_level(finding)
        if best is None or risk_rank(level) > risk_rank(best):
            best = level
    return best if best is not None else RiskLevel.NONE


def _priority_key(finding: Finding) -> tuple:
    vulnerability = getattr(finding, "vulnerability", None)
    severity = getattr(vulnerability, "severity", None)
    cvss = getattr(vulnerability, "cvss_score", None)
    identifier = getattr(vulnerability, "identifier", None) or ""
    return (
        -severity_rank(severity),
        -(cvss if cvss is not None else -1.0),  # unknown scores sort after any real score
        identifier,
        finding.finding_id or 0,
    )


def sort_findings_by_priority(findings: Iterable[Finding]) -> list[Finding]:
    """Findings ordered severity desc, CVSS score desc (unknown last), identifier asc."""
    return sorted(findings, key=_priority_key)
