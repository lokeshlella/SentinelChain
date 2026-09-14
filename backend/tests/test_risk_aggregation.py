"""Unit tests for app.services.analysis.risk using ORM rows in the SQLite ``db`` fixture."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Analysis, Dependency, Finding, Repository, Vulnerability
from app.models.enums import RiskLevel, Severity
from app.services.analysis.risk import (
    aggregate_overall_risk,
    effective_risk_level,
    normalise_risk_level,
    normalise_severity,
    provisional_risk_from_severity,
    risk_rank,
    severity_rank,
    sort_findings_by_priority,
)

# --------------------------------------------------------------------------- fixtures


class RepoBuilder:
    """Creates Repository -> Analysis -> Dependency -> Vulnerability -> Finding rows."""

    def __init__(self, db: Session):
        self.db = db
        self.repository = Repository(name="demo", source_url="/tmp/demo", source_type="local", language="Python")
        db.add(self.repository)
        db.flush()
        self.analysis = Analysis(repository_id=self.repository.repository_id, status="RUNNING")
        db.add(self.analysis)
        db.flush()
        self._counter = 0

    def dependency(self, name: str, version: str = "1.0.0") -> Dependency:
        dep = Dependency(
            repository_id=self.repository.repository_id,
            analysis_id=self.analysis.analysis_id,
            package_name=name,
            version=version,
            ecosystem="PyPI",
            source_file="requirements.txt",
            vulnerability_status="VULNERABLE",
        )
        self.db.add(dep)
        self.db.flush()
        return dep

    def vulnerability(self, identifier: str, severity: str | None, cvss: float | None = None) -> Vulnerability:
        vuln = Vulnerability(identifier=identifier, source="osv", severity=severity or "UNKNOWN", cvss_score=cvss)
        self.db.add(vuln)
        self.db.flush()
        return vuln

    def finding(
        self,
        severity: str | None,
        *,
        risk_level: str | None = None,
        cvss: float | None = None,
        identifier: str | None = None,
        dependency: Dependency | None = None,
    ) -> Finding:
        self._counter += 1
        dep = dependency or self.dependency(f"pkg{self._counter}")
        vuln = self.vulnerability(identifier or f"GHSA-test-{self._counter:04d}", severity, cvss)
        finding = Finding(
            analysis_id=self.analysis.analysis_id,
            dependency_id=dep.dependency_id,
            vulnerability_id=vuln.vulnerability_id,
            risk_level=risk_level,
            ai_status="PENDING",
        )
        self.db.add(finding)
        self.db.flush()
        return finding

    def stored_findings(self) -> list[Finding]:
        """Reload from the database so relationships are exercised, not in-memory objects."""
        self.db.expire_all()
        return list(self.db.scalars(select(Finding).where(Finding.analysis_id == self.analysis.analysis_id)).all())


@pytest.fixture
def builder(db: Session) -> RepoBuilder:
    return RepoBuilder(db)


# --------------------------------------------------------------------------- pure helpers


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        ("CRITICAL", RiskLevel.CRITICAL),
        ("HIGH", RiskLevel.HIGH),
        ("MEDIUM", RiskLevel.MEDIUM),
        ("LOW", RiskLevel.LOW),
        ("UNKNOWN", RiskLevel.UNKNOWN),
        (None, RiskLevel.UNKNOWN),
        ("", RiskLevel.UNKNOWN),
        ("   ", RiskLevel.UNKNOWN),
        ("high", RiskLevel.HIGH),  # case-insensitive
        (" Critical ", RiskLevel.CRITICAL),
        ("MODERATE", RiskLevel.MEDIUM),  # GHSA label
        ("NONE", RiskLevel.LOW),  # CVSS 0 band is reported as LOW, never "no risk"
        (Severity.HIGH, RiskLevel.HIGH),
        ("garbage", RiskLevel.UNKNOWN),
    ],
)
def test_provisional_risk_from_severity(severity, expected):
    assert provisional_risk_from_severity(severity) is expected


def test_provisional_risk_never_returns_none_level():
    for severity in [None, "", "UNKNOWN", "bogus", "NONE", "LOW", "CRITICAL"]:
        assert provisional_risk_from_severity(severity) is not RiskLevel.NONE


def test_risk_rank_is_a_strict_ordering():
    assert risk_rank(RiskLevel.CRITICAL) == 5
    assert risk_rank(RiskLevel.HIGH) == 4
    assert risk_rank(RiskLevel.MEDIUM) == 3
    assert risk_rank(RiskLevel.LOW) == 2
    assert risk_rank(RiskLevel.UNKNOWN) == 1
    assert risk_rank(RiskLevel.NONE) == 0
    assert risk_rank("critical") == 5  # stored strings are accepted
    assert risk_rank(None) == 1
    assert risk_rank("weird") == 1
    ranks = [risk_rank(level) for level in RiskLevel]
    assert len(set(ranks)) == len(RiskLevel)


def test_severity_rank():
    assert [severity_rank(s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")] == [4, 3, 2, 1, 0]
    assert severity_rank(None) == 0
    assert severity_rank("moderate") == 2
    assert severity_rank("nonsense") == 0


def test_normalisers():
    assert normalise_severity("moderate") is Severity.MEDIUM
    assert normalise_severity(None) is Severity.UNKNOWN
    assert normalise_risk_level(" low ") is RiskLevel.LOW
    assert normalise_risk_level("none") is RiskLevel.NONE
    assert normalise_risk_level(None) is RiskLevel.UNKNOWN
    assert normalise_risk_level("not-a-level") is RiskLevel.UNKNOWN


# --------------------------------------------------------------------------- aggregation with ORM rows


def test_aggregate_no_findings_is_none():
    assert aggregate_overall_risk([]) is RiskLevel.NONE
    assert aggregate_overall_risk(iter(())) is RiskLevel.NONE


def test_aggregate_only_unknown_severities_is_unknown(builder: RepoBuilder):
    builder.finding("UNKNOWN")
    builder.finding(None)  # stored as the column default "UNKNOWN"

    assert aggregate_overall_risk(builder.stored_findings()) is RiskLevel.UNKNOWN


def test_aggregate_uses_provisional_severity_when_no_ai_risk(builder: RepoBuilder):
    builder.finding("LOW")
    builder.finding("MEDIUM")
    builder.finding("UNKNOWN")

    assert aggregate_overall_risk(builder.stored_findings()) is RiskLevel.MEDIUM


def test_aggregate_takes_maximum_across_findings(builder: RepoBuilder):
    builder.finding("LOW")
    builder.finding("CRITICAL")
    builder.finding("HIGH")

    assert aggregate_overall_risk(builder.stored_findings()) is RiskLevel.CRITICAL


def test_aggregate_prefers_ai_risk_over_provisional(builder: RepoBuilder):
    # AI raised the level: LOW severity but the risk agent judged CRITICAL.
    builder.finding("LOW", risk_level="CRITICAL")
    builder.finding("MEDIUM")

    assert aggregate_overall_risk(builder.stored_findings()) is RiskLevel.CRITICAL


def test_aggregate_ai_risk_can_lower_a_finding(builder: RepoBuilder):
    # AI lowered the level: CRITICAL severity, but usage evidence made the agent say LOW.
    builder.finding("CRITICAL", risk_level="LOW")

    assert aggregate_overall_risk(builder.stored_findings()) is RiskLevel.LOW


def test_aggregate_unknown_beats_none(builder: RepoBuilder):
    builder.finding("HIGH", risk_level="NONE")
    builder.finding("UNKNOWN")

    assert aggregate_overall_risk(builder.stored_findings()) is RiskLevel.UNKNOWN


def test_aggregate_all_none_stays_none(builder: RepoBuilder):
    builder.finding("HIGH", risk_level="NONE")
    builder.finding("LOW", risk_level="none")

    assert aggregate_overall_risk(builder.stored_findings()) is RiskLevel.NONE


def test_aggregate_accepts_lowercase_and_garbage_stored_levels(builder: RepoBuilder):
    builder.finding("LOW", risk_level="high")
    builder.finding("CRITICAL", risk_level="not-a-level")  # unrecognised AI value -> UNKNOWN, not CRITICAL

    findings = builder.stored_findings()
    assert {effective_risk_level(f) for f in findings} == {RiskLevel.HIGH, RiskLevel.UNKNOWN}
    assert aggregate_overall_risk(findings) is RiskLevel.HIGH


def test_aggregate_accepts_generator(builder: RepoBuilder):
    builder.finding("MEDIUM")
    builder.finding("HIGH")

    assert aggregate_overall_risk(f for f in builder.stored_findings()) is RiskLevel.HIGH


def test_effective_risk_level_per_finding(builder: RepoBuilder):
    provisional = builder.finding("HIGH")
    ai = builder.finding("HIGH", risk_level="MEDIUM")
    unknown = builder.finding(None)

    assert effective_risk_level(provisional) is RiskLevel.HIGH
    assert effective_risk_level(ai) is RiskLevel.MEDIUM
    assert effective_risk_level(unknown) is RiskLevel.UNKNOWN


# --------------------------------------------------------------------------- priority ordering


def test_sort_findings_by_priority(builder: RepoBuilder):
    dep = builder.dependency("shared")
    low = builder.finding("LOW", cvss=3.9, identifier="GHSA-low")
    high_no_score = builder.finding("HIGH", cvss=None, identifier="GHSA-aaaa-high-noscore")
    high_75 = builder.finding("HIGH", cvss=7.5, identifier="GHSA-zzzz-high", dependency=dep)
    high_88_b = builder.finding("HIGH", cvss=8.8, identifier="GHSA-bbbb", dependency=dep)
    high_88_a = builder.finding("HIGH", cvss=8.8, identifier="GHSA-aaaa")
    critical = builder.finding("CRITICAL", cvss=9.1, identifier="CVE-2024-0001")
    unknown = builder.finding("UNKNOWN", cvss=None, identifier="PYSEC-0001")
    medium = builder.finding("moderate", cvss=5.0, identifier="GHSA-medium")

    ordered = sort_findings_by_priority(reversed(builder.stored_findings()))

    assert [f.vulnerability.identifier for f in ordered] == [
        "CVE-2024-0001",  # CRITICAL
        "GHSA-aaaa",  # HIGH 8.8, identifier tie-break
        "GHSA-bbbb",  # HIGH 8.8
        "GHSA-zzzz-high",  # HIGH 7.5
        "GHSA-aaaa-high-noscore",  # HIGH without a score sorts after scored HIGH findings
        "GHSA-medium",  # MEDIUM (via MODERATE alias)
        "GHSA-low",  # LOW
        "PYSEC-0001",  # UNKNOWN last
    ]
    assert ordered[0].finding_id == critical.finding_id
    assert ordered[-1].finding_id == unknown.finding_id
    assert {f.finding_id for f in ordered} == {
        x.finding_id for x in (low, high_no_score, high_75, high_88_b, high_88_a, critical, unknown, medium)
    }


def test_sort_findings_is_deterministic_for_identical_vulnerability_data(builder: RepoBuilder):
    vuln = builder.vulnerability("GHSA-same", "HIGH", 7.0)
    findings = []
    for name in ("b", "a", "c"):
        dep = builder.dependency(name)
        finding = Finding(
            analysis_id=builder.analysis.analysis_id,
            dependency_id=dep.dependency_id,
            vulnerability_id=vuln.vulnerability_id,
            ai_status="PENDING",
        )
        builder.db.add(finding)
        builder.db.flush()
        findings.append(finding)

    ordered = sort_findings_by_priority(reversed(findings))
    assert [f.finding_id for f in ordered] == sorted(f.finding_id for f in findings)


def test_sort_findings_empty():
    assert sort_findings_by_priority([]) == []
