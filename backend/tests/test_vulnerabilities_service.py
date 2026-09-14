"""VulnerabilityService with a fake provider and the SQLite ``db`` fixture."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.models import Analysis, Base, Dependency, Finding, Repository, Vulnerability
from app.models.enums import AIStatus, RiskLevel, Severity, StageStatus, VulnerabilityStatus
from app.services.vulnerabilities.aliases import deduplicate_records, group_by_alias, merge_group
from app.services.vulnerabilities.base import (
    AffectedPackage,
    AffectedRange,
    PackageQuery,
    PackageVulnerabilityResult,
    VulnerabilityProvider,
    VulnerabilityRecord,
)
from app.services.vulnerabilities.osv_provider import UNAVAILABLE_PREFIX, filter_record_for_package, parse_osv_record
from app.services.vulnerabilities.service import (
    UNPINNED_REASON,
    VulnerabilityCheckSummary,
    VulnerabilityService,
    provisional_risk_level,
)

FIXTURES = Path(__file__).parent / "fixtures" / "vulnerabilities"


# ---------------------------------------------------------------------------
# Test doubles and helpers
# ---------------------------------------------------------------------------


class FakeVulnerabilityProvider(VulnerabilityProvider):
    """Deterministic provider: answers from a dict keyed by (ecosystem, name, version)."""

    name = "fake"

    def __init__(self, answers: dict[tuple[str, str, str], list[VulnerabilityRecord] | str] | None = None) -> None:
        # value: list of records (VULNERABLE / SAFE when empty) or a str reason (UNKNOWN)
        self.answers = answers or {}
        self.batch_calls: list[list[PackageQuery]] = []
        self.query_calls: list[PackageQuery] = []
        self.healthy = True
        self.raise_on_batch: Exception | None = None

    def _answer(self, query: PackageQuery) -> PackageVulnerabilityResult:
        answer = self.answers.get((query.ecosystem, query.package_name, query.version), [])
        if isinstance(answer, str):
            return PackageVulnerabilityResult(query=query, status=VulnerabilityStatus.UNKNOWN, reason=answer)
        records = [filter_record_for_package(r, query.ecosystem, query.package_name) for r in answer]
        status = VulnerabilityStatus.VULNERABLE if records else VulnerabilityStatus.SAFE
        return PackageVulnerabilityResult(query=query, status=status, vulnerabilities=records)

    def query(self, query: PackageQuery) -> PackageVulnerabilityResult:
        self.query_calls.append(query)
        return self._answer(query)

    def query_batch(self, queries: list[PackageQuery]) -> list[PackageVulnerabilityResult]:
        self.batch_calls.append(list(queries))
        if self.raise_on_batch:
            raise self.raise_on_batch
        return [self._answer(q) for q in queries]

    def health(self) -> tuple[bool, str]:
        return self.healthy, "fake provider"


def unavailable(cause: str) -> str:
    return f"{UNAVAILABLE_PREFIX}: {cause}"


def osv_records(name: str) -> list[VulnerabilityRecord]:
    data = json.loads((FIXTURES / name).read_text())
    return [parse_osv_record(v) for v in data["vulns"]]


def record(
    identifier: str,
    *,
    aliases: list[str] | None = None,
    severity: Severity = Severity.HIGH,
    score: float | None = 7.5,
    fixed: str | None = "1.1.0",
    ecosystem: str = "PyPI",
    package: str = "demo",
    summary: str | None = "demo summary",
    published: datetime | None = None,
) -> VulnerabilityRecord:
    affected = [
        AffectedPackage(
            ecosystem=ecosystem,
            package_name=package,
            ranges=[AffectedRange("ECOSYSTEM", introduced="0", fixed=fixed)],
            fixed_versions=[fixed] if fixed else [],
        )
    ]
    return VulnerabilityRecord(
        identifier=identifier,
        source="fake",
        aliases=aliases or [],
        summary=summary,
        description=f"description of {identifier}",
        severity=severity,
        cvss_score=score,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" if score else None,
        published_at=published,
        reference_url=f"https://example.test/{identifier}",
        affected=affected,
    )


@pytest.fixture
def analysis(db) -> Analysis:
    repo = Repository(name="demo", source_url="/tmp/demo", source_type="local")
    db.add(repo)
    db.flush()
    analysis = Analysis(repository_id=repo.repository_id, status="RUNNING")
    db.add(analysis)
    db.flush()
    return analysis


def add_dependency(db, analysis: Analysis, name: str, version: str | None, ecosystem: str = "PyPI", source_file="requirements.txt") -> Dependency:
    dep = Dependency(
        repository_id=analysis.repository_id,
        analysis_id=analysis.analysis_id,
        package_name=name,
        version=version,
        version_spec=f"=={version}" if version else ">=1",
        ecosystem=ecosystem,
        source_file=source_file,
    )
    db.add(dep)
    db.flush()
    return dep


# ---------------------------------------------------------------------------
# check_dependencies
# ---------------------------------------------------------------------------


def test_classifies_safe_vulnerable_unknown_and_unpinned(db, analysis) -> None:
    provider = FakeVulnerabilityProvider(
        {
            ("PyPI", "demo", "1.0.0"): [record("GHSA-aaaa-bbbb-cccc", aliases=["CVE-2024-0001"])],
            ("PyPI", "flaky", "2.0"): unavailable("timeout after 30s calling POST /querybatch"),
        }
    )
    vulnerable = add_dependency(db, analysis, "demo", "1.0.0")
    safe = add_dependency(db, analysis, "six", "1.16.0")
    unknown = add_dependency(db, analysis, "flaky", "2.0")
    unpinned = add_dependency(db, analysis, "loose", None)

    summary = VulnerabilityService(db, provider).check_dependencies([vulnerable, safe, unknown, unpinned])

    assert isinstance(summary, VulnerabilityCheckSummary)
    assert (summary.checked, summary.safe, summary.vulnerable, summary.unknown, summary.unpinned) == (4, 1, 1, 2, 1)
    assert summary.vulnerabilities_total == 1
    assert summary.provider_available is True
    assert summary.stage_status is StageStatus.PARTIAL  # one provider error among three queries
    assert list(summary.dep_vulns) == [vulnerable.dependency_id]

    # Unpinned dependencies never reach the provider.
    assert len(provider.batch_calls) == 1
    assert {q.package_name for q in provider.batch_calls[0]} == {"demo", "six", "flaky"}

    assert vulnerable.vulnerability_status == VulnerabilityStatus.VULNERABLE
    assert "GHSA-aaaa-bbbb-cccc" in vulnerable.status_reason
    assert safe.vulnerability_status == VulnerabilityStatus.SAFE and safe.status_reason is None
    assert unknown.vulnerability_status == VulnerabilityStatus.UNKNOWN
    assert unknown.status_reason == unavailable("timeout after 30s calling POST /querybatch")
    assert unpinned.vulnerability_status == VulnerabilityStatus.UNKNOWN
    assert unpinned.status_reason == UNPINNED_REASON
    for dep in (vulnerable, safe, unknown, unpinned):
        assert dep.last_checked_at is not None

    row = db.scalar(select(Vulnerability).where(Vulnerability.identifier == "GHSA-aaaa-bbbb-cccc"))
    assert row is not None and row.source == "fake"
    assert row.aliases == ["CVE-2024-0001"]
    assert row.severity == Severity.HIGH and row.cvss_score == 7.5
    assert row.summary == "demo summary" and row.description == "description of GHSA-aaaa-bbbb-cccc"
    assert row.reference_url == "https://example.test/GHSA-aaaa-bbbb-cccc"
    assert row.affected == [
        {
            "ecosystem": "PyPI",
            "package_name": "demo",
            "ranges": [{"range_type": "ECOSYSTEM", "introduced": "0", "fixed": "1.1.0", "last_affected": None}],
            "versions": [],
            "fixed_versions": ["1.1.0"],
        }
    ]
    assert summary.to_dict()["stage_status"] == "PARTIAL" and "dep_vulns" not in summary.to_dict()


def test_provider_totally_unavailable_marks_stage_unavailable(db, analysis) -> None:
    provider = FakeVulnerabilityProvider(
        {
            ("PyPI", "a", "1"): unavailable("connection error"),
            ("PyPI", "b", "2"): unavailable("connection error"),
        }
    )
    deps = [add_dependency(db, analysis, "a", "1"), add_dependency(db, analysis, "b", "2"), add_dependency(db, analysis, "c", None)]
    summary = VulnerabilityService(db, provider).check_dependencies(deps)
    assert summary.provider_available is False
    assert summary.stage_status is StageStatus.UNAVAILABLE
    assert summary.unknown == 3 and summary.safe == 0 and summary.vulnerable == 0
    assert all(d.vulnerability_status == VulnerabilityStatus.UNKNOWN for d in deps)
    assert deps[0].status_reason.startswith(UNAVAILABLE_PREFIX)
    assert any("answered none of 2 queries" in n for n in summary.notes)


def test_provider_exception_does_not_crash_the_stage(db, analysis) -> None:
    provider = FakeVulnerabilityProvider()
    provider.raise_on_batch = RuntimeError("provider exploded")
    dep = add_dependency(db, analysis, "a", "1")
    summary = VulnerabilityService(db, provider).check_dependencies([dep])
    assert summary.stage_status is StageStatus.UNAVAILABLE and summary.provider_available is False
    assert dep.vulnerability_status == VulnerabilityStatus.UNKNOWN
    assert dep.status_reason == unavailable("provider exploded")


def test_mismatched_provider_answer_is_never_safe(db, analysis) -> None:
    class BrokenProvider(FakeVulnerabilityProvider):
        def query_batch(self, queries):
            return []  # contract violation: wrong number of results

    dep = add_dependency(db, analysis, "a", "1")
    summary = VulnerabilityService(db, BrokenProvider()).check_dependencies([dep])
    assert dep.vulnerability_status == VulnerabilityStatus.UNKNOWN
    assert "mismatched" in dep.status_reason
    assert summary.stage_status is StageStatus.UNAVAILABLE


def test_only_unpinned_dependencies_skips_provider(db, analysis) -> None:
    provider = FakeVulnerabilityProvider()
    dep = add_dependency(db, analysis, "loose", "")
    summary = VulnerabilityService(db, provider).check_dependencies([dep])
    assert provider.batch_calls == []
    assert summary.stage_status is StageStatus.OK and summary.provider_available is True
    assert summary.unknown == 1 and summary.unpinned == 1
    assert dep.status_reason == UNPINNED_REASON


def test_empty_input(db) -> None:
    summary = VulnerabilityService(db, FakeVulnerabilityProvider()).check_dependencies([])
    assert summary.checked == 0 and summary.stage_status is StageStatus.OK and summary.dep_vulns == {}


def test_identical_dependencies_are_queried_once_and_share_rows(db, analysis) -> None:
    provider = FakeVulnerabilityProvider({("PyPI", "demo", "1.0.0"): [record("GHSA-1111-2222-3333")]})
    dep_a = add_dependency(db, analysis, "demo", "1.0.0", source_file="requirements.txt")
    dep_b = add_dependency(db, analysis, "demo", "1.0.0", source_file="requirements/dev.txt")
    summary = VulnerabilityService(db, provider).check_dependencies([dep_a, dep_b])
    assert len(provider.batch_calls[0]) == 1
    assert summary.vulnerable == 2 and summary.vulnerabilities_total == 1
    assert summary.dep_vulns[dep_a.dependency_id][0] is summary.dep_vulns[dep_b.dependency_id][0]


def test_alias_groups_become_one_vulnerability(db, analysis) -> None:
    """A PYSEC and a GHSA record sharing a CVE alias are stored as one row (GHSA preferred)."""
    provider = FakeVulnerabilityProvider(
        {
            ("PyPI", "demo", "1.0.0"): [
                record("PYSEC-2023-1", aliases=["CVE-2023-1"], severity=Severity.UNKNOWN, score=None, summary=None),
                record("GHSA-xxxx-yyyy-zzzz", aliases=["CVE-2023-1"], severity=Severity.MEDIUM, score=5.3),
                record("GHSA-solo-solo-solo", aliases=["CVE-2023-2"], fixed="1.2.0"),
            ]
        }
    )
    dep = add_dependency(db, analysis, "demo", "1.0.0")
    summary = VulnerabilityService(db, provider).check_dependencies([dep])
    rows = summary.dep_vulns[dep.dependency_id]
    assert [r.identifier for r in rows] == ["GHSA-xxxx-yyyy-zzzz", "GHSA-solo-solo-solo"]
    assert summary.vulnerabilities_total == 2
    merged = rows[0]
    assert set(merged.aliases) == {"CVE-2023-1", "PYSEC-2023-1"}
    assert merged.severity == Severity.MEDIUM and merged.cvss_score == 5.3
    assert merged.summary == "demo summary"
    assert db.scalar(select(Vulnerability).where(Vulnerability.identifier == "PYSEC-2023-1")) is None
    assert "2 known vulnerabilities" in dep.status_reason


def test_alias_dedup_with_real_osv_records(db, analysis) -> None:
    """The real requests 2.25.1 answer (4 GHSA + 4 PYSEC) collapses to 4 vulnerabilities."""
    provider = FakeVulnerabilityProvider({("PyPI", "requests", "2.25.1"): osv_records("osv_query_requests_2.25.1.json")})
    dep = add_dependency(db, analysis, "requests", "2.25.1")
    summary = VulnerabilityService(db, provider).check_dependencies([dep])
    rows = summary.dep_vulns[dep.dependency_id]
    assert sorted(r.identifier for r in rows) == [
        "GHSA-9hjg-9r4m-mvj7", "GHSA-9wx4-h78v-vm56", "GHSA-gc5v-m9x4-r6x2", "GHSA-j8r2-6x86-q33q",
    ]
    j8r2 = next(r for r in rows if r.identifier == "GHSA-j8r2-6x86-q33q")
    assert set(j8r2.aliases) == {"CVE-2023-32681", "PYSEC-2023-74"}
    assert j8r2.severity == Severity.MEDIUM and j8r2.cvss_score == 6.1
    assert j8r2.published_at.replace(tzinfo=timezone.utc) == datetime(2023, 5, 22, 20, 36, 32, tzinfo=timezone.utc)
    assert j8r2.affected[0]["fixed_versions"] == ["2.31.0"]
    # The PYSEC GIT range was merged in as evidence next to the ECOSYSTEM range.
    assert {r["range_type"] for r in j8r2.affected[0]["ranges"]} == {"ECOSYSTEM", "GIT"}
    assert db.scalar(select(Vulnerability).where(Vulnerability.identifier.like("PYSEC-%"))) is None


def test_alias_groups_are_consistent_across_dependencies(db, analysis) -> None:
    """dep B only sees the PYSEC id, but it maps to the GHSA row created for dep A."""
    ghsa = record("GHSA-xxxx-yyyy-zzzz", aliases=["CVE-2023-1"])
    pysec = record("PYSEC-2023-1", aliases=["CVE-2023-1"], package="other", severity=Severity.UNKNOWN, score=None)
    provider = FakeVulnerabilityProvider({("PyPI", "demo", "1.0.0"): [ghsa, pysec], ("PyPI", "other", "3.0"): [pysec]})
    dep_a = add_dependency(db, analysis, "demo", "1.0.0")
    dep_b = add_dependency(db, analysis, "other", "3.0")
    summary = VulnerabilityService(db, provider).check_dependencies([dep_a, dep_b])
    assert [r.identifier for r in summary.dep_vulns[dep_b.dependency_id]] == ["GHSA-xxxx-yyyy-zzzz"]
    assert summary.vulnerabilities_total == 1
    row = summary.dep_vulns[dep_b.dependency_id][0]
    assert {p["package_name"] for p in row.affected} == {"demo", "other"}


def test_second_run_upserts_existing_rows(db, analysis) -> None:
    provider = FakeVulnerabilityProvider({("PyPI", "demo", "1.0.0"): [record("GHSA-1111-2222-3333", severity=Severity.LOW, score=3.1)]})
    dep = add_dependency(db, analysis, "demo", "1.0.0")
    service = VulnerabilityService(db, provider)
    first = service.check_dependencies([dep]).dep_vulns[dep.dependency_id][0]
    first_fetched = first.fetched_at

    provider.answers[("PyPI", "demo", "1.0.0")] = [
        record("GHSA-1111-2222-3333", aliases=["CVE-2024-9"], severity=Severity.CRITICAL, score=9.8, fixed="1.5.0", summary="updated")
    ]
    second = service.check_dependencies([dep]).dep_vulns[dep.dependency_id][0]

    assert second.vulnerability_id == first.vulnerability_id
    assert db.query(Vulnerability).count() == 1
    assert second.severity == Severity.CRITICAL and second.cvss_score == 9.8
    assert second.summary == "updated" and second.aliases == ["CVE-2024-9"]
    assert second.affected[0]["fixed_versions"] == ["1.5.0"]
    assert second.fetched_at >= first_fetched


def test_minimal_record_does_not_wipe_existing_details(db, analysis) -> None:
    provider = FakeVulnerabilityProvider({("PyPI", "demo", "1.0.0"): [record("GHSA-1111-2222-3333")]})
    dep = add_dependency(db, analysis, "demo", "1.0.0")
    service = VulnerabilityService(db, provider)
    service.check_dependencies([dep])
    provider.answers[("PyPI", "demo", "1.0.0")] = [VulnerabilityRecord(identifier="GHSA-1111-2222-3333", source="fake")]
    row = service.check_dependencies([dep]).dep_vulns[dep.dependency_id][0]
    assert row.severity == Severity.HIGH and row.cvss_score == 7.5
    assert row.summary == "demo summary" and row.affected[0]["fixed_versions"] == ["1.1.0"]


def test_recheck_clears_stale_vulnerable_status(db, analysis) -> None:
    provider = FakeVulnerabilityProvider({("PyPI", "demo", "1.0.0"): [record("GHSA-1111-2222-3333")]})
    dep = add_dependency(db, analysis, "demo", "1.0.0")
    service = VulnerabilityService(db, provider)
    service.check_dependencies([dep])
    assert dep.vulnerability_status == VulnerabilityStatus.VULNERABLE
    provider.answers[("PyPI", "demo", "1.0.0")] = []
    summary = service.check_dependencies([dep])
    assert dep.vulnerability_status == VulnerabilityStatus.SAFE and dep.status_reason is None
    assert summary.dep_vulns == {}


def test_commit_can_be_deferred(db, analysis) -> None:
    provider = FakeVulnerabilityProvider({("PyPI", "demo", "1.0.0"): [record("GHSA-1111-2222-3333")]})
    dep = add_dependency(db, analysis, "demo", "1.0.0")
    VulnerabilityService(db, provider).check_dependencies([dep], commit=False)
    assert db.in_transaction()
    db.rollback()
    assert db.query(Vulnerability).count() == 0


def test_deferred_commit_rolls_back_rows_inserted_in_a_fresh_transaction(db, analysis) -> None:
    """The vulnerability INSERT is the first write of the transaction and must still roll back with it."""
    provider = FakeVulnerabilityProvider({("PyPI", "demo", "1.0.0"): [record("GHSA-1111-2222-3333")]})
    dep = add_dependency(db, analysis, "demo", "1.0.0")
    db.commit()
    VulnerabilityService(db, provider).check_dependencies([dep], commit=False)
    assert dep.vulnerability_status == VulnerabilityStatus.VULNERABLE
    db.rollback()
    assert db.query(Vulnerability).count() == 0
    assert db.get(Dependency, dep.dependency_id).vulnerability_status != VulnerabilityStatus.VULNERABLE


# ---------------------------------------------------------------------------
# Concurrent analyses (two sessions, one database file)
# ---------------------------------------------------------------------------


@pytest.fixture
def session_factory(tmp_path):
    """Sessions with their own connections on one SQLite file: models concurrent background analyses."""
    engine = create_engine(f"sqlite:///{tmp_path / 'concurrent.db'}", future=True)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)
    sessions: list[Session] = []

    def make() -> Session:
        session = factory()
        sessions.append(session)
        return session

    try:
        yield make
    finally:
        for session in sessions:
            session.close()
        engine.dispose()


def committed_analysis(session: Session) -> Analysis:
    repo = Repository(name="demo", source_url="/tmp/demo", source_type="local")
    session.add(repo)
    session.flush()
    analysis = Analysis(repository_id=repo.repository_id, status="RUNNING")
    session.add(analysis)
    session.commit()
    return analysis


@pytest.mark.parametrize("order", ["vulnerable_only", "safe_then_vulnerable", "vulnerable_then_safe"])
def test_concurrent_insert_of_same_vulnerability_reuses_winning_row(session_factory, order: str) -> None:
    """Two analyses discover the same advisory at once: the loser reuses the row instead of crashing.

    Session B looks the identifier up, finds nothing, and before it inserts,
    session A inserts and commits ``GHSA-race-race-race`` (injected right
    after B's lookup, while B holds no SQLite write lock).  B's INSERT then
    collides with the unique constraint; the stage must survive, keep every
    status it already set and end up referencing A's row.
    """
    provider = FakeVulnerabilityProvider({("PyPI", "demo", "1.0.0"): [record("GHSA-race-race-race", aliases=["CVE-2024-1"])]})
    a, b = session_factory(), session_factory()
    dep_a = add_dependency(a, committed_analysis(a), "demo", "1.0.0")
    a.commit()
    analysis_b = committed_analysis(b)
    dep_b = add_dependency(b, analysis_b, "demo", "1.0.0")
    safe_b = add_dependency(b, analysis_b, "six", "1.16.0") if order != "vulnerable_only" else None
    b.commit()
    deps_b = {"vulnerable_only": [dep_b], "safe_then_vulnerable": [safe_b, dep_b], "vulnerable_then_safe": [dep_b, safe_b]}[order]

    service_b = VulnerabilityService(b, provider)
    lookup = service_b._select_vulnerability
    fired: list[str] = []

    def lookup_then_lose_the_race(identifier: str) -> Vulnerability | None:
        found = lookup(identifier)
        if found is None and not fired:
            fired.append(identifier)
            VulnerabilityService(a, provider).check_dependencies([dep_a])
        return found

    service_b._select_vulnerability = lookup_then_lose_the_race
    summary = service_b.check_dependencies(deps_b)

    assert fired == ["GHSA-race-race-race"]  # the race was actually exercised
    assert summary.stage_status is StageStatus.OK and summary.provider_available is True
    assert (summary.vulnerable, summary.safe, summary.vulnerabilities_total) == (1, len(deps_b) - 1, 1)
    winner = a.scalar(select(Vulnerability).where(Vulnerability.identifier == "GHSA-race-race-race"))
    row = summary.dep_vulns[dep_b.dependency_id][0]
    assert row.vulnerability_id == winner.vulnerability_id
    assert row.aliases == ["CVE-2024-1"] and row.severity == Severity.HIGH
    assert not b.new and not b.dirty  # nothing left pending after the stage committed

    # Everything B did before and after the race is committed.
    fresh = session_factory()
    assert fresh.query(Vulnerability).count() == 1
    stored_vuln = fresh.get(Dependency, dep_b.dependency_id)
    assert stored_vuln.vulnerability_status == VulnerabilityStatus.VULNERABLE
    assert "GHSA-race-race-race" in stored_vuln.status_reason and stored_vuln.last_checked_at is not None
    if safe_b is not None:
        stored_safe = fresh.get(Dependency, safe_b.dependency_id)
        assert stored_safe.vulnerability_status == VulnerabilityStatus.SAFE and stored_safe.last_checked_at is not None
    assert fresh.get(Dependency, dep_a.dependency_id).vulnerability_status == VulnerabilityStatus.VULNERABLE
    findings = VulnerabilityService(b, provider).create_findings(analysis_b, summary.dep_vulns)
    assert [f.vulnerability_id for f in findings] == [winner.vulnerability_id]


def test_integrity_error_that_is_not_the_identifier_race_still_raises(session_factory) -> None:
    """Only the identifier race is absorbed; any other constraint violation must surface."""
    session = session_factory()
    dep = add_dependency(session, committed_analysis(session), "demo", "1.0.0")
    session.commit()
    bad = record("GHSA-nope-nope-nope")
    bad.source = None  # NOT NULL column -> IntegrityError, but no row with this identifier exists
    provider = FakeVulnerabilityProvider({("PyPI", "demo", "1.0.0"): [bad]})
    with pytest.raises(Exception, match="NOT NULL"):
        VulnerabilityService(session, provider).check_dependencies([dep])


# ---------------------------------------------------------------------------
# create_findings
# ---------------------------------------------------------------------------


def test_create_findings_one_per_pair_with_provisional_risk(db, analysis) -> None:
    provider = FakeVulnerabilityProvider(
        {
            ("PyPI", "demo", "1.0.0"): [
                record("GHSA-crit-crit-crit", severity=Severity.CRITICAL, score=9.8),
                record("GHSA-unkn-unkn-unkn", severity=Severity.UNKNOWN, score=None),
            ],
            ("npm", "lodash", "4.17.15"): [record("GHSA-lodash-1", severity=Severity.HIGH, ecosystem="npm", package="lodash")],
        }
    )
    deps = [
        add_dependency(db, analysis, "demo", "1.0.0"),
        add_dependency(db, analysis, "lodash", "4.17.15", ecosystem="npm", source_file="package.json"),
        add_dependency(db, analysis, "six", "1.16.0"),
    ]
    service = VulnerabilityService(db, provider)
    summary = service.check_dependencies(deps)
    findings = service.create_findings(analysis, summary.dep_vulns)

    assert len(findings) == 3
    assert {(f.dependency_id, f.vulnerability.identifier) for f in findings} == {
        (deps[0].dependency_id, "GHSA-crit-crit-crit"),
        (deps[0].dependency_id, "GHSA-unkn-unkn-unkn"),
        (deps[1].dependency_id, "GHSA-lodash-1"),
    }
    by_vuln = {f.vulnerability.identifier: f for f in findings}
    assert by_vuln["GHSA-crit-crit-crit"].risk_level == RiskLevel.CRITICAL
    assert by_vuln["GHSA-unkn-unkn-unkn"].risk_level == RiskLevel.UNKNOWN
    assert by_vuln["GHSA-lodash-1"].risk_level == RiskLevel.HIGH
    for finding in findings:
        assert finding.analysis_id == analysis.analysis_id
        assert finding.ai_status == AIStatus.PENDING
        assert finding.impact_level is None
        assert finding.detected_at is not None
        assert finding.finding_id is not None
    assert db.query(Finding).count() == 3


def test_create_findings_is_idempotent_and_keeps_ai_results(db, analysis) -> None:
    provider = FakeVulnerabilityProvider({("PyPI", "demo", "1.0.0"): [record("GHSA-1111-2222-3333")]})
    dep = add_dependency(db, analysis, "demo", "1.0.0")
    service = VulnerabilityService(db, provider)
    dep_vulns = service.check_dependencies([dep]).dep_vulns
    first = service.create_findings(analysis, dep_vulns)
    first[0].ai_status = AIStatus.COMPLETED
    first[0].risk_level = RiskLevel.LOW
    db.commit()

    again = service.create_findings(analysis, service.check_dependencies([dep]).dep_vulns)
    assert len(again) == 1 and again[0].finding_id == first[0].finding_id
    assert db.query(Finding).count() == 1
    assert again[0].ai_status == AIStatus.COMPLETED and again[0].risk_level == RiskLevel.LOW

    # A different analysis of the same repository gets its own findings.
    other = Analysis(repository_id=analysis.repository_id, status="RUNNING")
    db.add(other)
    db.flush()
    other_dep = add_dependency(db, other, "demo", "1.0.0")
    other_findings = service.create_findings(other, service.check_dependencies([other_dep]).dep_vulns)
    assert len(other_findings) == 1 and other_findings[0].analysis_id == other.analysis_id
    assert db.query(Finding).count() == 2


def test_create_findings_with_nothing_vulnerable(db, analysis) -> None:
    assert VulnerabilityService(db, FakeVulnerabilityProvider()).create_findings(analysis, {}) == []


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        (Severity.CRITICAL, RiskLevel.CRITICAL),
        ("HIGH", RiskLevel.HIGH),
        (Severity.MEDIUM, RiskLevel.MEDIUM),
        (Severity.LOW, RiskLevel.LOW),
        (Severity.UNKNOWN, RiskLevel.UNKNOWN),
        (None, RiskLevel.UNKNOWN),
        ("weird", RiskLevel.UNKNOWN),
    ],
)
def test_provisional_risk_level(severity, expected) -> None:
    assert provisional_risk_level(severity) is expected


# ---------------------------------------------------------------------------
# check_package
# ---------------------------------------------------------------------------


def test_check_package_dedupes_aliases(db) -> None:
    provider = FakeVulnerabilityProvider({("PyPI", "requests", "2.25.1"): osv_records("osv_query_requests_2.25.1.json")})
    result = VulnerabilityService(db, provider).check_package("PyPI", "requests", "2.25.1")
    assert result.status is VulnerabilityStatus.VULNERABLE
    assert len(result.vulnerabilities) == 4
    assert all(r.identifier.startswith("GHSA-") for r in result.vulnerabilities)
    assert provider.query_calls == [PackageQuery("PyPI", "requests", "2.25.1")]


def test_check_package_safe_and_unknown(db) -> None:
    provider = FakeVulnerabilityProvider({("PyPI", "flaky", "1"): unavailable("HTTP 503")})
    service = VulnerabilityService(db, provider)
    assert service.check_package("PyPI", "six", "1.16.0").status is VulnerabilityStatus.SAFE
    unknown = service.check_package("PyPI", "flaky", "1")
    assert unknown.status is VulnerabilityStatus.UNKNOWN and "HTTP 503" in unknown.reason
    unpinned = service.check_package("PyPI", "six", "")
    assert unpinned.status is VulnerabilityStatus.UNKNOWN and unpinned.reason == UNPINNED_REASON
    assert len(provider.query_calls) == 2


def test_check_package_provider_exception_is_unknown(db) -> None:
    class Exploding(FakeVulnerabilityProvider):
        def query(self, query):
            raise RuntimeError("boom")

    result = VulnerabilityService(db, Exploding()).check_package("PyPI", "six", "1.16.0")
    assert result.status is VulnerabilityStatus.UNKNOWN and result.reason == unavailable("boom")


def test_provider_health_passthrough(db) -> None:
    provider = FakeVulnerabilityProvider()
    service = VulnerabilityService(db, provider)
    assert service.provider_health() == (True, "fake provider")
    provider.healthy = False
    assert service.provider_health()[0] is False


# ---------------------------------------------------------------------------
# alias helpers
# ---------------------------------------------------------------------------


def test_group_by_alias_merges_only_records_with_the_same_cve_set() -> None:
    """Records naming different CVE sets describe different issues and must not be
    blended (their fixed versions would otherwise mask each other)."""
    a = record("PYSEC-1", aliases=["CVE-1"])
    b = record("GHSA-1", aliases=["CVE-1", "CVE-2"])
    c = record("OSV-1", aliases=["CVE-2"])
    d = record("GHSA-2", aliases=[])
    e = record("PYSEC-9", aliases=["CVE-1", "GHSA-9"])
    f = record("GHSA-9", aliases=["CVE-1"])
    groups = group_by_alias([a, b, c, d, e, f])
    assert sorted(sorted(r.identifier for r in g) for g in groups) == [
        ["GHSA-1"], ["GHSA-2"], ["GHSA-9", "PYSEC-1", "PYSEC-9"], ["OSV-1"],
    ]


def test_merge_group_prefers_ghsa_then_cve_then_other_and_keeps_all_data() -> None:
    pysec = record("PYSEC-1", aliases=["CVE-1"], severity=Severity.HIGH, score=8.8, fixed="1.1.0", summary=None)
    cve = record("CVE-1", aliases=[], severity=Severity.UNKNOWN, score=None, fixed="1.1.1", summary="cve summary")
    merged = merge_group([pysec, cve])
    assert merged.identifier == "CVE-1"
    assert merged.aliases == ["PYSEC-1"]
    assert merged.severity is Severity.HIGH  # primary unknown -> best known from the group
    assert merged.cvss_score == 8.8 and merged.cvss_vector is not None
    assert merged.summary == "cve summary"
    # 1.1.0 is still inside the other record's affected range, so only 1.1.1 fixes the whole group.
    assert merged.fixed_versions_for("PyPI", "demo") == ["1.1.1"]

    ghsa = record("GHSA-1", aliases=["CVE-1"], severity=Severity.LOW, score=2.0)
    assert merge_group([pysec, cve, ghsa]).identifier == "GHSA-1"


def test_merge_group_same_tier_prefers_scored_then_oldest() -> None:
    newer = record("GHSA-bbbb", aliases=["CVE-1"], published=datetime(2026, 1, 1, tzinfo=timezone.utc))
    older = record("GHSA-aaaa", aliases=["CVE-1"], published=datetime(2021, 1, 1, tzinfo=timezone.utc))
    unscored = record("GHSA-0000", aliases=["CVE-1"], score=None, published=datetime(2020, 1, 1, tzinfo=timezone.utc))
    assert merge_group([newer, older, unscored]).identifier == "GHSA-aaaa"


def test_deduplicate_records_preserves_first_seen_order() -> None:
    records = [record("PYSEC-9"), record("GHSA-a", aliases=["CVE-9"]), record("PYSEC-8", aliases=["CVE-9"]), record("GHSA-b")]
    assert [r.identifier for r in deduplicate_records(records)] == ["PYSEC-9", "GHSA-a", "GHSA-b"]


def test_merged_group_reports_highest_score_and_group_safe_fix_for_real_lodash_data() -> None:
    """GHSA-35jh-r3h4-6jhm (7.2, fixed 4.17.21) and GHSA-r5fr-rjxr-66jc (8.1, fixed 4.18.0)
    share the same CVE aliases in OSV; the merged record must not under-report."""
    import json
    from pathlib import Path

    from app.services.vulnerabilities.aliases import deduplicate_records
    from app.services.vulnerabilities.osv_provider import filter_record_for_package, parse_osv_record

    data = json.loads(Path("tests/fixtures/vulnerabilities/osv_query_lodash_4.17.15.json").read_text())
    records = [filter_record_for_package(parse_osv_record(v), "npm", "lodash") for v in data["vulns"]]
    merged = {r.identifier: r for r in deduplicate_records(records)}
    group = merged["GHSA-35jh-r3h4-6jhm"]
    assert group.cvss_score == 8.1
    assert group.fixed_versions_for("npm", "lodash") == ["4.18.0"]


def test_invalid_version_strings_are_unknown_and_never_sent_to_the_provider(db, analysis) -> None:
    """OSV treats unparsable versions as "0" and returns every advisory — we must not ask."""
    provider = FakeVulnerabilityProvider()
    dep = add_dependency(db, analysis, "requests", "2.25.1-custom")
    service = VulnerabilityService(db, provider=provider)
    summary = service.check_dependencies([dep])
    assert provider.batch_calls == []
    assert dep.vulnerability_status == VulnerabilityStatus.UNKNOWN
    assert "not a valid PyPI version" in dep.status_reason
    assert summary.unknown == 1
    result = service.check_package("npm", "lodash", "=4.17.15")
    assert result.status == VulnerabilityStatus.UNKNOWN and "not a valid npm version" in result.reason
    assert provider.query_calls == []
