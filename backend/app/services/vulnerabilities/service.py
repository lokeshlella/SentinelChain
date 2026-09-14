"""Vulnerability stage: dependencies -> provider queries -> Vulnerability rows -> Findings.

The service never invents results.  A dependency is SAFE only when the
provider answered with an empty result, VULNERABLE when it returned records,
and UNKNOWN when the version is not pinned or the provider could not answer
(``status_reason`` explains why).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import insert, select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.logging import get_stage_logger
from app.core.versions import is_valid_version
from app.db.base import utcnow
from app.models.analysis import Analysis
from app.models.dependency import Dependency
from app.models.enums import AIStatus, RiskLevel, Severity, StageStatus, VulnerabilityStatus
from app.models.finding import Finding
from app.models.vulnerability import Vulnerability
from app.services.vulnerabilities.aliases import canonical_records, deduplicate_records, merge_affected, package_key
from app.services.vulnerabilities.base import (
    AffectedPackage,
    AffectedRange,
    PackageQuery,
    PackageVulnerabilityResult,
    VulnerabilityProvider,
    VulnerabilityRecord,
)
from app.services.vulnerabilities.osv_provider import UNAVAILABLE_PREFIX, OSVProvider

log = get_stage_logger("Vulnerability")

UNPINNED_REASON = "Version not pinned; add a lock file or pin the version"


def invalid_version_reason(version: str, ecosystem: str) -> str:
    # OSV silently treats an unparsable version as "0" and would return every advisory
    # ever published for the package — an invented result we must never show as real.
    return f'Version "{version}" is not a valid {ecosystem} version; it cannot be checked'


# Dialect INSERT constructs offering ``ON CONFLICT DO NOTHING`` (same API on both).
_INSERT_ON_CONFLICT = {"postgresql": postgresql.insert, "sqlite": sqlite.insert}

# Provisional (non-AI) risk derived from severity only.  The AI risk agent may
# later replace ``Finding.risk_level``; until then this mapping is documented
# as the source of the value.
_PROVISIONAL_RISK = {
    Severity.CRITICAL: RiskLevel.CRITICAL,
    Severity.HIGH: RiskLevel.HIGH,
    Severity.MEDIUM: RiskLevel.MEDIUM,
    Severity.LOW: RiskLevel.LOW,
    Severity.UNKNOWN: RiskLevel.UNKNOWN,
}


def provisional_risk_level(severity: Severity | str | None) -> RiskLevel:
    """Provisional risk for a finding before any AI assessment (severity-only mapping)."""
    try:
        return _PROVISIONAL_RISK[Severity(severity)] if severity is not None else RiskLevel.UNKNOWN
    except ValueError:
        return RiskLevel.UNKNOWN


@dataclass
class VulnerabilityCheckSummary:
    """Outcome of ``VulnerabilityService.check_dependencies``."""

    dep_vulns: dict[int, list[Vulnerability]] = field(default_factory=dict)
    checked: int = 0  # dependencies processed
    safe: int = 0
    vulnerable: int = 0
    unknown: int = 0  # includes unpinned dependencies
    unpinned: int = 0  # subset of ``unknown`` that was never sent to the provider
    vulnerabilities_total: int = 0  # distinct Vulnerability rows referenced
    provider_available: bool = True
    stage_status: StageStatus = StageStatus.OK
    notes: list[str] = field(default_factory=list)

    @property
    def queried(self) -> int:
        return self.checked - self.unpinned

    def to_dict(self) -> dict:
        """JSON-friendly counters for ``analysis.summary`` (no ORM objects)."""
        return {
            "checked": self.checked,
            "queried": self.queried,
            "safe": self.safe,
            "vulnerable": self.vulnerable,
            "unknown": self.unknown,
            "unpinned": self.unpinned,
            "vulnerabilities_total": self.vulnerabilities_total,
            "provider_available": self.provider_available,
            "stage_status": str(self.stage_status),
            "notes": list(self.notes),
        }


class VulnerabilityService:
    """Checks dependency snapshots against a ``VulnerabilityProvider`` and persists the outcome."""

    def __init__(
        self,
        db: Session,
        provider: VulnerabilityProvider | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.db = db
        self.settings = settings or get_settings()
        self.provider = provider if provider is not None else OSVProvider(self.settings.osv_api_url, self.settings.osv_timeout)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_dependencies(self, dependencies: list[Dependency], *, commit: bool = True) -> VulnerabilityCheckSummary:
        """Classify every dependency as SAFE / VULNERABLE / UNKNOWN and store vulnerabilities.

        Dependencies without a concrete version are marked UNKNOWN without a
        provider call.  The remaining ones are sent in one batch; identical
        (ecosystem, name, version) triples are queried once.
        """
        now = utcnow()
        summary = VulnerabilityCheckSummary(checked=len(dependencies))
        self._ensure_ids(dependencies)

        deps_by_query: dict[PackageQuery, list[Dependency]] = {}
        for dep in dependencies:
            version = (dep.version or "").strip()
            if not version:
                self._mark(dep, VulnerabilityStatus.UNKNOWN, UNPINNED_REASON, now)
                summary.unknown += 1
                summary.unpinned += 1
                continue
            if not is_valid_version(version, dep.ecosystem):
                self._mark(dep, VulnerabilityStatus.UNKNOWN, invalid_version_reason(version, dep.ecosystem), now)
                summary.unknown += 1
                continue
            deps_by_query.setdefault(PackageQuery(dep.ecosystem, dep.package_name, version), []).append(dep)

        queries = list(deps_by_query)
        if queries:
            results = self._query_batch_safely(queries)
            self._apply_results(queries, results, deps_by_query, summary, now)
        else:
            summary.notes.append("No pinned dependencies to check")

        self._finish(commit)
        log.info(
            "%d dependencies checked: %d vulnerable, %d safe, %d unknown (%d unpinned); "
            "%d distinct vulnerabilities; provider %s; stage %s",
            summary.checked,
            summary.vulnerable,
            summary.safe,
            summary.unknown,
            summary.unpinned,
            summary.vulnerabilities_total,
            "available" if summary.provider_available else "unavailable",
            summary.stage_status,
        )
        return summary

    def create_findings(
        self,
        analysis: Analysis,
        dep_vulns: dict[int, list[Vulnerability]],
        *,
        commit: bool = True,
    ) -> list[Finding]:
        """One Finding per (dependency, vulnerability) for ``analysis``; idempotent on re-runs.

        Existing findings of the analysis are reused untouched (their AI
        results survive), new ones start with ``ai_status=PENDING`` and a
        provisional, severity-derived ``risk_level``.
        """
        if analysis.analysis_id is None:
            self.db.flush()
        analysis_id = analysis.analysis_id
        existing = {
            (f.dependency_id, f.vulnerability_id): f
            for f in self.db.scalars(select(Finding).where(Finding.analysis_id == analysis_id))
        }
        findings: list[Finding] = []
        created = 0
        now = utcnow()
        for dependency_id, vulnerabilities in dep_vulns.items():
            for vuln in vulnerabilities:
                if vuln.vulnerability_id is None:
                    self.db.flush()
                key = (dependency_id, vuln.vulnerability_id)
                finding = existing.get(key)
                if finding is None:
                    finding = Finding(
                        analysis_id=analysis_id,
                        dependency_id=dependency_id,
                        vulnerability_id=vuln.vulnerability_id,
                        impact_level=None,
                        risk_level=provisional_risk_level(vuln.severity),
                        ai_status=AIStatus.PENDING,
                        detected_at=now,
                    )
                    self.db.add(finding)
                    existing[key] = finding
                    created += 1
                findings.append(finding)
        self._finish(commit)
        log.info("%d findings created for analysis %s (%d already existed)", created, analysis_id, len(findings) - created)
        return findings

    def check_package(self, ecosystem: str, name: str, version: str) -> PackageVulnerabilityResult:
        """Single package check (remediation candidates, security scan); alias groups merged."""
        query = PackageQuery(ecosystem, name, (version or "").strip())
        if not query.version:
            return PackageVulnerabilityResult(query=query, status=VulnerabilityStatus.UNKNOWN, reason=UNPINNED_REASON)
        if not is_valid_version(query.version, ecosystem):
            return PackageVulnerabilityResult(
                query=query, status=VulnerabilityStatus.UNKNOWN, reason=invalid_version_reason(query.version, ecosystem)
            )
        try:
            result = self.provider.query(query)
        except Exception as exc:  # noqa: BLE001 - a provider bug must not break callers
            log.warning("provider %s raised for %s %s %s: %s", self.provider.name, ecosystem, name, version, exc)
            return PackageVulnerabilityResult(
                query=query,
                status=VulnerabilityStatus.UNKNOWN,
                reason=f"{UNAVAILABLE_PREFIX}: {exc}",
            )
        if result.status == VulnerabilityStatus.VULNERABLE:
            result.vulnerabilities = deduplicate_records(result.vulnerabilities)
        elif result.status == VulnerabilityStatus.SAFE and result.vulnerabilities:
            # Defensive: a provider must never claim SAFE while returning records.
            result.status = VulnerabilityStatus.VULNERABLE
            result.vulnerabilities = deduplicate_records(result.vulnerabilities)
        log.info("%s %s %s -> %s (%d vulnerabilities)", ecosystem, name, version, result.status, len(result.vulnerabilities))
        return result

    def provider_health(self) -> tuple[bool, str]:
        try:
            return self.provider.health()
        except Exception as exc:  # noqa: BLE001
            return False, f"{UNAVAILABLE_PREFIX}: {exc}"

    # ------------------------------------------------------------------
    # Batch handling
    # ------------------------------------------------------------------

    def _query_batch_safely(self, queries: list[PackageQuery]) -> list[PackageVulnerabilityResult]:
        """Call the provider; convert any exception / contract violation into UNKNOWN results."""
        try:
            results = self.provider.query_batch(queries)
        except Exception as exc:  # noqa: BLE001
            log.error("provider %s failed for %d queries: %s", self.provider.name, len(queries), exc)
            return [self._unknown_result(q, str(exc)) for q in queries]
        if len(results) != len(queries):
            log.error(
                "provider %s returned %d results for %d queries", self.provider.name, len(results), len(queries)
            )
            return [self._unknown_result(q, "provider returned a mismatched number of results") for q in queries]
        return results

    @staticmethod
    def _unknown_result(query: PackageQuery, cause: str) -> PackageVulnerabilityResult:
        return PackageVulnerabilityResult(
            query=query, status=VulnerabilityStatus.UNKNOWN, reason=f"{UNAVAILABLE_PREFIX}: {cause}"
        )

    def _apply_results(
        self,
        queries: list[PackageQuery],
        results: list[PackageVulnerabilityResult],
        deps_by_query: dict[PackageQuery, list[Dependency]],
        summary: VulnerabilityCheckSummary,
        now: datetime,
    ) -> None:
        all_records = [rec for res in results for rec in res.vulnerabilities]
        canonical = canonical_records(all_records)
        rows: dict[str, Vulnerability] = {}
        provider_errors = 0

        for query, result in zip(queries, results):
            deps = deps_by_query[query]
            if result.status == VulnerabilityStatus.VULNERABLE and result.vulnerabilities:
                merged = _unique_by_identifier(canonical[rec.identifier] for rec in result.vulnerabilities)
                vuln_rows = [self._upsert_vulnerability(rec, rows, now) for rec in merged]
                ids = ", ".join(row.identifier for row in vuln_rows)
                reason = f"{len(vuln_rows)} known {'vulnerability' if len(vuln_rows) == 1 else 'vulnerabilities'} ({ids})"
                if result.reason:
                    reason = f"{reason}; {result.reason}"
                for dep in deps:
                    self._mark(dep, VulnerabilityStatus.VULNERABLE, reason, now)
                    summary.dep_vulns[dep.dependency_id] = list(vuln_rows)
                summary.vulnerable += len(deps)
            elif result.status == VulnerabilityStatus.SAFE and not result.vulnerabilities:
                for dep in deps:
                    self._mark(dep, VulnerabilityStatus.SAFE, None, now)
                summary.safe += len(deps)
            else:
                # UNKNOWN, or an inconsistent answer (e.g. VULNERABLE without records) -> never SAFE.
                provider_errors += 1
                reason = result.reason or f"{UNAVAILABLE_PREFIX}: provider returned status {result.status} without details"
                for dep in deps:
                    self._mark(dep, VulnerabilityStatus.UNKNOWN, reason, now)
                summary.unknown += len(deps)

        summary.vulnerabilities_total = len(rows)
        if provider_errors == 0:
            summary.provider_available = True
            summary.stage_status = StageStatus.OK
        elif provider_errors == len(queries):
            summary.provider_available = False
            summary.stage_status = StageStatus.UNAVAILABLE
            summary.notes.append(f"{UNAVAILABLE_PREFIX}: provider {self.provider.name} answered none of {len(queries)} queries")
        else:
            summary.provider_available = True
            summary.stage_status = StageStatus.PARTIAL
            summary.notes.append(f"{provider_errors} of {len(queries)} queries could not be answered by {self.provider.name}")

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _ensure_ids(self, dependencies: list[Dependency]) -> None:
        if any(dep.dependency_id is None for dep in dependencies):
            self.db.flush()

    @staticmethod
    def _mark(dep: Dependency, status: VulnerabilityStatus, reason: str | None, now: datetime) -> None:
        dep.vulnerability_status = status
        dep.status_reason = reason
        dep.last_checked_at = now

    def _upsert_vulnerability(
        self, record: VulnerabilityRecord, cache: dict[str, Vulnerability], now: datetime
    ) -> Vulnerability:
        """Insert or refresh the ``Vulnerability`` row for ``record.identifier``.

        Fields are only overwritten with concrete data: a record whose details
        could not be fetched (id only) never wipes information stored earlier.
        """
        row = cache.get(record.identifier)
        if row is None:
            row = self._select_vulnerability(record.identifier)
        if row is None:
            row = self._insert_vulnerability(record)

        aliases = list(row.aliases or [])
        aliases.extend(a for a in record.aliases if a not in aliases and a != record.identifier)
        row.aliases = aliases
        if record.severity != Severity.UNKNOWN or not row.severity:
            row.severity = record.severity
        for attr in ("cvss_score", "cvss_vector", "summary", "description", "published_at", "modified_at", "reference_url"):
            value = getattr(record, attr)
            if value is not None:
                setattr(row, attr, value)
        if record.affected:
            row.affected = [pkg.to_dict() for pkg in _refresh_affected(row.affected, record.affected)]
        row.fetched_at = now
        self.db.flush()
        cache[record.identifier] = row
        return row

    def _select_vulnerability(self, identifier: str) -> Vulnerability | None:
        return self.db.scalar(select(Vulnerability).where(Vulnerability.identifier == identifier))

    def _insert_vulnerability(self, record: VulnerabilityRecord) -> Vulnerability:
        """Insert the row for ``record.identifier``, or reuse the one a concurrent analysis inserted first.

        ``vulnerabilities.identifier`` is globally unique and analyses run as
        parallel background tasks, so two of them can discover the same
        advisory at once.  A plain INSERT would raise ``IntegrityError`` for
        the loser and poison its whole transaction; ``INSERT ... ON CONFLICT
        DO NOTHING`` keeps the transaction valid on both supported databases
        (PostgreSQL waits for the competing transaction, SQLite serialises
        writers), after which the row is read back so both analyses share it.
        """
        values = {"identifier": record.identifier, "source": record.source, "severity": Severity.UNKNOWN}
        dialect_insert = _INSERT_ON_CONFLICT.get(self.db.get_bind().dialect.name)
        if dialect_insert is not None:
            statement = dialect_insert(Vulnerability).values(**values).on_conflict_do_nothing(index_elements=["identifier"])
        else:  # unsupported dialect: behaves like a plain insert (V1 targets PostgreSQL; tests use SQLite)
            statement = insert(Vulnerability).values(**values)
        inserted = self.db.execute(statement).rowcount == 1
        row = self._select_vulnerability(record.identifier)
        if row is None:  # pragma: no cover - the row was inserted or already existed
            raise RuntimeError(f"vulnerability {record.identifier} vanished after insert")
        if not inserted:
            log.info("vulnerability %s was stored concurrently by another analysis; reusing it", record.identifier)
        return row

    def _finish(self, commit: bool) -> None:
        self.db.flush()
        if commit:
            self.db.commit()


# ----------------------------------------------------------------------
# Module helpers
# ----------------------------------------------------------------------


def _unique_by_identifier(records) -> list[VulnerabilityRecord]:
    seen: set[str] = set()
    out: list[VulnerabilityRecord] = []
    for rec in records:
        if rec.identifier not in seen:
            seen.add(rec.identifier)
            out.append(rec)
    return out


def _affected_from_json(items: list | None) -> list[AffectedPackage]:
    packages: list[AffectedPackage] = []
    for item in items or []:
        if not isinstance(item, dict) or not item.get("ecosystem") or not item.get("package_name"):
            continue
        ranges = [
            AffectedRange(
                range_type=str(r.get("range_type") or "ECOSYSTEM"),
                introduced=r.get("introduced"),
                fixed=r.get("fixed"),
                last_affected=r.get("last_affected"),
            )
            for r in item.get("ranges") or []
            if isinstance(r, dict)
        ]
        packages.append(
            AffectedPackage(
                ecosystem=str(item["ecosystem"]),
                package_name=str(item["package_name"]),
                ranges=ranges,
                versions=[v for v in item.get("versions") or [] if isinstance(v, str)],
                fixed_versions=[v for v in item.get("fixed_versions") or [] if isinstance(v, str)],
            )
        )
    return packages


def _refresh_affected(stored: list | None, incoming: list[AffectedPackage]) -> list[AffectedPackage]:
    """Stored affected data with the incoming packages replacing entries for the same package."""
    incoming_keys = {package_key(pkg.ecosystem, pkg.package_name) for pkg in incoming}
    kept = [pkg for pkg in _affected_from_json(stored) if package_key(pkg.ecosystem, pkg.package_name) not in incoming_keys]
    return merge_affected(kept, incoming)
