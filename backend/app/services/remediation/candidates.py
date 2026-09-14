"""Deterministic candidate versions for a vulnerable dependency - contract §4.7.

Every version in a :class:`CandidateSet` comes from one of two observed
sources: the ``fixed`` events OSV recorded for the dependency's
vulnerabilities, or the package registry's list of published releases.
Nothing is guessed: a candidate is *verified safe* only when OSV answered
SAFE for it, *unverified* (``verified_safe=None``) when OSV could not be
reached, and *not safe* when OSV still lists vulnerabilities for it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from app.core.logging import get_stage_logger
from app.core.versions import (
    InvalidVersionError,
    compare_versions,
    is_prerelease,
    major_of,
    min_version_at_least,
    parse_version,
    sort_versions,
)
from app.models.enums import VulnerabilityStatus
from app.models.vulnerability import Vulnerability
from app.services.analysis.context import fixed_versions_for
from app.services.remediation.registry import RegistryInfo
from app.services.vulnerabilities.base import PackageQuery, PackageVulnerabilityResult, VulnerabilityRecord

log = get_stage_logger("Remediation")

#: Upper bound on "candidate still vulnerable -> bump to the next fixed version" rounds.
MAX_VERIFY_ITERATIONS = 5
OSV_UNAVAILABLE_NOTE = "OSV unavailable; candidate not verified"


class RegistryLike(Protocol):
    def versions(self, ecosystem: str, name: str) -> RegistryInfo: ...


class VulnerabilityCheckerLike(Protocol):
    def check_package(self, ecosystem: str, name: str, version: str) -> PackageVulnerabilityResult: ...


class DependencyLike(Protocol):
    package_name: str
    ecosystem: str
    version: str | None


@dataclass
class CandidateSet:
    """Versions a remediation may propose, with the evidence behind each of them."""

    current_version: str | None
    minimum_fixed_version: str | None = None
    preferred_version: str | None = None
    allowed_versions: list[str] = field(default_factory=list)
    latest_version: str | None = None
    latest_in_same_major: str | None = None
    #: ``preferred_version`` shares the major version of ``current_version`` (None when unknown).
    same_major: bool | None = None
    #: True = OSV answered SAFE for ``preferred_version``; False = still vulnerable; None = OSV unavailable.
    verified_safe: bool | None = None
    #: Vulnerability identifiers OSV still reports for ``preferred_version``.
    remaining_vulnerabilities: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    registry_available: bool = True
    osv_available: bool = True
    #: Every OSV verification performed: version -> SAFE | VULNERABLE | UNKNOWN.
    verification: dict[str, str] = field(default_factory=dict)
    #: Fixed versions OSV published per vulnerability identifier (evidence for the report).
    fixed_versions: dict[str, list[str]] = field(default_factory=dict)

    @property
    def has_candidate(self) -> bool:
        return self.preferred_version is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "current_version": self.current_version,
            "minimum_fixed_version": self.minimum_fixed_version,
            "preferred_version": self.preferred_version,
            "allowed_versions": list(self.allowed_versions),
            "latest_version": self.latest_version,
            "latest_in_same_major": self.latest_in_same_major,
            "same_major": self.same_major,
            "verified_safe": self.verified_safe,
            "remaining_vulnerabilities": list(self.remaining_vulnerabilities),
            "notes": list(self.notes),
            "registry_available": self.registry_available,
            "osv_available": self.osv_available,
            "verification": dict(self.verification),
            "fixed_versions": {k: list(v) for k, v in self.fixed_versions.items()},
        }


# ---------------------------------------------------------------------- selection


def select_candidates(
    dependency: DependencyLike,
    vulnerabilities: list[Vulnerability],
    *,
    registry: RegistryLike,
    vulnerability_service: VulnerabilityCheckerLike,
    ecosystem: str | None = None,
) -> CandidateSet:
    """Compute the candidate versions for ``dependency`` given its ``vulnerabilities`` (ORM rows).

    1. per vulnerability: the smallest OSV *fixed* version above the current one;
       ``minimum_fixed_version`` is the maximum of those (so every fixable
       vulnerability is covered);
    2. snap it to a version the registry really publishes (pre-releases excluded);
    3. verify with OSV; while the candidate is still vulnerable, move to the next
       fixed version taken from the returned records (at most
       :data:`MAX_VERIFY_ITERATIONS` rounds);
    4. ``preferred_version`` = lowest verified-safe version in the current major
       when one exists, else the lowest verified-safe one (or the unverified
       minimum when OSV is unavailable); ``allowed_versions`` = verified-safe
       members of {preferred, latest in same major, latest}.
    """
    eco = ecosystem or dependency.ecosystem
    name = dependency.package_name
    current = dependency.version
    selection = _Selection(eco, name, current, registry, vulnerability_service)
    return selection.run(vulnerabilities)


class _Selection:
    """One ``select_candidates`` run; keeps the notes / verification bookkeeping together."""

    def __init__(
        self,
        ecosystem: str,
        name: str,
        current: str | None,
        registry: RegistryLike,
        checker: VulnerabilityCheckerLike,
    ) -> None:
        self.ecosystem = ecosystem
        self.name = name
        self.current = current if _parses(current, ecosystem) else None
        self.registry = registry
        self.checker = checker
        self.result = CandidateSet(current_version=current)
        self.registry_info: RegistryInfo | None = None
        if current and self.current is None:
            self.note(f'current version "{current}" is not a valid {ecosystem} version; every fixed version is considered')

    # -------------------------------------------------------------- orchestration

    def run(self, vulnerabilities: list[Vulnerability]) -> CandidateSet:
        res = self.result
        minimum = self._minimum_fixed(vulnerabilities)
        self._load_registry()
        if minimum is None:
            self.note("no fixed version is known for any of the vulnerabilities; no candidate can be proposed")
            log.info("%s %s@%s: no candidate (no fixed version published)", self.ecosystem, self.name, self.current)
            return res

        res.minimum_fixed_version = self._snap(minimum)
        candidate, verified = self._verify_loop(res.minimum_fixed_version)
        safe_versions = self._collect_safe(candidate, verified)
        self._choose(candidate, verified, safe_versions)
        log.info(
            "%s %s@%s: preferred %s (verified_safe=%s, same_major=%s), allowed %s, latest %s, registry %s, osv %s",
            self.ecosystem, self.name, self.current, res.preferred_version, res.verified_safe, res.same_major,
            res.allowed_versions, res.latest_version,
            "available" if res.registry_available else "unavailable",
            "available" if res.osv_available else "unavailable",
        )
        return res

    # -------------------------------------------------------------- step 1: OSV fixed versions

    def _minimum_fixed(self, vulnerabilities: list[Vulnerability]) -> str | None:
        """Max over vulnerabilities of the smallest fixed version above the current one."""
        floors: list[str] = []
        for vuln in _unique_by_identifier(vulnerabilities):
            fixed = sort_versions(fixed_versions_for(vuln, self.ecosystem, self.name), self.ecosystem)
            self.result.fixed_versions[vuln.identifier] = fixed
            if not fixed:
                self.note(f"{vuln.identifier} has no fixed version published")
                continue
            above = [v for v in fixed if self._above_current(v)]
            if not above:
                self.note(
                    f"{vuln.identifier}: fixed in {', '.join(fixed)}, none above the current version "
                    f"{self.current}; the current version may be affected through another range"
                )
                continue
            self.note(f"{vuln.identifier}: fixed in {above[0]}")
            floors.append(above[0])
        if not floors:
            return None
        minimum = sort_versions(floors, self.ecosystem)[-1]
        if len(floors) > 1:
            self.note(f"minimum fixed version {minimum} covers all {len(floors)} fixable vulnerabilities")
        return minimum

    def _above_current(self, version: str) -> bool:
        if self.current is None:
            return True
        try:
            return compare_versions(version, self.current, self.ecosystem) > 0
        except InvalidVersionError:
            return False

    # -------------------------------------------------------------- step 2: registry

    def _load_registry(self) -> None:
        res = self.result
        try:
            info = self.registry.versions(self.ecosystem, self.name)
        except Exception as exc:  # noqa: BLE001 - the registry is optional evidence
            log.warning("Registry lookup crashed for %s %s: %s", self.ecosystem, self.name, exc)
            info = RegistryInfo(ecosystem=self.ecosystem, package_name=self.name, available=False, error=str(exc))
        self.registry_info = info
        res.registry_available = info.available
        if not info.available:
            self.note(f"registry unavailable ({info.error}); OSV fixed versions are used without confirming they exist")
            return
        if not info.versions:
            self.note(f"registry lists no installable version for {self.name} ({info.error or 'empty listing'})")
            return
        res.latest_version = info.latest
        res.latest_in_same_major = self._latest_in_same_major(info.versions)

    def _latest_in_same_major(self, versions: list[str]) -> str | None:
        if self.current is None:
            return None
        major = major_of(self.current, self.ecosystem)
        same = [
            v for v in versions
            if major_of(v, self.ecosystem) == major and not is_prerelease(v, self.ecosystem)
        ]
        ordered = sort_versions(same, self.ecosystem)
        return ordered[-1] if ordered else None

    def _snap(self, floor: str) -> str:
        """Smallest published (non-pre-release) version >= ``floor``; ``floor`` itself when unknown."""
        info = self.registry_info
        if info is None or not info.available or not info.versions:
            return floor
        snapped = min_version_at_least(info.versions, floor, self.ecosystem)
        if snapped is None:
            self.note(f"no published version >= {floor} found in the registry; keeping the OSV fixed version {floor}")
            return floor
        if snapped != floor:
            deprecation = (info.deprecations or {}).get(floor)
            reason = f"deprecated on the registry: {deprecation}" if deprecation else "not published (yanked or missing)"
            self.note(f"fixed version {floor} is {reason}; using {snapped} instead")
        return snapped

    # -------------------------------------------------------------- step 3: OSV verification

    def _verify_loop(self, start: str) -> tuple[str, bool | None]:
        """Verify ``start``; bump to the next fixed version while OSV still reports vulnerabilities."""
        candidate = start
        for _ in range(MAX_VERIFY_ITERATIONS):
            result = self._check(candidate)
            if result.status == VulnerabilityStatus.UNKNOWN:
                self.result.osv_available = False
                self.note(f"{OSV_UNAVAILABLE_NOTE} ({result.reason or 'no reason given'})")
                return candidate, None
            if result.status == VulnerabilityStatus.SAFE:
                self.note(f"{candidate} verified safe against OSV")
                return candidate, True
            ids = sorted(rec.identifier for rec in result.vulnerabilities)
            self.result.remaining_vulnerabilities = ids
            next_floor = self._next_fixed(candidate, result.vulnerabilities)
            if next_floor is None:
                self.note(f"{candidate} is still affected by {', '.join(ids)} and no later fixed version is published")
                return candidate, False
            bumped = self._snap(next_floor)
            self.note(f"{candidate} is still affected by {', '.join(ids)}; bumped to {bumped}")
            candidate = bumped
        self.note(f"gave up after {MAX_VERIFY_ITERATIONS} verification rounds; {candidate} is not verified safe")
        return candidate, False

    def _check(self, version: str) -> PackageVulnerabilityResult:
        try:
            result = self.checker.check_package(self.ecosystem, self.name, version)
        except Exception as exc:  # noqa: BLE001 - never let a checker bug invent a verdict
            log.warning("OSV check crashed for %s %s %s: %s", self.ecosystem, self.name, version, exc)
            result = PackageVulnerabilityResult(
                query=PackageQuery(self.ecosystem, self.name, version),
                status=VulnerabilityStatus.UNKNOWN,
                reason=f"Vulnerability check unavailable: {exc}",
            )
        self.result.verification[version] = str(result.status)
        return result

    def _next_fixed(self, candidate: str, records: list[VulnerabilityRecord]) -> str | None:
        """Max over records of the smallest fixed version above ``candidate`` (None when none has one)."""
        floors: list[str] = []
        for rec in records:
            fixed = sort_versions(rec.fixed_versions_for(self.ecosystem, self.name), self.ecosystem)
            self.result.fixed_versions.setdefault(rec.identifier, fixed)
            above = [v for v in fixed if compare_versions(v, candidate, self.ecosystem) > 0]
            if above:
                floors.append(above[0])
        return sort_versions(floors, self.ecosystem)[-1] if floors else None

    # -------------------------------------------------------------- step 4: choice

    def _collect_safe(self, candidate: str, verified: bool | None) -> list[str]:
        """Versions among {candidate, latest in same major, latest} that may be proposed (ascending).

        With OSV available only versions it answered SAFE for are kept; with OSV
        down the candidate and the registry's latest versions are kept unverified.
        """
        res = self.result
        safe: list[str] = [candidate] if verified or verified is None else []
        for extra in (res.latest_in_same_major, res.latest_version):
            if extra is None or extra in safe or extra == candidate:
                continue
            if not self._above(extra, candidate):
                self.note(f"{extra} is below the minimum fixed version {candidate} and cannot be proposed")
                continue
            if verified is None:
                safe.append(extra)
                self.note(f"{extra} included unverified (OSV unavailable)")
                continue
            outcome = self._check(extra)
            if outcome.status == VulnerabilityStatus.SAFE:
                safe.append(extra)
                self.note(f"{extra} verified safe against OSV")
            elif outcome.status == VulnerabilityStatus.VULNERABLE:
                ids = ", ".join(sorted(rec.identifier for rec in outcome.vulnerabilities))
                self.note(f"{extra} excluded: still affected by {ids}")
            else:
                self.note(f"{extra} excluded: {OSV_UNAVAILABLE_NOTE}")
        return sort_versions(safe, self.ecosystem)

    def _above(self, version: str, floor: str) -> bool:
        try:
            return compare_versions(version, floor, self.ecosystem) > 0
        except InvalidVersionError:
            return False

    def _choose(self, candidate: str, verified: bool | None, safe: list[str]) -> None:
        """Fill ``preferred_version`` / ``allowed_versions`` / ``verified_safe`` / ``same_major``."""
        res = self.result
        if safe:
            preferred = self._lowest_in_current_major(safe) or safe[0]
            res.preferred_version = preferred
            res.allowed_versions = safe
            res.verified_safe = None if verified is None else True
            res.remaining_vulnerabilities = []
            if verified is None:
                self.note("allowed versions are unverified because OSV was unavailable")
            elif preferred != candidate:
                self.note(f"preferred {preferred} over {candidate}: lowest verified-safe version")
        else:
            # OSV answered and nothing verified safe: the best-effort candidate is still recorded
            # (with the vulnerabilities that remain) so the caller can decide; it is not "allowed".
            res.preferred_version = candidate
            res.allowed_versions = []
            res.verified_safe = False
        res.same_major = self._same_major(res.preferred_version)

    def _lowest_in_current_major(self, versions: list[str]) -> str | None:
        if self.current is None:
            return None
        major = major_of(self.current, self.ecosystem)
        same = [v for v in versions if major_of(v, self.ecosystem) == major]
        return same[0] if same else None

    def _same_major(self, version: str | None) -> bool | None:
        if version is None or self.current is None:
            return None
        a, b = major_of(version, self.ecosystem), major_of(self.current, self.ecosystem)
        return None if a is None or b is None else a == b

    # -------------------------------------------------------------- helpers

    def note(self, text: str) -> None:
        if text not in self.result.notes:
            self.result.notes.append(text)


def _parses(version: str | None, ecosystem: str) -> bool:
    if not version:
        return False
    try:
        parse_version(version, ecosystem)
        return True
    except InvalidVersionError:
        return False


def _unique_by_identifier(vulnerabilities: list[Vulnerability]) -> list[Vulnerability]:
    seen: set[str] = set()
    out: list[Vulnerability] = []
    for vuln in vulnerabilities:
        if vuln is None or vuln.identifier in seen:
            continue
        seen.add(vuln.identifier)
        out.append(vuln)
    return out


__all__ = ["MAX_VERIFY_ITERATIONS", "OSV_UNAVAILABLE_NOTE", "CandidateSet", "select_candidates"]
