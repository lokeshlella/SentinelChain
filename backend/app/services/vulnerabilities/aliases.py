"""Alias-group de-duplication of vulnerability records.

OSV returns the same vulnerability several times under different database
ids (e.g. ``GHSA-j8r2-6x86-q33q`` and ``PYSEC-2023-74`` both alias
``CVE-2023-32681``).  Records whose ids/aliases overlap are merged into one
canonical record so a dependency yields one finding per real vulnerability.

Canonical id preference: GHSA > CVE > everything else (PYSEC, OSV, ...).  The
merged record keeps every alias and the union of affected package data so no
fix information is lost.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from datetime import datetime, timezone

from app.core.versions import InvalidVersionError, compare_versions, normalize_package_name, sort_versions
from app.models.enums import Severity
from app.services.vulnerabilities.base import AffectedPackage, AffectedRange, VulnerabilityRecord

_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.UNKNOWN: 0,
}
_FAR_FUTURE = datetime.max.replace(tzinfo=timezone.utc)


def identifier_tier(identifier: str) -> int:
    """0 for GHSA ids, 1 for CVE ids, 2 for everything else (lower is preferred)."""
    upper = identifier.upper()
    if upper.startswith("GHSA-"):
        return 0
    if upper.startswith("CVE-"):
        return 1
    return 2


def severity_rank(severity: Severity | str) -> int:
    try:
        return _SEVERITY_RANK[Severity(severity)]
    except ValueError:
        return 0


def _primary_sort_key(record: VulnerabilityRecord) -> tuple:
    """Prefer GHSA > CVE > other, then scored records, then the oldest advisory, then the id."""
    published = record.published_at or _FAR_FUTURE
    if published.tzinfo is None:
        published = published.replace(tzinfo=timezone.utc)
    return (
        identifier_tier(record.identifier),
        0 if record.cvss_score is not None else 1,
        published,
        record.identifier,
    )


def package_key(ecosystem: str, package_name: str) -> tuple[str, str]:
    return ecosystem, normalize_package_name(package_name, ecosystem)


def _range_key(rng: AffectedRange) -> tuple:
    return (rng.range_type, rng.introduced, rng.fixed, rng.last_affected)


def merge_affected(*groups: Iterable[AffectedPackage]) -> list[AffectedPackage]:
    """Union of affected packages keyed by (ecosystem, normalised name).

    Ranges, explicit versions and fixed versions of entries for the same
    package are combined without duplicates; fixed versions stay sorted.
    """
    merged: dict[tuple[str, str], AffectedPackage] = {}
    for group in groups:
        for pkg in group:
            key = package_key(pkg.ecosystem, pkg.package_name)
            current = merged.get(key)
            if current is None:
                merged[key] = AffectedPackage(
                    ecosystem=pkg.ecosystem,
                    package_name=pkg.package_name,
                    ranges=[replace(r) for r in pkg.ranges],
                    versions=list(dict.fromkeys(pkg.versions)),
                    fixed_versions=list(dict.fromkeys(pkg.fixed_versions)),
                )
                continue
            known_ranges = {_range_key(r) for r in current.ranges}
            for rng in pkg.ranges:
                if _range_key(rng) not in known_ranges:
                    current.ranges.append(replace(rng))
                    known_ranges.add(_range_key(rng))
            current.versions.extend(v for v in pkg.versions if v not in current.versions)
            current.fixed_versions.extend(v for v in pkg.fixed_versions if v not in current.fixed_versions)
    for pkg in merged.values():
        safe = [v for v in pkg.fixed_versions if not _inside_other_range(v, pkg)]
        ordered = sort_versions(safe, pkg.ecosystem)
        ordered.extend(v for v in safe if v not in ordered)
        pkg.fixed_versions = ordered
    return list(merged.values())


def _inside_other_range(version: str, pkg: AffectedPackage) -> bool:
    """True when ``version`` is still affected by another range of the same package.

    After merging several advisories into one group, a version fixed by one
    advisory may still lie inside the affected range of another; such a
    version must not be advertised as a fix for the whole group.
    """
    for rng in pkg.ranges:
        if rng.fixed == version or not rng.introduced:
            continue
        try:
            after_intro = compare_versions(version, rng.introduced, pkg.ecosystem) >= 0
            before_fix = rng.fixed is None or compare_versions(version, rng.fixed, pkg.ecosystem) < 0
        except InvalidVersionError:
            continue
        if after_intro and before_fix:
            return True
    return False


def merge_group(records: list[VulnerabilityRecord]) -> VulnerabilityRecord:
    """Collapse records of one alias group into a single canonical record."""
    ordered = sorted(records, key=_primary_sort_key)
    primary = ordered[0]
    others = ordered[1:]

    alias_ids: list[str] = []
    for rec in ordered:
        for alias in [rec.identifier, *rec.aliases]:
            if alias != primary.identifier and alias not in alias_ids:
                alias_ids.append(alias)

    def first(attr: str):
        for rec in ordered:
            value = getattr(rec, attr)
            if value is not None:
                return value
        return None

    severity = primary.severity
    if severity == Severity.UNKNOWN:
        severity = max((rec.severity for rec in ordered), key=severity_rank, default=Severity.UNKNOWN)

    references: list[str] = []
    for rec in ordered:
        references.extend(url for url in rec.references if url not in references)

    # Score and vector must come from the same record: take the highest score in
    # the group (the group describes one issue; never under-report it).
    scored = [r for r in ordered if r.cvss_score is not None]
    cvss_source = max(scored, key=lambda r: r.cvss_score) if scored else next(
        (r for r in ordered if r.cvss_vector is not None), None
    )
    if cvss_source is not None and cvss_source.cvss_score is not None:
        severity = max((severity, cvss_source.severity), key=severity_rank)

    return VulnerabilityRecord(
        identifier=primary.identifier,
        source=primary.source,
        aliases=alias_ids,
        summary=first("summary"),
        description=first("description"),
        severity=severity,
        cvss_score=cvss_source.cvss_score if cvss_source else None,
        cvss_vector=cvss_source.cvss_vector if cvss_source else None,
        published_at=first("published_at"),
        modified_at=first("modified_at"),
        reference_url=first("reference_url"),
        references=references,
        affected=merge_affected(primary.affected, *(rec.affected for rec in others)),
    )


def group_by_alias(records: Iterable[VulnerabilityRecord]) -> list[list[VulnerabilityRecord]]:
    """Partition records into alias groups (union-find over ids and aliases)."""
    parent: dict[str, str] = {}

    def find(key: str) -> str:
        root = key
        while parent.setdefault(root, root) != root:
            root = parent[root]
        while parent[key] != root:  # path compression
            parent[key], key = root, parent[key]
        return root

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    # The same identifier can appear several times (e.g. one copy per queried
    # package, each filtered to that package); every copy joins the group so
    # that their affected data is merged rather than dropped.
    instances: dict[str, list[VulnerabilityRecord]] = {}
    cves_of_root: dict[str, set[str]] = {}

    def cves(rec: VulnerabilityRecord) -> set[str]:
        return {i for i in [rec.identifier, *rec.aliases] if i.upper().startswith("CVE-")}

    def safe_union(a: str, b: str, rec_cves: set[str]) -> None:
        # Two records that name DIFFERENT CVEs describe different issues even if
        # OSV cross-lists them as aliases; merging them would blend fixed versions.
        ra, rb = find(a), find(b)
        if ra == rb:
            return
        existing = cves_of_root.get(rb, set())
        if existing and rec_cves and existing != rec_cves:
            return
        union(a, b)
        cves_of_root[find(a)] = existing | rec_cves | cves_of_root.pop(ra, set())

    for rec in records:
        instances.setdefault(rec.identifier, []).append(rec)
        rec_cves = cves(rec)
        root = find(rec.identifier)
        cves_of_root[root] = cves_of_root.get(root, set()) | rec_cves
        for alias in rec.aliases:
            safe_union(rec.identifier, alias, rec_cves)

    groups: dict[str, list[VulnerabilityRecord]] = {}
    for identifier, copies in instances.items():
        groups.setdefault(find(identifier), []).extend(copies)
    return list(groups.values())


def canonical_records(records: Iterable[VulnerabilityRecord]) -> dict[str, VulnerabilityRecord]:
    """Map every input identifier to the merged canonical record of its alias group."""
    mapping: dict[str, VulnerabilityRecord] = {}
    for group in group_by_alias(records):
        merged = merge_group(group)
        for rec in group:
            mapping[rec.identifier] = merged
    return mapping


def deduplicate_records(records: list[VulnerabilityRecord]) -> list[VulnerabilityRecord]:
    """Merged records, one per alias group, in first-seen order."""
    mapping = canonical_records(records)
    out: list[VulnerabilityRecord] = []
    seen: set[str] = set()
    for rec in records:
        merged = mapping[rec.identifier]
        if merged.identifier not in seen:
            seen.add(merged.identifier)
            out.append(merged)
    return out
