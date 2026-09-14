"""Vulnerability provider contract (OSV in V1; GHSA / NVD later)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import ClassVar

from app.models.enums import Severity, VulnerabilityStatus


@dataclass(frozen=True)
class PackageQuery:
    ecosystem: str  # "PyPI" | "npm"
    package_name: str
    version: str


@dataclass
class AffectedRange:
    range_type: str  # ECOSYSTEM | SEMVER | GIT
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None


@dataclass
class AffectedPackage:
    ecosystem: str
    package_name: str
    ranges: list[AffectedRange] = field(default_factory=list)
    versions: list[str] = field(default_factory=list)  # explicit affected versions when listed
    fixed_versions: list[str] = field(default_factory=list)  # derived from ranges

    def to_dict(self) -> dict:
        return {
            "ecosystem": self.ecosystem,
            "package_name": self.package_name,
            "ranges": [r.__dict__ for r in self.ranges],
            "versions": self.versions,
            "fixed_versions": self.fixed_versions,
        }


@dataclass
class VulnerabilityRecord:
    identifier: str  # e.g. GHSA-xxxx, PYSEC-xxxx, CVE-xxxx
    source: str  # provider name, e.g. "osv"
    aliases: list[str] = field(default_factory=list)
    summary: str | None = None
    description: str | None = None
    severity: Severity = Severity.UNKNOWN
    cvss_score: float | None = None
    cvss_vector: str | None = None
    published_at: datetime | None = None
    modified_at: datetime | None = None
    reference_url: str | None = None
    references: list[str] = field(default_factory=list)
    affected: list[AffectedPackage] = field(default_factory=list)

    def fixed_versions_for(self, ecosystem: str, package_name: str) -> list[str]:
        from app.core.versions import normalize_package_name

        wanted = normalize_package_name(package_name, ecosystem)
        out: list[str] = []
        for pkg in self.affected:
            if pkg.ecosystem == ecosystem and normalize_package_name(pkg.package_name, ecosystem) == wanted:
                out.extend(pkg.fixed_versions)
        return out


@dataclass
class PackageVulnerabilityResult:
    query: PackageQuery
    status: VulnerabilityStatus  # SAFE | VULNERABLE | UNKNOWN
    vulnerabilities: list[VulnerabilityRecord] = field(default_factory=list)
    reason: str | None = None  # populated when status is UNKNOWN (e.g. "Vulnerability check unavailable")


class VulnerabilityProviderError(Exception):
    """Raised when the provider is unreachable / returned malformed data."""


class VulnerabilityProvider(ABC):
    name: ClassVar[str]

    @abstractmethod
    def query(self, query: PackageQuery) -> PackageVulnerabilityResult:
        """Query one package version. Must return status UNKNOWN (never SAFE) when the check could not run."""

    @abstractmethod
    def query_batch(self, queries: list[PackageQuery]) -> list[PackageVulnerabilityResult]:
        """Query many package versions; result order matches ``queries``."""

    @abstractmethod
    def health(self) -> tuple[bool, str]:
        """(reachable, detail) — used by the health endpoint and stage status."""
