"""Vulnerability detection stage (OSV.dev in V1).

Public surface:

* ``base``          — provider contract and result dataclasses
* ``cvss``          — CVSS v3.x base score + severity banding
* ``osv_provider``  — ``OSVProvider`` (real OSV.dev integration)
* ``service``       — ``VulnerabilityService`` / ``VulnerabilityCheckSummary``
"""

from app.services.vulnerabilities.base import (
    AffectedPackage,
    AffectedRange,
    PackageQuery,
    PackageVulnerabilityResult,
    VulnerabilityProvider,
    VulnerabilityProviderError,
    VulnerabilityRecord,
)
from app.services.vulnerabilities.cvss import cvss_v3_base_score, severity_from_score
from app.services.vulnerabilities.osv_provider import OSVProvider
from app.services.vulnerabilities.service import (
    VulnerabilityCheckSummary,
    VulnerabilityService,
    provisional_risk_level,
)

__all__ = [
    "AffectedPackage",
    "AffectedRange",
    "OSVProvider",
    "PackageQuery",
    "PackageVulnerabilityResult",
    "VulnerabilityCheckSummary",
    "VulnerabilityProvider",
    "VulnerabilityProviderError",
    "VulnerabilityRecord",
    "VulnerabilityService",
    "cvss_v3_base_score",
    "provisional_risk_level",
    "severity_from_score",
]
