"""Real OSV.dev round trip (run with SENTINEL_INTEGRATION=1)."""

from __future__ import annotations

import pytest

from app.models.enums import VulnerabilityStatus
from app.services.vulnerabilities.base import PackageQuery
from app.services.vulnerabilities.osv_provider import OSVProvider

pytestmark = pytest.mark.integration


def test_real_osv_reports_requests_2_25_1_with_fixed_version() -> None:
    provider = OSVProvider()
    try:
        ok, detail = provider.health()
        assert ok, detail

        query = PackageQuery("PyPI", "requests", "2.25.1")
        single = provider.query(query)
        assert single.status is VulnerabilityStatus.VULNERABLE, single.reason
        with_fix = [r for r in single.vulnerabilities if r.fixed_versions_for("PyPI", "requests")]
        assert with_fix, "expected at least one advisory with a fixed version"
        # CVE-2023-32681 (Proxy-Authorization leak) is fixed in 2.31.0 and affects 2.25.1.
        ids_and_aliases = {a for r in single.vulnerabilities for a in [r.identifier, *r.aliases]}
        assert "CVE-2023-32681" in ids_and_aliases
        assert any("2.31.0" in r.fixed_versions_for("PyPI", "requests") for r in with_fix)
        assert all(all(p.package_name == "requests" for p in r.affected) for r in single.vulnerabilities)

        batch = provider.query_batch([query, PackageQuery("PyPI", "six", "1.16.0")])
        assert batch[0].status is VulnerabilityStatus.VULNERABLE
        assert {r.identifier for r in batch[0].vulnerabilities} == {r.identifier for r in single.vulnerabilities}
        assert batch[1].status is VulnerabilityStatus.SAFE, batch[1].reason
    finally:
        provider.close()
