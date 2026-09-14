"""Fake collaborators shared by the API and pipeline tests (no network, no Docker, no Neo4j, no Ollama)."""

from __future__ import annotations

from pathlib import Path

from app.models.enums import Severity, VulnerabilityStatus
from app.services.agents.schemas import GraphContext
from app.services.knowledge_graph.service import GraphSyncResult
from app.services.vulnerabilities.base import (
    AffectedPackage,
    AffectedRange,
    PackageQuery,
    PackageVulnerabilityResult,
    VulnerabilityProvider,
    VulnerabilityRecord,
)


def make_demo_repo(root: Path) -> Path:
    """A tiny Python + JS project with one import of ``requests``."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "requirements.txt").write_text("requests==2.25.1\nflask>=2\n")
    (root / "package.json").write_text('{"name": "demo", "dependencies": {"lodash": "4.17.15"}}\n')
    src = root / "src" / "app"
    src.mkdir(parents=True)
    (src / "__init__.py").write_text("")
    (src / "client.py").write_text("import requests\n\ndef get(url):\n    return requests.get(url)\n")
    tests = root / "tests"
    tests.mkdir()
    (tests / "test_client.py").write_text("def test_nothing():\n    assert True\n")
    return root


def requests_record() -> VulnerabilityRecord:
    return VulnerabilityRecord(
        identifier="GHSA-j8r2-6x86-q33q",
        source="osv",
        aliases=["CVE-2023-32681"],
        summary="Unintended leak of Proxy-Authorization header in requests",
        description="Requests leaks Proxy-Authorization headers to destination servers when redirected.",
        severity=Severity.MEDIUM,
        cvss_score=6.1,
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        reference_url="https://github.com/psf/requests/security/advisories/GHSA-j8r2-6x86-q33q",
        affected=[
            AffectedPackage(
                ecosystem="PyPI",
                package_name="requests",
                ranges=[AffectedRange(range_type="ECOSYSTEM", introduced="2.3.0", fixed="2.31.0")],
                fixed_versions=["2.31.0"],
            )
        ],
    )


class FakeVulnerabilityProvider(VulnerabilityProvider):
    name = "fake"

    def __init__(self, *, vulnerable: dict[tuple[str, str], list[VulnerabilityRecord]] | None = None, available: bool = True):
        self.vulnerable = vulnerable if vulnerable is not None else {("PyPI", "requests"): [requests_record()]}
        self.available = available

    def query(self, query: PackageQuery) -> PackageVulnerabilityResult:
        if not self.available:
            return PackageVulnerabilityResult(query=query, status=VulnerabilityStatus.UNKNOWN, reason="Vulnerability check unavailable: fake outage")
        records = self.vulnerable.get((query.ecosystem, query.package_name), [])
        status = VulnerabilityStatus.VULNERABLE if records else VulnerabilityStatus.SAFE
        return PackageVulnerabilityResult(query=query, status=status, vulnerabilities=list(records))

    def query_batch(self, queries: list[PackageQuery]) -> list[PackageVulnerabilityResult]:
        return [self.query(q) for q in queries]

    def health(self) -> tuple[bool, str]:
        return self.available, "fake"


class FakeGraphService:
    """Stands in for KnowledgeGraphService; records what was synced."""

    def __init__(self, available: bool = True):
        self._available = available
        self.synced: list[dict] = []

    def available(self) -> bool:
        return self._available

    def sync_analysis(self, repository, components, dependencies, relations, dep_vulns, component_usage, *, preserve_unknown_vulnerability_edges=False):
        if not self._available:
            return GraphSyncResult(available=False, error=None)
        self.synced.append({
            "dependencies": len(dependencies), "vulnerable": len(dep_vulns), "usage": dict(component_usage),
            "preserve": preserve_unknown_vulnerability_edges,
        })
        return GraphSyncResult(
            available=True, nodes_written=len(dependencies) + len(components) + 1, relationships_written=len(dependencies),
            preserved_unknown_edges=preserve_unknown_vulnerability_edges,
        )

    def dependency_context(self, dep) -> GraphContext:
        if not self._available:
            return GraphContext(available=False)
        return GraphContext(available=True, components_using=["src"], vulnerabilities=["GHSA-j8r2-6x86-q33q"])

    def remove_repository(self, repository_id: int) -> int:
        return 0

    def repository_graph(self, repository_id: int, limit: int = 500) -> dict:
        return {"nodes": [], "edges": []}

    def components_using_dependency(self, dep):
        return []

    def related_dependencies(self, dep):
        return {"depends_on": [], "depended_on_by": []}

    def vulnerabilities_for_dependency(self, dep):
        return []

    def dependency_paths(self, dep, max_depth: int = 4, limit: int = 25):
        return []
