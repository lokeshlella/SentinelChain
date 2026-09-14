"""A small synthetic repository persisted in the SQLite test database.

Shape (mirrors what the pipeline hands to ``KnowledgeGraphService.sync_analysis``):

* components ``src`` and ``tests``
* dependencies ``requests==2.28.2`` (listed twice: requirements.txt + requirements-dev.txt,
  which must collapse to ONE graph node), ``urllib3==1.26.15`` and ``flask`` (unpinned)
* relation ``requests -> urllib3``
* one real advisory affecting ``requests 2.28.2`` (values as published by OSV/GitHub)
* usage: ``requests`` referenced from ``src`` and ``tests``, ``urllib3`` from ``src``
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from app.models import Analysis, Component, Dependency, DependencyRelation, Repository, Vulnerability

# GHSA-j8r2-6x86-q33q / CVE-2023-32681 - requests < 2.31.0 leaks Proxy-Authorization headers.
ADVISORY_ID = "GHSA-j8r2-6x86-q33q"
ADVISORY = {
    "identifier": ADVISORY_ID,
    "source": "osv",
    "aliases": ["CVE-2023-32681"],
    "severity": "MEDIUM",
    "cvss_score": 6.1,
    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "summary": "Unintended leak of Proxy-Authorization header in requests",
    "reference_url": "https://github.com/psf/requests/security/advisories/GHSA-j8r2-6x86-q33q",
    "affected": [{"ecosystem": "PyPI", "package_name": "requests", "fixed_versions": ["2.31.0"]}],
}


@dataclass
class GraphFixture:
    repository: Repository
    analysis: Analysis
    components: list[Component]
    dependencies: dict[str, Dependency]
    relations: list[DependencyRelation]
    vulnerability: Vulnerability
    extra_component_usage: dict[int, list[str]] = field(default_factory=dict)

    @property
    def dependency_list(self) -> list[Dependency]:
        return list(self.dependencies.values())

    def dep_vulns(self) -> dict[int, list[Vulnerability]]:
        return {
            self.dependencies["requests"].dependency_id: [self.vulnerability],
            self.dependencies["requests_dev"].dependency_id: [self.vulnerability],
        }

    def component_usage(self) -> dict[int, list[str]]:
        usage = {
            self.dependencies["requests"].dependency_id: ["src", "tests"],
            self.dependencies["urllib3"].dependency_id: ["src"],
        }
        usage.update(self.extra_component_usage)
        return usage


def build_graph_fixture(db: Session, repository_id: int | None = None, name: str = "sentinel-demo") -> GraphFixture:
    repository = Repository(
        name=name,
        source_url=f"https://github.com/example/{name}",
        source_type="github",
        language="Python",
    )
    if repository_id is not None:
        repository.repository_id = repository_id
    db.add(repository)
    db.flush()

    analysis = Analysis(repository_id=repository.repository_id, status="RUNNING")
    db.add(analysis)
    db.flush()

    components = [
        Component(repository_id=repository.repository_id, name="src", path="src", component_type="source", file_count=4),
        Component(repository_id=repository.repository_id, name="tests", path="tests", component_type="tests", file_count=2),
    ]
    db.add_all(components)

    def dep(package: str, version: str | None, source_file: str, scope: str, status: str, spec: str | None = None):
        row = Dependency(
            repository_id=repository.repository_id,
            analysis_id=analysis.analysis_id,
            package_name=package,
            version=version,
            version_spec=spec,
            ecosystem="PyPI",
            direct_or_transitive=scope,
            source_file=source_file,
            vulnerability_status=status,
        )
        db.add(row)
        return row

    dependencies = {
        "requests": dep("requests", "2.28.2", "requirements.txt", "direct", "VULNERABLE", "==2.28.2"),
        "requests_dev": dep("requests", "2.28.2", "requirements-dev.txt", "unknown", "VULNERABLE", "==2.28.2"),
        "urllib3": dep("urllib3", "1.26.15", "requirements.txt", "transitive", "SAFE", "==1.26.15"),
        "flask": dep("flask", None, "requirements.txt", "unknown", "UNKNOWN", ">=2.0"),
    }
    db.flush()

    relations = [
        DependencyRelation(
            parent_dependency_id=dependencies["requests"].dependency_id,
            child_dependency_id=dependencies["urllib3"].dependency_id,
        )
    ]
    db.add_all(relations)

    vulnerability = Vulnerability(**ADVISORY)
    db.add(vulnerability)
    db.commit()

    return GraphFixture(
        repository=repository,
        analysis=analysis,
        components=components,
        dependencies=dependencies,
        relations=relations,
        vulnerability=vulnerability,
    )
