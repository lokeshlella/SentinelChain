"""DependencyService: extractor orchestration, persistence snapshot, de-duplication, summary."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from sqlalchemy import select

from app.core.exceptions import RepositoryError, UnsupportedProjectError
from app.models import Analysis, Dependency, DependencyRelation, Repository
from app.models.enums import DependencyScope, Ecosystem, VulnerabilityStatus
from app.services.dependencies import (
    DependencyService,
    ExtractedDependency,
    ExtractedRelation,
    ExtractionResult,
    JavaScriptDependencyExtractor,
    PythonDependencyExtractor,
    get_extractors,
)
from app.services.dependencies.base import DependencyExtractor

FIXTURES = Path(__file__).parent / "fixtures" / "dependencies"


class BrokenExtractor(DependencyExtractor):
    """Simulates an extractor with a bug so the service's isolation can be tested."""

    ecosystem = Ecosystem.NPM

    def detect(self, repo_path: Path) -> list[Path]:
        return [repo_path / "package.json"]

    def extract(self, repo_path: Path) -> ExtractionResult:
        raise RuntimeError("boom")


@pytest.fixture
def service() -> DependencyService:
    return DependencyService()


@pytest.fixture
def repo_and_analysis(db):
    repository = Repository(name="fixture", source_url="/tmp/fixture", source_type="local")
    db.add(repository)
    db.flush()
    analysis = Analysis(repository_id=repository.repository_id, status="RUNNING")
    db.add(analysis)
    db.commit()
    return repository, analysis


def dep(name: str, version: str | None, *, source="requirements.txt", ecosystem=Ecosystem.PYPI, **kw) -> ExtractedDependency:
    return ExtractedDependency(package_name=name, ecosystem=ecosystem, source_file=source, version=version, **kw)


# ---------------------------------------------------------------- extractors
def test_default_extractors_cover_both_ecosystems(service):
    kinds = [type(e) for e in service.get_extractors()]
    assert kinds == [PythonDependencyExtractor, JavaScriptDependencyExtractor]
    assert [type(e) for e in get_extractors()] == kinds
    # get_extractors() returns a copy: mutating it does not change the service.
    service.get_extractors().clear()
    assert len(service.get_extractors()) == 2


def test_custom_extractors_are_used_as_given():
    only_python = DependencyService(extractors=[PythonDependencyExtractor()])
    assert [type(e) for e in only_python.get_extractors()] == [PythonDependencyExtractor]


# ------------------------------------------------------------------- extract
def test_extract_raises_unsupported_project_when_no_dependency_file_exists(service, tmp_path):
    (tmp_path / "README.md").write_text("# nothing to see\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.go").write_text("package main\n")
    with pytest.raises(UnsupportedProjectError) as excinfo:
        service.extract(tmp_path)
    assert "No supported dependency files" in excinfo.value.message
    assert "requirements.txt" in excinfo.value.message and "package.json" in excinfo.value.message
    assert excinfo.value.status_code == 422
    assert excinfo.value.details["repo_path"] == str(tmp_path.resolve())


def test_extract_rejects_missing_directory(service, tmp_path):
    with pytest.raises(RepositoryError):
        service.extract(tmp_path / "missing")


def test_extract_merges_every_ecosystem(service, tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.25.1\nDjango>=3.2,<4\n")
    (tmp_path / "package.json").write_text('{"dependencies": {"lodash": "4.17.21", "express": "^4.18.2"}}')
    result = service.extract(str(tmp_path))
    assert result.files == ["requirements.txt", "package.json"]
    assert {(d.package_name, d.ecosystem, d.version) for d in result.dependencies} == {
        ("requests", Ecosystem.PYPI, "2.25.1"),
        ("Django", Ecosystem.PYPI, None),
        ("lodash", Ecosystem.NPM, "4.17.21"),
        ("express", Ecosystem.NPM, None),
    }
    assert service.summarize(result) == {
        "total": 4,
        "by_ecosystem": {"PyPI": 2, "npm": 2},
        "direct": 2,
        "transitive": 0,
        "unknown_scope": 2,
        "pinned": 2,
        "unpinned": 2,
        "files": ["requirements.txt", "package.json"],
        "warnings": [],
    }


def test_extract_with_only_one_ecosystem_present_is_fine(service, tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==3.0.3\n")
    result = service.extract(tmp_path)
    assert [d.package_name for d in result.dependencies] == ["flask"]


def test_extract_javascript_repo_with_malformed_workspaces_is_supported(service, tmp_path):
    """A hostile/odd ``workspaces`` list must not turn a valid package.json into a 422."""
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "r", "workspaces": [".", "", "./", "/abs", "../x", "**/*", None], "dependencies": {"a": "1.0.0"},
    }))
    result = service.extract(tmp_path)
    assert result.files == ["package.json"]
    assert [(d.package_name, d.version, d.scope) for d in result.dependencies] == [("a", "1.0.0", DependencyScope.DIRECT)]
    assert not any("detection failed" in w for w in result.warnings)


def test_extract_never_reads_host_files_through_symlinks(service, tmp_path):
    """``requirements.txt -> /etc/passwd`` in a hostile repository must not leak host data into warnings."""
    host_file = tmp_path / "host" / "passwd"
    host_file.parent.mkdir()
    host_file.write_text("root:*:0:0:System Administrator:/var/root:/bin/sh\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    try:
        os.symlink(host_file, repo / "requirements.txt")
        os.symlink(host_file, repo / "package-lock.json")
    except (OSError, NotImplementedError):  # pragma: no cover
        pytest.skip("symlinks are not supported on this platform")
    with pytest.raises(UnsupportedProjectError):  # the symlink is not a dependency file of this repository
        service.extract(repo)
    (repo / "package.json").write_text('{"dependencies": {"a": "^1.0.0"}}')
    result = service.extract(repo)
    assert result.files == ["package.json"]
    assert not any("System Administrator" in w or "root:" in w for w in result.warnings)


def test_extract_isolates_a_crashing_extractor(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==3.0.3\n")
    (tmp_path / "package.json").write_text("{}")
    service = DependencyService(extractors=[PythonDependencyExtractor(), BrokenExtractor()])
    result = service.extract(tmp_path)
    assert [d.package_name for d in result.dependencies] == ["flask"]
    assert any(w.startswith("BrokenExtractor: extraction failed (boom)") for w in result.warnings)


# ------------------------------------------------------------------- persist
def test_persist_javascript_snapshot_with_relations(db, service, repo_and_analysis):
    repository, analysis = repo_and_analysis
    result = service.extract(FIXTURES / "js_project")
    rows = service.persist(db, repository, analysis, result)

    assert len(rows) == 21 == len(result.dependencies)
    stored = db.scalars(select(Dependency).where(Dependency.analysis_id == analysis.analysis_id)).all()
    assert len(stored) == 21
    assert all(r.repository_id == repository.repository_id for r in stored)
    assert {r.vulnerability_status for r in stored} == {VulnerabilityStatus.UNCHECKED}
    assert all(r.status_reason is None and r.last_checked_at is None for r in stored)
    assert {r.ecosystem for r in stored} == {"npm"}

    by_key = {(r.package_name, r.version, r.source_file): r for r in stored}
    send = by_key[("send", "0.18.0", "package.json")]
    assert (send.direct_or_transitive, send.version_spec) == (DependencyScope.DIRECT, "~0.18.0")
    assert by_key[("ms", "2.1.3", "package-lock.json")].direct_or_transitive == DependencyScope.TRANSITIVE
    assert by_key[("ms", "2.0.0", "package-lock.json")].dependency_id != by_key[("ms", "2.1.2", "package-lock.json")].dependency_id
    assert by_key[("local-lib", None, "package.json")].version_spec == "file:../local-lib"

    relations = db.scalars(select(DependencyRelation)).all()
    assert len(relations) == 13 == len(result.relations)
    ids = {r.dependency_id: r for r in stored}
    edges = {
        (ids[r.parent_dependency_id].package_name, ids[r.parent_dependency_id].version,
         ids[r.child_dependency_id].package_name, ids[r.child_dependency_id].version)
        for r in relations
    }
    assert ("send", "0.18.0", "ms", "2.1.3") in edges
    assert ("debug", "2.6.9", "ms", "2.0.0") in edges
    assert ("debug", "4.3.4", "ms", "2.1.2") in edges
    assert ("my-fork", None, "ms", "2.0.0") in edges  # version-less parent still resolves
    assert {r.relation_type for r in relations} == {"depends_on"}


def test_persist_dedupes_normalised_identities(db, service, repo_and_analysis):
    repository, analysis = repo_and_analysis
    result = service.extract(FIXTURES / "python_project")
    assert len(result.dependencies) == 18  # SQLAlchemy and sqlalchemy both extracted
    rows = service.persist(db, repository, analysis, result)
    assert len(rows) == 17
    names = [r.package_name for r in rows if r.package_name.lower() == "sqlalchemy"]
    assert names == ["SQLAlchemy"]  # first spelling wins, kept as written
    assert {r.direct_or_transitive for r in rows} == {DependencyScope.UNKNOWN}
    assert db.scalar(select(Dependency.version_spec).where(Dependency.package_name == "foo")) == '[extra]==1.0 ; python_version<"3.9"'


def test_persist_keeps_distinct_identities_apart(db, service, repo_and_analysis):
    repository, analysis = repo_and_analysis
    result = ExtractionResult(
        dependencies=[
            dep("requests", "2.25.1"),
            dep("Requests", "2.25.1"),  # same identity (normalised name)
            dep("requests", "2.31.0"),  # different version
            dep("requests", "2.25.1", source="requirements-dev.txt"),  # different file
            dep("requests", None),  # unknown version is its own identity
            dep("requests", None),
            dep("requests", "2.25.1", ecosystem=Ecosystem.NPM, source="package.json"),  # different ecosystem
        ],
        files=["requirements.txt", "requirements-dev.txt", "package.json"],
    )
    rows = service.persist(db, repository, analysis, result)
    assert len(rows) == 5
    assert db.scalar(select(Dependency).where(Dependency.package_name == "Requests")) is None


def test_persist_skips_unresolved_and_duplicate_relations(db, service, repo_and_analysis):
    repository, analysis = repo_and_analysis
    result = ExtractionResult(
        dependencies=[
            dep("a", "1.0.0", ecosystem=Ecosystem.NPM, source="package-lock.json"),
            dep("B", "2.0.0", ecosystem=Ecosystem.NPM, source="package-lock.json"),
            dep("c", None, ecosystem=Ecosystem.NPM, source="package.json"),
        ],
        relations=[
            ExtractedRelation("a", "1.0.0", "B", "2.0.0", Ecosystem.NPM),
            ExtractedRelation("a", "1.0.0", "B", "2.0.0", Ecosystem.NPM),  # duplicate edge
            ExtractedRelation("a", "1.0.0", "B", "9.9.9", Ecosystem.NPM),  # unknown child version
            ExtractedRelation("ghost", "1.0.0", "B", "2.0.0", Ecosystem.NPM),  # unknown parent
            ExtractedRelation("a", "1.0.0", "a", "1.0.0", Ecosystem.NPM),  # self loop
            ExtractedRelation("a", "1.0.0", "c", None, Ecosystem.NPM),  # version-less child
            ExtractedRelation("a", "1.0.0", "B", "2.0.0", Ecosystem.PYPI),  # wrong ecosystem
        ],
    )
    rows = service.persist(db, repository, analysis, result)
    ids = {r.package_name: r.dependency_id for r in rows}
    relations = db.scalars(select(DependencyRelation)).all()
    assert {(r.parent_dependency_id, r.child_dependency_id) for r in relations} == {
        (ids["a"], ids["B"]),
        (ids["a"], ids["c"]),
    }


def test_persist_is_idempotent_for_an_analysis(db, service, repo_and_analysis):
    repository, analysis = repo_and_analysis
    result = service.extract(FIXTURES / "js_v1_project")
    first = service.persist(db, repository, analysis, result)
    second = service.persist(db, repository, analysis, result)
    assert len(first) == len(second) == 6
    assert db.scalar(select(Dependency).where(Dependency.analysis_id == analysis.analysis_id).limit(1)) is not None
    assert len(db.scalars(select(Dependency)).all()) == 6
    assert len(db.scalars(select(DependencyRelation)).all()) == 5


def test_persist_snapshots_are_per_analysis(db, service, repo_and_analysis):
    repository, analysis = repo_and_analysis
    second_analysis = Analysis(repository_id=repository.repository_id, status="RUNNING")
    db.add(second_analysis)
    db.commit()
    result = ExtractionResult(dependencies=[dep("flask", "3.0.3")])
    service.persist(db, repository, analysis, result)
    service.persist(db, repository, second_analysis, result)
    rows = db.scalars(select(Dependency).where(Dependency.package_name == "flask")).all()
    assert sorted(r.analysis_id for r in rows) == sorted([analysis.analysis_id, second_analysis.analysis_id])


def test_persist_truncates_overlong_specs(db, service, repo_and_analysis):
    repository, analysis = repo_and_analysis
    result = ExtractionResult(dependencies=[dep("x", None, version_spec=">=1," * 200)])
    rows = service.persist(db, repository, analysis, result)
    assert len(rows[0].version_spec) == 255


# ----------------------------------------------------------------- summarize
def test_summarize_counts_scopes_and_pins(service):
    result = ExtractionResult(
        dependencies=[
            dep("a", "1.0"),
            dep("b", None),
            dep("c", "2.0", ecosystem=Ecosystem.NPM, source="package.json", scope=DependencyScope.DIRECT),
            dep("d", "3.0", ecosystem=Ecosystem.NPM, source="package-lock.json", scope=DependencyScope.TRANSITIVE),
            dep("e", None, ecosystem=Ecosystem.NPM, source="package.json", scope=DependencyScope.DIRECT),
        ],
        files=["requirements.txt", "package.json", "package-lock.json"],
        warnings=["package.json: something"],
    )
    summary = service.summarize(result)
    assert summary == {
        "total": 5,
        "by_ecosystem": {"PyPI": 2, "npm": 3},
        "direct": 2,
        "transitive": 1,
        "unknown_scope": 2,
        "pinned": 3,
        "unpinned": 2,
        "files": ["requirements.txt", "package.json", "package-lock.json"],
        "warnings": ["package.json: something"],
    }


def test_summarize_empty_result(service):
    assert service.summarize(ExtractionResult())["total"] == 0
    assert service.summarize(ExtractionResult())["by_ecosystem"] == {}


def test_overlong_names_that_collide_after_truncation_persist_once(db, service, repo_and_analysis):
    """Two identities that only differ beyond the column width must not raise IntegrityError."""
    repo, analysis = repo_and_analysis
    result = ExtractionResult(
        dependencies=[
            dep("a" * 300 + "x", "1.0.0", source="package.json", ecosystem=Ecosystem.NPM),
            dep("a" * 300 + "y", "1.0.0", source="package.json", ecosystem=Ecosystem.NPM),
        ]
    )
    rows = service.persist(db, repo, analysis, result)
    assert len(rows) == 1 and len(rows[0].package_name) == 255
