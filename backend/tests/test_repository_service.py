"""RepositoryService with the SQLite ``db`` fixture, the real local provider and an offline GitHub provider."""

from __future__ import annotations

import json
from pathlib import Path

import git
import pytest
from sqlalchemy import select

from app.core.config import Settings
from app.core.exceptions import ConflictError, NotFoundError, RepositoryError, ValidationFailedError
from app.models import Component, Repository
from app.models.enums import ComponentType, SourceType
from app.services.repository.base import FetchedRepository, RepositoryProvider, RepositorySource
from app.services.repository.github_provider import GitHubRepositoryProvider
from app.services.repository.local_provider import LocalRepositoryProvider
from app.services.repository.service import RepositoryService


def write(path: Path, content: str = "") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(_env_file=None, repository_workspace=str(tmp_path / "ws"), github_token=None)


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "demo-project"
    write(root / "README.md", "# demo\n")
    write(root / "requirements.txt", "flask==2.0.0\n")
    write(root / "app" / "main.py", "from flask import Flask\n")
    write(root / "tests" / "test_main.py", "def test_ok(): pass\n")
    write(root / "docs" / "index.md", "# docs\n")
    write(root / "node_modules" / "x" / "index.js", "// ignored\n")
    return root


@pytest.fixture
def service(db, settings) -> RepositoryService:
    return RepositoryService(db, settings)


@pytest.fixture
def bare_remote(tmp_path: Path) -> dict:
    """Bare repository whose default branch is ``main``; ``dev`` has one extra commit."""
    work = tmp_path / "upstream"
    repo = git.Repo.init(work, initial_branch="main")
    with repo.config_writer() as cfg:
        cfg.set_value("user", "email", "tests@example.com")
        cfg.set_value("user", "name", "Sentinel Tests")
    write(work / "package.json", json.dumps({"name": "hello", "dependencies": {"lodash": "4.17.15"}}))
    write(work / "src" / "index.js", "const _ = require('lodash');\n")
    repo.git.add("--all")
    sha = repo.index.commit("initial").hexsha
    repo.git.checkout("-b", "dev")
    write(work / "src" / "dev.js", "export const DEV = true;\n")
    repo.git.add("--all")
    dev_sha = repo.index.commit("dev work").hexsha
    repo.git.checkout("main")
    bare = tmp_path / "remote.git"
    git.Repo.clone_from(work, bare, bare=True)
    return {"path": bare, "sha": sha, "dev_sha": dev_sha}


@pytest.fixture
def github_service(db, settings, bare_remote, monkeypatch) -> RepositoryService:
    """Service with a real GitHub provider whose clone/ls-remote URL points at the bare repository."""
    github = GitHubRepositoryProvider(settings)
    monkeypatch.setattr(github, "_clone_url", lambda parsed: (str(bare_remote["path"]), False))
    return RepositoryService(db, settings, providers=[github, LocalRepositoryProvider(settings)])


class ExplodingProvider(RepositoryProvider):
    """Validates fine but fails while fetching (simulates an inaccessible repository)."""

    source_type = SourceType.GITHUB

    def supports(self, location: str) -> bool:
        return location.startswith("https://github.com/")

    def validate(self, source: RepositorySource) -> None:
        return None

    def fetch(self, source: RepositorySource, destination: Path) -> FetchedRepository:
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "partial").write_text("half a clone")
        raise RepositoryError("Repository not found or not accessible: " + source.location)


# ---------------------------------------------------------------------------- register


def test_register_local_project_ingests_profile_and_components(service, db, settings, project):
    repository = service.register(str(project))

    assert repository.repository_id is not None
    assert repository.name == "demo-project"
    assert repository.source_type == SourceType.LOCAL
    assert repository.source_url == str(project.resolve())
    assert repository.branch is None
    assert repository.commit_sha is None
    assert repository.language == "Python"
    # stored relative to the workspace (audit F-10), resolved against this instance's workspace
    assert repository.local_path == f"repos/{repository.repository_id}"
    local = service.local_path_of(repository)
    assert local == settings.workspace_path / "repos" / str(repository.repository_id)
    assert local.is_dir()
    assert (local / "app" / "main.py").exists()
    assert not (local / "node_modules").exists()

    assert repository.profile["name"] == "demo-project"
    assert repository.profile["dependency_files"] == ["requirements.txt"]
    assert repository.profile["hints"]["has_pytest"] is True
    assert repository.profile["total_files"] == 5

    rows = db.scalars(select(Component).where(Component.repository_id == repository.repository_id)).all()
    by_path = {row.path: row for row in rows}
    assert set(by_path) == {"app", "docs", "tests"}
    assert by_path["app"].component_type == ComponentType.SOURCE
    assert by_path["app"].file_count == 1
    assert by_path["tests"].component_type == ComponentType.TESTS
    assert by_path["docs"].description == "Documentation directory (1 file)"

    profile = service.profile_of(repository)
    assert profile.component_paths == ["app", "docs", "tests"]


def test_register_detects_source_type_or_accepts_explicit_one(service, project):
    explicit = service.register(str(project), source_type="local")
    assert explicit.source_type == SourceType.LOCAL
    with pytest.raises(ValidationFailedError, match="source_type"):
        service.register(str(project), source_type="svn")
    with pytest.raises(RepositoryError, match="does not exist"):
        service.register("/definitely/not/here", source_type=SourceType.LOCAL)


def test_register_rejects_unsupported_locations(service, db, tmp_path):
    for location in ("", "   ", "https://gitlab.com/o/r", "/nowhere/at/all", "not a url"):
        with pytest.raises(ValidationFailedError):
            service.register(location)
    assert db.scalars(select(Repository)).all() == []
    assert not (tmp_path / "ws" / "repos").exists() or not any((tmp_path / "ws" / "repos").iterdir())


def test_register_same_source_twice_conflicts(service, project):
    first = service.register(str(project))
    with pytest.raises(ConflictError) as excinfo:
        service.register(str(project))
    assert excinfo.value.details["repository_id"] == first.repository_id
    with pytest.raises(ConflictError):
        service.register(f"{project}/")  # normalised to the same path
    assert len(service.list()) == 1


def test_register_failure_leaves_nothing_behind(db, settings, tmp_path):
    service = RepositoryService(db, settings, providers=[ExplodingProvider()])
    with pytest.raises(RepositoryError, match="not accessible"):
        service.register("https://github.com/octocat/Missing")
    assert db.scalars(select(Repository)).all() == []
    repos_dir = settings.workspace_path / "repos"
    assert not repos_dir.exists() or list(repos_dir.iterdir()) == []


def test_register_github_offline_via_bare_remote(github_service, bare_remote):
    service = github_service

    repository = service.register("git@github.com:octocat/Hello-World.git")
    assert repository.source_type == SourceType.GITHUB
    assert repository.source_url == "https://github.com/octocat/Hello-World"
    assert repository.name == "Hello-World"
    assert repository.branch == "main"
    assert repository.commit_sha == bare_remote["sha"]
    assert repository.language == "JavaScript"
    assert repository.profile["name"] == "hello"
    assert (github_service.local_path_of(repository) / ".git").is_dir()

    # duplicates are detected on the canonical URL, whatever form the user typed
    with pytest.raises(ConflictError):
        service.register("https://github.com/octocat/Hello-World.git")
    with pytest.raises(ConflictError):
        service.register("https://github.com/octocat/Hello-World", branch="main")
    # another branch of the same repository is a different registration (fails here: branch missing)
    with pytest.raises(RepositoryError, match="Branch 'nope' not found"):
        service.register("https://github.com/octocat/Hello-World", branch="nope")
    assert len(service.list()) == 1


def test_register_default_branch_after_a_named_branch(github_service, bare_remote):
    """Regression: a row for branch ``dev`` used to block registering the default branch."""
    dev = github_service.register("https://github.com/octocat/Hello-World", branch="dev")
    assert dev.branch == "dev" and dev.commit_sha == bare_remote["dev_sha"]

    default = github_service.register("https://github.com/octocat/Hello-World")
    assert default.repository_id != dev.repository_id
    assert default.branch == "main" and default.commit_sha == bare_remote["sha"]
    assert not (github_service.local_path_of(default) / "src" / "dev.js").exists()
    assert github_service.local_path_of(dev).is_dir(), "the dev registration is untouched"

    # both registrations now exist, so each of them is a duplicate of itself only
    with pytest.raises(ConflictError) as excinfo:
        github_service.register("https://github.com/octocat/Hello-World")
    assert excinfo.value.details == {"repository_id": default.repository_id, "branch": "main"}
    with pytest.raises(ConflictError) as excinfo:
        github_service.register("https://github.com/octocat/Hello-World/tree/dev")
    assert excinfo.value.details == {"repository_id": dev.repository_id, "branch": "dev"}
    assert len(github_service.list()) == 2


def test_register_named_branch_after_the_default_branch(github_service, bare_remote):
    default = github_service.register("https://github.com/octocat/Hello-World")
    dev = github_service.register("https://github.com/octocat/Hello-World", branch="dev")
    assert {default.branch, dev.branch} == {"main", "dev"}
    assert len(github_service.list()) == 2
    # naming the default branch explicitly is the same registration as leaving it out
    with pytest.raises(ConflictError) as excinfo:
        github_service.register("https://github.com/octocat/Hello-World", branch="main")
    assert excinfo.value.details["repository_id"] == default.repository_id


class OtherBranchesRegistered(RepositoryProvider):
    """Provider that cannot tell which branch is the default (base-class behaviour)."""

    source_type = SourceType.GITHUB

    def __init__(self):
        self.default_branch_calls = 0

    def supports(self, location: str) -> bool:
        return location.startswith("https://github.com/")

    def validate(self, source: RepositorySource) -> None:
        return None

    def fetch(self, source: RepositorySource, destination: Path) -> FetchedRepository:
        destination.mkdir(parents=True, exist_ok=True)
        write(destination / "README.md", "# x\n")
        return FetchedRepository(
            name="r", source_url=source.location, source_type=SourceType.GITHUB, local_path=destination,
            branch=source.branch or "main", commit_sha="a" * 40, is_git=True, github_full_name="o/r",
        )


def test_register_without_branch_is_conservative_when_default_is_unknown(db, settings):
    provider = OtherBranchesRegistered()
    service = RepositoryService(db, settings, providers=[provider])
    dev = service.register("https://github.com/o/r", branch="dev")
    with pytest.raises(ConflictError) as excinfo:
        service.register("https://github.com/o/r")
    assert "default branch could not be determined" in str(excinfo.value)
    assert excinfo.value.details == {"repository_id": dev.repository_id, "branch": "dev"}
    assert len(service.list()) == 1


def test_register_default_branch_is_only_resolved_when_needed(db, settings, monkeypatch):
    provider = OtherBranchesRegistered()
    calls: list[str] = []

    def counting_default_branch(source):
        calls.append(source.location)
        return "main"

    monkeypatch.setattr(provider, "default_branch", counting_default_branch)
    service = RepositoryService(db, settings, providers=[provider])

    service.register("https://github.com/o/r")  # nothing registered yet: no lookup
    assert calls == []
    with pytest.raises(ConflictError):
        service.register("https://github.com/o/r")  # a row for "main" exists: resolve and compare
    assert calls == ["https://github.com/o/r"]
    service.register("https://github.com/o/r", branch="dev")  # explicit branch: no lookup
    assert calls == ["https://github.com/o/r"]


def test_register_default_branch_lookup_failure_leaves_nothing_behind(db, settings, monkeypatch):
    provider = OtherBranchesRegistered()
    service = RepositoryService(db, settings, providers=[provider])
    dev = service.register("https://github.com/o/r", branch="dev")

    def unreachable(source):
        raise RepositoryError("Network error while querying (git ls-remote) " + source.location)

    monkeypatch.setattr(provider, "default_branch", unreachable)
    with pytest.raises(RepositoryError, match="Network error"):
        service.register("https://github.com/o/r")
    assert [r.repository_id for r in service.list()] == [dev.repository_id]


# ---------------------------------------------------------------------------- ingest


def test_ingest_without_refresh_reanalyses_existing_copy(service, project):
    repository = service.register(str(project))
    copy = service.local_path_of(repository)
    write(copy / "scripts" / "run.sh", "#!/bin/sh\n")  # only in the working copy
    (copy / "docs" / "index.md").unlink()
    (copy / "docs").rmdir()

    service.ingest(repository, refresh=False)
    paths = sorted(component.path for component in repository.components)
    assert paths == ["app", "scripts", "tests"], "profile follows the working copy; docs component removed"
    assert repository.profile["hints"]["has_pytest"] is True

    service.ingest(repository, refresh=True)
    assert not (copy / "scripts").exists(), "refresh re-copies the source"
    assert sorted(component.path for component in repository.components) == ["app", "docs", "tests"]


def test_ingest_refresh_picks_up_source_changes_and_updates_components(service, db, project):
    repository = service.register(str(project))
    component_ids_before = {c.path: c.component_id for c in repository.components}

    write(project / "app" / "extra.py", "x = 1\n")
    write(project / "app" / "more.py", "y = 2\n")
    (project / "docs" / "index.md").unlink()
    (project / "docs").rmdir()
    write(project / "package.json", json.dumps({"name": "demo", "scripts": {"test": "jest"}}))

    service.ingest(repository, refresh=True)
    db.expire_all()
    rows = {c.path: c for c in db.scalars(select(Component).where(Component.repository_id == repository.repository_id))}
    assert set(rows) == {"app", "tests"}
    assert rows["app"].file_count == 3
    assert rows["app"].component_id == component_ids_before["app"], "existing components are updated in place"
    refreshed = db.get(Repository, repository.repository_id)
    assert refreshed.profile["dependency_files"] == ["package.json", "requirements.txt"]
    assert refreshed.profile["hints"]["npm_test_script"] == "jest"


def test_ingest_refetches_when_working_copy_is_missing(service, project):
    repository = service.register(str(project))
    copy = service.local_path_of(repository)
    import shutil

    shutil.rmtree(copy)
    service.ingest(repository, refresh=False)
    assert (copy / "app" / "main.py").exists()


def test_ingest_wraps_unexpected_provider_errors(db, settings, project):
    class BrokenProvider(LocalRepositoryProvider):
        def fetch(self, source, destination):
            raise OSError("disk on fire")

    service = RepositoryService(db, settings, providers=[BrokenProvider(settings)])
    with pytest.raises(RepositoryError, match="disk on fire"):
        service.register(str(project))
    assert service.list() == []


# ---------------------------------------------------------------------------- get / list / delete


def test_get_list_and_delete(service, db, settings, project, tmp_path):
    second = tmp_path / "second"
    write(second / "index.js", "console.log('hi')\n")
    first = service.register(str(project))
    other = service.register(str(second))

    assert service.get(first.repository_id) is first
    listed = service.list()
    assert [r.repository_id for r in listed] == [other.repository_id, first.repository_id], "newest first"

    workspace_dir = service.local_path_of(first)
    assert workspace_dir.exists()
    service.delete(first.repository_id)
    assert db.get(Repository, first.repository_id) is None
    assert db.scalars(select(Component).where(Component.repository_id == first.repository_id)).all() == []
    assert not workspace_dir.exists()
    assert service.local_path_of(other).exists(), "other repositories are untouched"
    assert project.exists() and (project / "app" / "main.py").exists(), "the user's original is never deleted"

    with pytest.raises(NotFoundError) as excinfo:
        service.get(first.repository_id)
    assert excinfo.value.details == {"repository_id": first.repository_id}
    with pytest.raises(NotFoundError):
        service.delete(first.repository_id)
    with pytest.raises(NotFoundError):
        service.get(999_999)


def test_delete_never_removes_paths_outside_the_workspace(service, db, project):
    repository = service.register(str(project))
    repository.local_path = str(project)  # a tampered / legacy row pointing at the user's directory
    db.commit()
    service.delete(repository.repository_id)
    assert project.exists() and (project / "requirements.txt").exists()


@pytest.mark.parametrize("stray", ["workspace", "repos", "other-repo"])
def test_delete_only_removes_the_repositorys_own_workspace_directory(service, db, settings, project, tmp_path, stray):
    """Regression: a local_path equal to the workspace root wiped every other repository and
    remediation; the repos directory and another repository's copy must be safe too."""
    second = tmp_path / "second"
    write(second / "index.js", "console.log('hi')\n")
    first = service.register(str(project))
    other = service.register(str(second))
    marker = write(settings.workspace_path / "remediations" / "5" / "x.txt", "keep me")
    own_dir = service.workspace_dir(first.repository_id)
    assert own_dir.is_dir()

    first.local_path = {
        "workspace": str(settings.workspace_path),
        "repos": str(settings.workspace_path / "repos"),
        "other-repo": other.local_path,
    }[stray]
    db.commit()

    service.delete(first.repository_id)

    assert not own_dir.exists(), "the repository's own directory is always removed"
    assert service.local_path_of(other).is_dir() and (service.local_path_of(other) / "index.js").exists()
    assert marker.read_text() == "keep me"
    assert service.get(other.repository_id).repository_id == other.repository_id


def test_delete_accepts_local_path_below_the_own_directory(service, db, project):
    repository = service.register(str(project))
    nested = service.local_path_of(repository) / "app"
    repository.local_path = str(nested)  # absolute legacy value still accepted
    db.commit()
    service.delete(repository.repository_id)
    assert not nested.exists() and not nested.parent.exists()


def test_local_directory_cannot_be_registered_twice_even_with_a_branch(service, project):
    """Local copies ignore branches, so any second registration of the same directory conflicts."""
    first = service.register(str(project))
    for branch in (None, "dev", "anything"):
        with pytest.raises(ConflictError) as exc:
            service.register(str(project), branch=branch)
        assert exc.value.details["repository_id"] == first.repository_id
    assert len(service.list()) == 1


def test_github_duplicate_detection_is_case_insensitive(github_service):
    github_service.register("https://github.com/Octocat/Hello-World")
    with pytest.raises(ConflictError):
        github_service.register("https://github.com/octocat/hello-world")
