"""LocalRepositoryProvider: copying with the ignore list, .git kept, workspace refusal, git metadata."""

from __future__ import annotations

import os
from pathlib import Path

import git
import pytest

from app.core.config import Settings
from app.core.exceptions import RepositoryError, ValidationFailedError
from app.models.enums import SourceType
from app.services.repository.base import RepositorySource
from app.services.repository.ignore import IGNORED_DIR_NAMES, copytree_ignore
from app.services.repository.local_provider import LocalRepositoryProvider


def make_settings(tmp_path: Path, workspace: Path | None = None) -> Settings:
    return Settings(
        _env_file=None,
        repository_workspace=str(workspace or tmp_path / "ws"),
        github_token=None,
    )


def build_project(root: Path) -> Path:
    """A small project with every ignored directory, a file that shares an ignored name, and a symlink."""
    (root / "src").mkdir(parents=True)
    (root / "src" / "main.py").write_text("import requests\n")
    (root / "requirements.txt").write_text("requests==2.25.1\n")
    for name in IGNORED_DIR_NAMES:
        (root / name).mkdir()
        (root / name / "junk.py").write_text("# generated\n")
    (root / "src" / "node_modules").mkdir()
    (root / "src" / "node_modules" / "nested.js").write_text("// nested\n")
    (root / "docs").mkdir()
    (root / "docs" / "build").write_text("a file called build must survive\n")
    os.symlink("requirements.txt", root / "req-link.txt")
    return root


@pytest.fixture
def project(tmp_path: Path) -> Path:
    return build_project(tmp_path / "project")


@pytest.fixture
def git_project(project: Path) -> dict:
    repo = git.Repo.init(project, initial_branch="main")
    with repo.config_writer() as cfg:
        cfg.set_value("user", "email", "tests@example.com")
        cfg.set_value("user", "name", "Sentinel Tests")
    repo.git.add("--all")
    sha = repo.index.commit("initial").hexsha
    repo.create_remote("origin", "git@github.com:octocat/local-project.git")
    return {"path": project, "sha": sha, "repo": repo}


# ---------------------------------------------------------------------------- supports / validate


def test_supports_existing_directories_only(tmp_path, project):
    provider = LocalRepositoryProvider(make_settings(tmp_path))
    assert provider.supports(str(project))
    assert provider.supports(f"{project}/")
    assert not provider.supports(str(project / "requirements.txt"))
    assert not provider.supports(str(tmp_path / "missing"))
    assert not provider.supports("https://github.com/octocat/Hello-World")
    assert not provider.supports("git@github.com:octocat/Hello-World.git")
    assert not provider.supports("")


def test_validate_reports_missing_file_and_unreadable(tmp_path, project):
    provider = LocalRepositoryProvider(make_settings(tmp_path))
    with pytest.raises(RepositoryError, match="does not exist"):
        provider.validate(RepositorySource(str(tmp_path / "nope"), SourceType.LOCAL))
    with pytest.raises(RepositoryError, match="not a directory"):
        provider.validate(RepositorySource(str(project / "requirements.txt"), SourceType.LOCAL))
    with pytest.raises(RepositoryError, match="empty"):
        provider.validate(RepositorySource("   ", SourceType.LOCAL))
    provider.validate(RepositorySource(str(project), SourceType.LOCAL))

    if os.geteuid() == 0:
        pytest.skip("root ignores directory permissions")
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0)
    try:
        with pytest.raises(RepositoryError, match="not readable"):
            provider.validate(RepositorySource(str(locked), SourceType.LOCAL))
    finally:
        locked.chmod(0o755)


def test_refuses_workspace_as_source(tmp_path):
    workspace = tmp_path / "ws"
    provider = LocalRepositoryProvider(make_settings(tmp_path, workspace))
    inside = workspace / "repos" / "7"
    inside.mkdir(parents=True)
    for location in (workspace, inside):
        with pytest.raises(ValidationFailedError, match="workspace") as excinfo:
            provider.validate(RepositorySource(str(location), SourceType.LOCAL))
        assert excinfo.value.details["workspace"] == str(workspace.resolve())
        with pytest.raises(ValidationFailedError):
            provider.fetch(RepositorySource(str(location), SourceType.LOCAL), tmp_path / "dest")
    assert not (tmp_path / "dest").exists()


def test_normalize_resolves_path(tmp_path, project):
    provider = LocalRepositoryProvider(make_settings(tmp_path))
    relative_form = str(project / "src" / "..")
    source = provider.normalize(RepositorySource(relative_form, SourceType.LOCAL, branch="x"))
    assert source.location == str(project.resolve())
    assert source.source_type == SourceType.LOCAL
    assert source.branch is None  # branches cannot be selected for local directories


def test_validate_rejects_filesystem_roots_and_home(tmp_path):
    import pytest as _pytest

    from app.core.exceptions import ValidationFailedError
    from pathlib import Path

    provider = LocalRepositoryProvider(make_settings(tmp_path))
    for location in ["/", str(Path.home()), "/usr"]:
        with _pytest.raises(ValidationFailedError):
            provider.validate(RepositorySource(location, SourceType.LOCAL))


# ---------------------------------------------------------------------------- copying


def test_fetch_copies_with_ignore_list_and_keeps_git(tmp_path, git_project):
    provider = LocalRepositoryProvider(make_settings(tmp_path))
    destination = tmp_path / "ws" / "repos" / "1"
    fetched = provider.fetch(RepositorySource(str(git_project["path"]), SourceType.LOCAL), destination)

    assert fetched.name == "project"
    assert fetched.source_url == str(git_project["path"].resolve())
    assert fetched.source_type == SourceType.LOCAL
    assert fetched.local_path == destination
    assert (destination / "src" / "main.py").read_text() == "import requests\n"
    assert (destination / "requirements.txt").exists()
    assert (destination / ".git").is_dir(), ".git must be kept"
    for name in IGNORED_DIR_NAMES:
        assert not (destination / name).exists(), f"{name} must not be copied"
    assert not (destination / "src" / "node_modules").exists(), "ignored names apply at any depth"
    assert (destination / "docs" / "build").is_file(), "a *file* named like an ignored dir is kept"
    assert (destination / "req-link.txt").is_symlink(), "symlinks are copied as links, not followed"

    # git metadata from the copy
    assert fetched.is_git is True
    assert fetched.branch == "main"
    assert fetched.commit_sha == git_project["sha"]
    assert fetched.github_full_name == "octocat/local-project"
    assert fetched.warnings == []


def test_fetch_never_modifies_the_original(tmp_path, project):
    provider = LocalRepositoryProvider(make_settings(tmp_path))
    before = sorted(p.relative_to(project).as_posix() for p in project.rglob("*"))
    provider.fetch(RepositorySource(str(project), SourceType.LOCAL), tmp_path / "copy")
    after = sorted(p.relative_to(project).as_posix() for p in project.rglob("*"))
    assert before == after
    assert (project / "node_modules" / "junk.py").exists()


def test_fetch_plain_directory_without_git(tmp_path, project):
    provider = LocalRepositoryProvider(make_settings(tmp_path))
    fetched = provider.fetch(RepositorySource(str(project), SourceType.LOCAL), tmp_path / "copy")
    assert fetched.is_git is False
    assert fetched.branch is None
    assert fetched.commit_sha is None
    assert fetched.github_full_name is None


def test_fetch_replaces_existing_destination(tmp_path, project):
    provider = LocalRepositoryProvider(make_settings(tmp_path))
    destination = tmp_path / "copy"
    destination.mkdir()
    (destination / "stale.txt").write_text("old")
    provider.fetch(RepositorySource(str(project), SourceType.LOCAL), destination)
    assert not (destination / "stale.txt").exists()
    assert (destination / "src" / "main.py").exists()


def test_fetch_tolerates_detached_head_and_non_github_remote(tmp_path, git_project):
    repo: git.Repo = git_project["repo"]
    repo.remotes.origin.set_url("https://gitlab.example.com/team/project.git")
    repo.git.checkout(git_project["sha"])  # detached HEAD
    provider = LocalRepositoryProvider(make_settings(tmp_path))
    fetched = provider.fetch(RepositorySource(str(git_project["path"]), SourceType.LOCAL), tmp_path / "copy")
    assert fetched.is_git is True
    assert fetched.branch is None
    assert fetched.commit_sha == git_project["sha"]
    assert fetched.github_full_name is None
    assert any("detached HEAD" in warning for warning in fetched.warnings)


def test_fetch_tolerates_repository_without_commits(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    git.Repo.init(empty, initial_branch="main")
    (empty / "README.md").write_text("no commits yet\n")
    provider = LocalRepositoryProvider(make_settings(tmp_path))
    fetched = provider.fetch(RepositorySource(str(empty), SourceType.LOCAL), tmp_path / "copy")
    assert fetched.is_git is True
    assert fetched.commit_sha is None
    assert any("no commits" in warning for warning in fetched.warnings)


def test_requested_branch_mismatch_is_reported(tmp_path, git_project):
    provider = LocalRepositoryProvider(make_settings(tmp_path))
    fetched = provider.fetch(
        RepositorySource(str(git_project["path"]), SourceType.LOCAL, branch="release"), tmp_path / "copy"
    )
    assert fetched.branch == "main"
    assert any("Requested branch 'release'" in warning for warning in fetched.warnings)


def test_workspace_inside_source_is_skipped(tmp_path, project):
    """Analysing a directory that contains the workspace must not copy the workspace into itself."""
    workspace = project / "workspace"
    provider = LocalRepositoryProvider(make_settings(tmp_path, workspace))
    destination = workspace / "repos" / "1"
    (workspace / "repos" / "0").mkdir(parents=True)
    (workspace / "repos" / "0" / "old.txt").write_text("previous clone")
    fetched = provider.fetch(RepositorySource(str(project), SourceType.LOCAL), destination)
    assert (destination / "src" / "main.py").exists()
    assert not (destination / "workspace").exists()
    assert any("Skipped the Sentinel Chain workspace" in warning for warning in fetched.warnings)


def test_unreadable_file_becomes_a_warning_not_an_error(tmp_path, project):
    if os.geteuid() == 0:
        pytest.skip("root ignores file permissions")
    secret = project / "src" / "secret.py"
    secret.write_text("x = 1\n")
    secret.chmod(0)
    provider = LocalRepositoryProvider(make_settings(tmp_path))
    try:
        fetched = provider.fetch(RepositorySource(str(project), SourceType.LOCAL), tmp_path / "copy")
    finally:
        secret.chmod(0o644)
    assert (tmp_path / "copy" / "src" / "main.py").exists()
    assert any("secret.py" in warning for warning in fetched.warnings)


def test_copytree_ignore_only_drops_directories(tmp_path):
    base = tmp_path / "base"
    (base / "build").mkdir(parents=True)
    (base / "dist").write_text("a file")
    ignore = copytree_ignore()
    assert ignore(str(base), ["build", "dist", "src"]) == {"build"}
