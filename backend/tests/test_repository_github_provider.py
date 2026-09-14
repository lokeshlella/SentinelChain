"""GitHubRepositoryProvider: URL parsing matrix, offline cloning, timeouts, token safety, error mapping."""

from __future__ import annotations

import socket
import subprocess
import threading
import time
from pathlib import Path

import git
import pytest
from git.exc import GitCommandError

from app.core.config import Settings
from app.core.exceptions import RepositoryError, ValidationFailedError
from app.models.enums import SourceType
from app.services.repository import github_provider as github_provider_module
from app.services.repository.base import RepositorySource
from app.services.repository.github_provider import (
    GitHubRepositoryProvider,
    parse_github_remote,
    parse_github_url,
    validate_branch_name,
)

TOKEN = "ghp_secretTOKEN1234567890"


class FakeProcess:
    """Stand-in for the ``subprocess.Popen`` object ``_run_git`` drives."""

    def __init__(self, stdout: bytes = b"", stderr: bytes = b"", returncode: int = 0):
        self.pid = 4242
        self.stdout = None
        self.stderr = None
        self.returncode = returncode
        self._output = (stdout, stderr)
        self.communicate_calls: list[float | None] = []

    def communicate(self, timeout: float | None = None):
        self.communicate_calls.append(timeout)
        return self._output


def patch_popen(monkeypatch, process: FakeProcess) -> dict:
    """Replace ``subprocess.Popen`` inside the provider module; returns the captured call."""
    captured: dict = {}

    def fake_popen(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return process

    monkeypatch.setattr(github_provider_module.subprocess, "Popen", fake_popen)
    return captured


def live_processes_mentioning(text: str, settle_seconds: float = 3.0) -> list[str]:
    """``ps`` lines of non-zombie processes whose command line contains ``text``.

    Polls briefly so processes that were just killed have time to disappear.
    """
    deadline = time.monotonic() + settle_seconds
    while True:
        listing = subprocess.run(["ps", "-eo", "pid,stat,command"], capture_output=True, text=True, check=False)
        survivors = [
            line
            for line in listing.stdout.splitlines()
            if text in line and "git" in line and not line.split(None, 2)[1].startswith("Z")
        ]
        if not survivors or time.monotonic() > deadline:
            return survivors
        time.sleep(0.1)


def make_settings(tmp_path: Path, **overrides) -> Settings:
    values = {"repository_workspace": str(tmp_path / "ws"), "github_token": None, "git_clone_timeout": 60}
    values.update(overrides)
    return Settings(_env_file=None, **values)


@pytest.fixture
def bare_remote(tmp_path: Path) -> dict:
    """A local bare repository with ``main`` (2 commits) and ``dev`` (1 extra commit)."""
    work = tmp_path / "upstream"
    repo = git.Repo.init(work, initial_branch="main")
    with repo.config_writer() as cfg:
        cfg.set_value("user", "email", "tests@example.com")
        cfg.set_value("user", "name", "Sentinel Tests")
    (work / "README.md").write_text("# upstream\n")
    (work / "app.py").write_text("import requests\n")
    repo.index.add(["README.md", "app.py"])
    repo.index.commit("initial")
    (work / "requirements.txt").write_text("requests==2.25.1\n")
    repo.index.add(["requirements.txt"])
    main_sha = repo.index.commit("add requirements").hexsha
    repo.git.checkout("-b", "dev")
    (work / "dev.py").write_text("DEV = True\n")
    repo.index.add(["dev.py"])
    dev_sha = repo.index.commit("dev work").hexsha
    repo.git.checkout("main")
    bare = tmp_path / "remote.git"
    git.Repo.clone_from(work, bare, bare=True)
    return {"path": bare, "main_sha": main_sha, "dev_sha": dev_sha}


@pytest.fixture
def offline_provider(tmp_path: Path, bare_remote: dict, monkeypatch) -> GitHubRepositoryProvider:
    """Real provider whose clone URL is redirected to the local bare repository."""
    provider = GitHubRepositoryProvider(make_settings(tmp_path))
    monkeypatch.setattr(provider, "_clone_url", lambda parsed: (str(bare_remote["path"]), False))
    return provider


@pytest.fixture
def stalled_remote():
    """Loopback TCP server that accepts connections and never answers: a hung git remote.

    Nothing leaves the machine; git connects, sends its request and then waits forever
    for a response, which is exactly what a clone timeout must cut short.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    server.settimeout(0.2)
    stop = threading.Event()
    held: list[socket.socket] = []

    def serve() -> None:
        while not stop.is_set():
            try:
                connection, _ = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            held.append(connection)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.getsockname()[1]}"
    stop.set()
    thread.join(timeout=2)
    for connection in held:
        connection.close()
    server.close()


# ---------------------------------------------------------------------------- URL parsing


@pytest.mark.parametrize(
    "url, owner, repo, branch",
    [
        ("https://github.com/octocat/Hello-World", "octocat", "Hello-World", None),
        ("https://github.com/octocat/Hello-World.git", "octocat", "Hello-World", None),
        ("https://github.com/octocat/Hello-World/", "octocat", "Hello-World", None),
        ("https://github.com/octocat/Hello-World.git/", "octocat", "Hello-World", None),
        ("https://github.com/octocat/Hello-World/tree/develop", "octocat", "Hello-World", "develop"),
        ("https://github.com/octocat/Hello-World/tree/feature/login", "octocat", "Hello-World", "feature/login"),
        ("https://github.com/octocat/Hello-World/tree/release-1.0/", "octocat", "Hello-World", "release-1.0"),
        ("git@github.com:octocat/Hello-World.git", "octocat", "Hello-World", None),
        ("git@github.com:octocat/Hello-World", "octocat", "Hello-World", None),
        ("http://github.com/octocat/Hello-World", "octocat", "Hello-World", None),
        ("https://www.github.com/octocat/Hello-World", "octocat", "Hello-World", None),
        ("HTTPS://GitHub.com/octocat/Hello-World", "octocat", "Hello-World", None),
        ("  https://github.com/octocat/Hello-World  ", "octocat", "Hello-World", None),
        ("https://github.com/octocat/my.repo_name", "octocat", "my.repo_name", None),
    ],
)
def test_parse_valid_urls(url, owner, repo, branch):
    parsed = parse_github_url(url)
    assert (parsed.owner, parsed.repo, parsed.branch) == (owner, repo, branch)
    assert parsed.full_name == f"{owner}/{repo}"
    assert parsed.https_url == f"https://github.com/{owner}/{repo}"
    assert parsed.clone_url == f"https://github.com/{owner}/{repo}.git"


@pytest.mark.parametrize(
    "url",
    [
        "",
        "   ",
        "octocat/Hello-World",
        "github.com/octocat/Hello-World",
        "www.github.com/octocat/Hello-World",
        "https://gitlab.com/octocat/Hello-World",
        "https://github.com",
        "https://github.com/octocat",
        "https://github.com/octocat/",
        "https://github.com/octocat/Hello-World/blob/main/README.md",
        "https://github.com/octocat/Hello-World/tree",
        "https://github.com/octocat/Hello-World/tree/",
        "https://github.com/octocat/Hello-World/pulls",
        "ftp://github.com/octocat/Hello-World",
        "ssh://git@github.com/octocat/Hello-World.git",
        "https://user:pass@github.com/octocat/Hello-World",
        "https://github.com/octo cat/Hello-World",
        "https://github.com/-octocat/Hello-World",
        "https://github.com/octocat/..",
        "git@github.com:octocat",
        "git@gitlab.com:octocat/Hello-World.git",
        "/Users/someone/projects/repo",
        "C:\\projects\\repo",
    ],
)
def test_parse_invalid_urls_list_accepted_forms(url):
    with pytest.raises(ValidationFailedError) as excinfo:
        parse_github_url(url)
    message = str(excinfo.value)
    assert "https://github.com/owner/repo" in message
    assert "git@github.com:owner/repo.git" in message


@pytest.mark.parametrize("url", ["https://github.com/o/r/tree/-evil", "https://github.com/o/r/tree/feature..x"])
def test_parse_rejects_invalid_branch_in_tree_url(url):
    with pytest.raises(ValidationFailedError) as excinfo:
        parse_github_url(url)
    assert "Invalid branch name" in str(excinfo.value)


def test_credentials_in_url_are_never_echoed():
    with pytest.raises(ValidationFailedError) as excinfo:
        parse_github_url("https://user:hunter2@github.com/octocat/Hello-World")
    assert "hunter2" not in str(excinfo.value)


@pytest.mark.parametrize("name", ["main", "feature/login", "release-1.0", "v2", "a.b", "user/feat_x"])
def test_valid_branch_names(name):
    validate_branch_name(name)


@pytest.mark.parametrize(
    "name", ["", "-evil", "--upload-pack=x", "a b", "a..b", "feat/", "/feat", "x.lock", "a//b", "a~1", "a^", "a:b", "x?", "x*", "x[1]", "a\\b", ".hidden/x", "a@{1}", "end."]
)
def test_invalid_branch_names(name):
    with pytest.raises(ValidationFailedError):
        validate_branch_name(name)


@pytest.mark.parametrize(
    "remote, expected",
    [
        ("https://github.com/octocat/Hello-World.git", "octocat/Hello-World"),
        ("git@github.com:octocat/Hello-World.git", "octocat/Hello-World"),
        ("ssh://git@github.com/octocat/Hello-World.git", "octocat/Hello-World"),
        ("https://github.com/octocat/Hello-World", "octocat/Hello-World"),
        ("https://gitlab.com/octocat/Hello-World.git", None),
        ("/srv/git/project.git", None),
        ("", None),
        (None, None),
    ],
)
def test_parse_github_remote(remote, expected):
    assert parse_github_remote(remote) == expected


# ---------------------------------------------------------------------------- supports / normalize / validate


def test_supports_only_github_locations(tmp_path):
    provider = GitHubRepositoryProvider(make_settings(tmp_path))
    assert provider.supports("https://github.com/octocat/Hello-World")
    assert provider.supports("git@github.com:octocat/Hello-World.git")
    assert provider.supports("github.com/octocat/Hello-World")  # meant for GitHub; validate() explains the fix
    assert not provider.supports("https://gitlab.com/octocat/Hello-World")
    assert not provider.supports(str(tmp_path))
    assert not provider.supports("/tmp/github.com/local-dir")
    assert not provider.supports("")


def test_normalize_canonicalises_and_extracts_branch(tmp_path):
    provider = GitHubRepositoryProvider(make_settings(tmp_path))
    source = provider.normalize(RepositorySource("git@github.com:octocat/Hello-World.git", SourceType.GITHUB))
    assert source.location == "https://github.com/octocat/Hello-World"
    assert source.branch is None

    from_tree = provider.normalize(
        RepositorySource("https://github.com/octocat/Hello-World/tree/develop", SourceType.GITHUB)
    )
    assert from_tree.branch == "develop"

    explicit = provider.normalize(
        RepositorySource("https://github.com/octocat/Hello-World/tree/develop", SourceType.GITHUB, branch="main")
    )
    assert explicit.branch == "main", "an explicit branch wins over the one in the URL"


def test_validate_rejects_bad_branch_without_network(tmp_path):
    provider = GitHubRepositoryProvider(make_settings(tmp_path))
    with pytest.raises(ValidationFailedError):
        provider.validate(RepositorySource("https://github.com/octocat/Hello-World", SourceType.GITHUB, branch="-x"))
    provider.validate(RepositorySource("https://github.com/octocat/Hello-World", SourceType.GITHUB, branch="main"))


# ---------------------------------------------------------------------------- offline cloning


def test_run_clone_default_branch_is_single_branch(tmp_path, bare_remote):
    provider = GitHubRepositoryProvider(make_settings(tmp_path))
    destination = tmp_path / "clone"
    provider._run_clone(str(bare_remote["path"]), destination, None)
    repo = git.Repo(destination)
    assert repo.active_branch.name == "main"
    assert repo.head.commit.hexsha == bare_remote["main_sha"]
    assert [b.name for b in repo.branches] == ["main"], "single-branch clone must not fetch other branches"


def test_fetch_records_metadata(tmp_path, offline_provider, bare_remote):
    destination = tmp_path / "ws" / "repos" / "1"
    source = RepositorySource("git@github.com:octocat/Hello-World.git", SourceType.GITHUB)
    fetched = offline_provider.fetch(source, destination)

    assert fetched.name == "Hello-World"
    assert fetched.source_url == "https://github.com/octocat/Hello-World"
    assert fetched.source_type == SourceType.GITHUB
    assert fetched.local_path == destination
    assert fetched.branch == "main"
    assert fetched.commit_sha == bare_remote["main_sha"]
    assert fetched.is_git is True
    assert fetched.github_full_name == "octocat/Hello-World"
    assert fetched.warnings == []
    assert (destination / "requirements.txt").read_text() == "requests==2.25.1\n"


def test_fetch_requested_branch(tmp_path, offline_provider, bare_remote):
    destination = tmp_path / "clone-dev"
    source = RepositorySource("https://github.com/octocat/Hello-World", SourceType.GITHUB, branch="dev")
    fetched = offline_provider.fetch(source, destination)
    assert fetched.branch == "dev"
    assert fetched.commit_sha == bare_remote["dev_sha"]
    assert (destination / "dev.py").exists()


def test_fetch_branch_from_tree_url(tmp_path, offline_provider, bare_remote):
    destination = tmp_path / "clone-tree"
    source = RepositorySource("https://github.com/octocat/Hello-World/tree/dev", SourceType.GITHUB)
    fetched = offline_provider.fetch(source, destination)
    assert fetched.branch == "dev"
    assert fetched.commit_sha == bare_remote["dev_sha"]


def test_fetch_replaces_existing_destination(tmp_path, offline_provider):
    destination = tmp_path / "clone-existing"
    destination.mkdir(parents=True)
    (destination / "stale.txt").write_text("old")
    offline_provider.fetch(RepositorySource("https://github.com/octocat/Hello-World", SourceType.GITHUB), destination)
    assert not (destination / "stale.txt").exists()
    assert (destination / "README.md").exists()


def test_fetch_unknown_branch_is_a_clear_error(tmp_path, offline_provider):
    destination = tmp_path / "clone-missing-branch"
    source = RepositorySource("https://github.com/octocat/Hello-World", SourceType.GITHUB, branch="nope")
    with pytest.raises(RepositoryError) as excinfo:
        offline_provider.fetch(source, destination)
    assert "Branch 'nope' not found" in str(excinfo.value)
    assert excinfo.value.details["branch"] == "nope"
    assert not destination.exists(), "a failed clone must not leave a partial directory behind"


def test_fetch_missing_repository_maps_to_not_accessible(tmp_path, monkeypatch):
    provider = GitHubRepositoryProvider(make_settings(tmp_path))
    monkeypatch.setattr(provider, "_clone_url", lambda parsed: (str(tmp_path / "does-not-exist.git"), False))
    with pytest.raises(RepositoryError) as excinfo:
        provider.fetch(RepositorySource("https://github.com/octocat/Missing", SourceType.GITHUB), tmp_path / "c")
    message = str(excinfo.value)
    assert message.startswith("Repository not found or not accessible: https://github.com/octocat/Missing")
    assert "GITHUB_TOKEN" in message
    assert excinfo.value.details["git_status"] == 128


# ---------------------------------------------------------------------------- token handling


def test_token_used_for_clone_only_and_never_persisted(tmp_path, bare_remote, monkeypatch):
    provider = GitHubRepositoryProvider(make_settings(tmp_path, github_token=TOKEN))
    seen: dict[str, str] = {}
    real_run_clone = provider._run_clone

    def fake_run_clone(clone_url: str, destination: Path, branch: str | None) -> None:
        seen["url"] = clone_url
        real_run_clone(str(bare_remote["path"]), destination, branch)

    monkeypatch.setattr(provider, "_run_clone", fake_run_clone)
    destination = tmp_path / "private-clone"
    fetched = provider.fetch(RepositorySource("https://github.com/octocat/Private", SourceType.GITHUB), destination)

    assert seen["url"] == f"https://x-access-token:{TOKEN}@github.com/octocat/Private.git"
    config_text = (destination / ".git" / "config").read_text()
    assert TOKEN not in config_text
    assert git.Repo(destination).remotes.origin.url == "https://github.com/octocat/Private.git"
    assert fetched.github_full_name == "octocat/Private"


def test_run_clone_disables_credential_helpers_when_token_embedded(tmp_path, monkeypatch):
    provider = GitHubRepositoryProvider(make_settings(tmp_path, github_token=TOKEN))
    process = FakeProcess()
    captured = patch_popen(monkeypatch, process)

    provider._run_clone(f"https://x-access-token:{TOKEN}@github.com/o/r.git", tmp_path / "x", "main")

    command = captured["command"]
    assert command[:3] == ["git", "-c", "credential.helper="]
    assert "--single-branch" in command and command[command.index("--branch") + 1] == "main"
    assert command[-2:] == [f"https://x-access-token:{TOKEN}@github.com/o/r.git", str(tmp_path / "x")]
    kwargs = captured["kwargs"]
    assert kwargs["env"]["GIT_TERMINAL_PROMPT"] == "0"
    assert kwargs["env"]["GIT_ASKPASS"] == ""
    assert kwargs["env"]["LC_ALL"] == "C", "error classification relies on English git messages"
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["start_new_session"] is True, "git must run in its own process group so its helpers can be killed"
    assert process.communicate_calls == [60], "settings.git_clone_timeout bounds the wait"


def test_run_clone_without_token_does_not_touch_credential_helpers(tmp_path, monkeypatch):
    provider = GitHubRepositoryProvider(make_settings(tmp_path))
    captured = patch_popen(monkeypatch, FakeProcess())
    provider._run_clone("https://github.com/o/r.git", tmp_path / "x", None)
    command = captured["command"]
    assert command[:3] == ["git", "clone", "--single-branch"]
    assert "--branch" not in command


def test_git_clone_timeout_is_enforced_and_kills_the_whole_process_tree(tmp_path, stalled_remote, monkeypatch):
    """Regression: GitPython's kill_after_timeout left ``git remote-https`` helpers alive holding the
    output pipes, so fetch() blocked until the helper's own network timeout (minutes) instead of
    ``settings.git_clone_timeout`` seconds."""
    provider = GitHubRepositoryProvider(make_settings(tmp_path, git_clone_timeout=1))
    clone_url = f"{stalled_remote}/octocat/Hello-World.git"
    monkeypatch.setattr(provider, "_clone_url", lambda parsed: (clone_url, False))
    destination = tmp_path / "hung-clone"

    started = time.monotonic()
    with pytest.raises(RepositoryError) as excinfo:
        provider.fetch(RepositorySource("https://github.com/octocat/Hello-World", SourceType.GITHUB), destination)
    elapsed = time.monotonic() - started

    assert "Cloning https://github.com/octocat/Hello-World timed out after 1s" in str(excinfo.value)
    assert excinfo.value.details["git_status"] == -9
    assert elapsed < 5, f"fetch() blocked for {elapsed:.1f}s despite a 1s timeout"
    assert not destination.exists(), "a timed-out clone must not leave a partial directory behind"
    assert live_processes_mentioning(clone_url) == [], "git and its remote helpers must all be gone"


def test_run_git_timeout_disabled_when_setting_is_zero(tmp_path, monkeypatch):
    provider = GitHubRepositoryProvider(make_settings(tmp_path, git_clone_timeout=0))
    process = FakeProcess()
    patch_popen(monkeypatch, process)
    provider._run_clone("https://github.com/o/r.git", tmp_path / "x", None)
    assert process.communicate_calls == [None]


def test_run_git_failure_becomes_git_command_error_with_redacted_command(tmp_path, monkeypatch):
    provider = GitHubRepositoryProvider(make_settings(tmp_path, github_token=TOKEN))
    patch_popen(monkeypatch, FakeProcess(stderr=b"fatal: Authentication failed", returncode=128))
    with pytest.raises(GitCommandError) as excinfo:
        provider._run_clone(f"https://x-access-token:{TOKEN}@github.com/o/r.git", tmp_path / "x", None)
    assert excinfo.value.status == 128
    assert TOKEN not in str(excinfo.value)
    assert TOKEN not in " ".join(excinfo.value.command)


def test_missing_git_executable_is_a_clear_error(tmp_path, monkeypatch):
    provider = GitHubRepositoryProvider(make_settings(tmp_path))
    monkeypatch.setattr(git.Git, "GIT_PYTHON_GIT_EXECUTABLE", str(tmp_path / "no-such-git"))
    with pytest.raises(RepositoryError, match="git is not installed"):
        provider.fetch(RepositorySource("https://github.com/o/r", SourceType.GITHUB), tmp_path / "c")


# ---------------------------------------------------------------------------- default branch


def test_default_branch_offline(tmp_path, offline_provider):
    source = RepositorySource("https://github.com/octocat/Hello-World", SourceType.GITHUB)
    assert offline_provider.default_branch(source) == "main"


def test_default_branch_of_missing_repository_maps_to_not_accessible(tmp_path, monkeypatch):
    provider = GitHubRepositoryProvider(make_settings(tmp_path))
    monkeypatch.setattr(provider, "_clone_url", lambda parsed: (str(tmp_path / "does-not-exist.git"), False))
    with pytest.raises(RepositoryError) as excinfo:
        provider.default_branch(RepositorySource("https://github.com/octocat/Missing", SourceType.GITHUB))
    assert str(excinfo.value).startswith("Repository not found or not accessible: https://github.com/octocat/Missing")
    assert excinfo.value.details["git_status"] == 128


def test_default_branch_uses_token_and_ls_remote_symref(tmp_path, monkeypatch):
    provider = GitHubRepositoryProvider(make_settings(tmp_path, github_token=TOKEN))
    process = FakeProcess(stdout=b"ref: refs/heads/trunk\tHEAD\nabc123\tHEAD\n")
    captured = patch_popen(monkeypatch, process)

    branch = provider.default_branch(RepositorySource("https://github.com/o/r", SourceType.GITHUB))

    assert branch == "trunk"
    command = captured["command"]
    assert command[:3] == ["git", "-c", "credential.helper="]
    assert command[3:6] == ["ls-remote", "--symref", "--"]
    assert command[6:] == [f"https://x-access-token:{TOKEN}@github.com/o/r.git", "HEAD"]
    assert captured["kwargs"]["start_new_session"] is True
    assert process.communicate_calls == [60]


def test_default_branch_is_none_for_an_empty_remote(tmp_path, monkeypatch):
    provider = GitHubRepositoryProvider(make_settings(tmp_path))
    patch_popen(monkeypatch, FakeProcess(stdout=b""))
    assert provider.default_branch(RepositorySource("https://github.com/o/r", SourceType.GITHUB)) is None


def test_default_branch_timeout_is_reported_as_a_query_timeout(tmp_path, stalled_remote, monkeypatch):
    provider = GitHubRepositoryProvider(make_settings(tmp_path, git_clone_timeout=1))
    remote_url = f"{stalled_remote}/o/r.git"
    monkeypatch.setattr(provider, "_clone_url", lambda parsed: (remote_url, False))
    started = time.monotonic()
    with pytest.raises(RepositoryError, match=r"Querying \(git ls-remote\) https://github.com/o/r timed out after 1s"):
        provider.default_branch(RepositorySource("https://github.com/o/r", SourceType.GITHUB))
    assert time.monotonic() - started < 5
    assert live_processes_mentioning(remote_url) == []


def test_git_errors_are_redacted(tmp_path, monkeypatch):
    provider = GitHubRepositoryProvider(make_settings(tmp_path, github_token=TOKEN))

    def failing_clone(clone_url, destination, branch):
        raise GitCommandError(
            ["git", "clone", clone_url],
            128,
            stderr=f"fatal: could not read from 'https://x-access-token:{TOKEN}@github.com/o/r.git': "
            "Repository not found",
        )

    monkeypatch.setattr(provider, "_run_clone", failing_clone)
    with pytest.raises(RepositoryError) as excinfo:
        provider.fetch(RepositorySource("https://github.com/o/r", SourceType.GITHUB), tmp_path / "c")
    error = excinfo.value
    assert TOKEN not in str(error)
    assert TOKEN not in repr(error.details)
    assert "x-access-token:***@" in error.details["git_stderr"]
    assert str(error).startswith("Repository not found or not accessible")
    assert "GITHUB_TOKEN has access" in str(error)


@pytest.mark.parametrize(
    "stderr, expected",
    [
        ('Timeout: the command "git clone" did not complete in 60 secs.', "timed out after 60s"),
        ("fatal: unable to access 'https://github.com/o/r.git/': Could not resolve host: github.com", "Network error"),
        ("fatal: could not read Username for 'https://github.com': terminal prompts disabled", "not found or not accessible"),
        ("fatal: Authentication failed for 'https://github.com/o/r.git/'", "not found or not accessible"),
        ("error: something unexpected happened", "git clone of https://github.com/o/r failed (exit 128)"),
    ],
)
def test_git_error_classification(tmp_path, monkeypatch, stderr, expected):
    provider = GitHubRepositoryProvider(make_settings(tmp_path))

    def failing_clone(clone_url, destination, branch):
        raise GitCommandError(["git", "clone"], 128, stderr=stderr)

    monkeypatch.setattr(provider, "_run_clone", failing_clone)
    with pytest.raises(RepositoryError) as excinfo:
        provider.fetch(RepositorySource("https://github.com/o/r", SourceType.GITHUB), tmp_path / "c")
    assert expected in str(excinfo.value)


def test_fetch_rejects_invalid_url_before_cloning(tmp_path, monkeypatch):
    provider = GitHubRepositoryProvider(make_settings(tmp_path))
    monkeypatch.setattr(provider, "_run_clone", lambda *a, **k: pytest.fail("clone must not run"))
    with pytest.raises(ValidationFailedError):
        provider.fetch(RepositorySource("https://gitlab.com/o/r", SourceType.GITHUB), tmp_path / "c")


# ---------------------------------------------------------------------------- integration


@pytest.mark.integration
def test_real_clone_of_public_repository(tmp_path):
    provider = GitHubRepositoryProvider(make_settings(tmp_path, git_clone_timeout=120))
    fetched = provider.fetch(
        RepositorySource("https://github.com/octocat/Hello-World", SourceType.GITHUB), tmp_path / "hello"
    )
    assert fetched.github_full_name == "octocat/Hello-World"
    assert fetched.branch == "master"
    assert fetched.commit_sha and len(fetched.commit_sha) == 40
    assert (tmp_path / "hello" / "README").exists()
