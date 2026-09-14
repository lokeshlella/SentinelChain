"""Audit F-02: repository-controlled git configuration must never execute on the host."""

from __future__ import annotations

import shutil
from pathlib import Path

import git
import pytest

from app.services.github.base import PullRequestSpec
from app.services.github.github_provider import GitHubProvider
from app.services.remediation.workspace import create_working_copy
from app.services.repository.git_safety import SAFE_GIT_OPTIONS, harden_git_dir, sanitize_git_config
from app.services.repository.ignore import copytree_ignore

MALICIOUS_CONFIG = """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
\thooksPath = .evil-hooks
\tfsmonitor = /tmp/evil-fsmonitor
\tsshCommand = /tmp/evil-ssh
[remote "origin"]
\turl = https://github.com/example/demo.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
\tuploadpack = /tmp/evil-upload
[url "https://attacker.example/"]
\tinsteadOf = https://github.com/
[filter "evil"]
\tclean = /tmp/evil-clean
\tsmudge = /tmp/evil-smudge
[diff "x"]
\texternal = /tmp/evil-diff
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
[include]
\tpath = /tmp/evil-include
[alias]
\tco = !/tmp/evil-alias
"""


def make_repo(root: Path, *, hook_marker: Path) -> Path:
    root.mkdir()
    repo = git.Repo.init(root, initial_branch="main")
    (root / "requirements.txt").write_text("requests==2.30.0\n")
    repo.index.add(["requirements.txt"])
    repo.index.commit("init", author=git.Actor("dev", "dev@example.com"), committer=git.Actor("dev", "dev@example.com"))
    repo.create_remote("origin", "https://github.com/example/demo.git")
    hook = root / ".git" / "hooks" / "pre-commit"
    hook.write_text(f"#!/bin/sh\necho ran > {hook_marker}\nexit 0\n")
    hook.chmod(0o755)
    return root


def test_hooks_are_not_copied_and_never_run_on_the_host(tmp_path):
    """The audit reproduction: a local repo's pre-commit hook wrote a file on the host."""
    marker = tmp_path / "HOOK_RAN_ON_HOST"
    source = make_repo(tmp_path / "repo", hook_marker=marker)
    ws = create_working_copy(source, tmp_path / "ws")
    assert not (ws / ".git" / "hooks").exists()
    assert (source / ".git" / "hooks" / "pre-commit").exists()  # the original is untouched
    (ws / "requirements.txt").write_text("requests==2.33.0\n")

    class FakeRepo:
        def get_pulls(self, **kwargs):
            return []

        def create_pull(self, **kwargs):
            raise RuntimeError("stop before network")

    class FakeGitHub:
        def get_repo(self, name):
            return FakeRepo()

    from app.services.github.github_provider import run_git

    seen: list[list[str]] = []

    def runner(args, *, cwd, env=None, timeout=None):
        seen.append(list(args))
        if "push" in args or "ls-remote" in args:
            return ""
        return run_git(args, cwd=cwd, env=env, timeout=timeout)

    result = GitHubProvider("ghp_fake", github_client=FakeGitHub(), git_runner=runner).create_pull_request(
        PullRequestSpec(workspace_path=ws, base_branch="main", head_branch="sentinel-chain/test", title="t", body="b",
                        commit_message="c", changed_files=["requirements.txt"], repo_full_name="example/demo")
    )
    assert result.status == "FAILED" and "stop before network" in (result.error or "")
    assert git.Repo(ws).head.commit.message.startswith("c")  # the commit itself happened
    assert not marker.exists(), "repository hook executed on the host"
    commit_args = next(a for a in seen if "commit" in a)
    assert "--no-verify" in commit_args
    assert all(list(SAFE_GIT_OPTIONS) == a[: len(SAFE_GIT_OPTIONS)] for a in seen)


def test_hooks_still_neutralised_even_if_copied(tmp_path):
    """Belt and braces: with a hook present in the working copy, the -c overrides stop it."""
    marker = tmp_path / "HOOK_RAN_ON_HOST"
    source = make_repo(tmp_path / "repo", hook_marker=marker)
    ws = tmp_path / "ws"
    shutil.copytree(source, ws, symlinks=True)  # raw copy, no hardening at all
    (ws / "requirements.txt").write_text("requests==2.33.0\n")
    from app.services.github.github_provider import run_git

    run_git([*SAFE_GIT_OPTIONS, "add", "--", "requirements.txt"], cwd=ws)
    run_git([*SAFE_GIT_OPTIONS, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "--no-verify", "-m", "x"], cwd=ws)
    assert not marker.exists()


def test_sanitize_config_keeps_only_safe_keys(tmp_path):
    config = tmp_path / "config"
    config.write_text(MALICIOUS_CONFIG)
    dropped = sanitize_git_config(config)
    text = config.read_text()
    for forbidden in ("hooksPath", "fsmonitor", "sshCommand", "uploadpack", "insteadOf", "filter", "smudge", "external", "include", "alias", "attacker.example"):
        assert forbidden not in text, forbidden
    assert 'url = https://github.com/example/demo.git' in text
    assert "fetch = +refs/heads/*:refs/remotes/origin/*" in text
    assert '[branch "main"]' in text and "merge = refs/heads/main" in text
    assert {"core.hookspath", "core.fsmonitor", "core.sshcommand", "url.https://attacker.example/.insteadof", "filter.evil.clean", "include.path", "alias.co"} <= set(dropped)
    # the result is a valid git config that GitPython can parse
    reader = git.GitConfigParser(str(config), read_only=True)
    assert reader.get_value('remote "origin"', "url") == "https://github.com/example/demo.git"


def test_harden_git_dir_removes_hooks_and_pointers(tmp_path):
    root = tmp_path / "ws"
    (root / ".git" / "hooks").mkdir(parents=True)
    (root / ".git" / "hooks" / "pre-push").write_text("#!/bin/sh\n")
    (root / ".git" / "config").write_text(MALICIOUS_CONFIG)
    notes = harden_git_dir(root)
    assert not (root / ".git" / "hooks").exists()
    assert "fsmonitor" not in (root / ".git" / "config").read_text()
    assert any("hooks removed" in n for n in notes) and any("config entries removed" in n for n in notes)

    # .git as a gitdir pointer file (worktree) → removed so commits cannot land elsewhere
    other = tmp_path / "ws2"
    other.mkdir()
    (other / ".git").write_text("gitdir: /some/other/repo/.git\n")
    notes = harden_git_dir(other)
    assert not (other / ".git").exists() and any("removed" in n for n in notes)

    # .git as a symlink to another repository → removed
    target = tmp_path / "victim"
    git.Repo.init(target, initial_branch="main")
    linked = tmp_path / "ws3"
    linked.mkdir()
    (linked / ".git").symlink_to(target / ".git")
    harden_git_dir(linked)
    assert not (linked / ".git").exists() and (target / ".git").exists()


def test_copytree_ignore_skips_git_hooks_only_inside_git(tmp_path):
    ignore = copytree_ignore()
    assert ignore(str(tmp_path / ".git"), ["hooks", "config", "refs"]) == {"hooks"}
    assert ignore(str(tmp_path / "src"), ["hooks", "app.py"]) == set()


def test_local_ingest_hardens_the_copy(tmp_path):
    from app.core.config import Settings
    from app.services.repository.base import RepositorySource
    from app.services.repository.local_provider import LocalRepositoryProvider
    from app.models.enums import SourceType

    marker = tmp_path / "HOOK_RAN_ON_HOST"
    source = make_repo(tmp_path / "repo", hook_marker=marker)
    (source / ".git" / "config").write_text(MALICIOUS_CONFIG)
    provider = LocalRepositoryProvider(Settings(_env_file=None, repository_workspace=str(tmp_path / "ws")))
    fetched = provider.fetch(RepositorySource(str(source), SourceType.LOCAL), tmp_path / "ws" / "repos" / "1")
    copy = fetched.local_path
    assert not (copy / ".git" / "hooks").exists()
    assert "fsmonitor" not in (copy / ".git" / "config").read_text()
    assert fetched.github_full_name == "example/demo"  # the remote url survived sanitisation
    assert any("config entries removed" in w for w in fetched.warnings)
