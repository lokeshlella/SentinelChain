"""GitHub pull request provider: branch → commit → push → DRAFT pull request.

Everything happens inside ``spec.workspace_path`` (the validated working copy,
which is a git clone). The flow is:

1. open the working copy with GitPython (not a repository → ``FAILED``);
2. resolve ``owner/repo`` from the spec or the ``origin`` remote (no GitHub
   remote → ``UNAVAILABLE``, the change can only be pushed manually);
3. create ``spec.head_branch`` from the current ``HEAD`` (a stale local branch of
   that name is deleted first), stage ``spec.changed_files`` and commit as
   ``Sentinel Chain <sentinel-chain@localhost>`` via ``GIT_AUTHOR_*`` /
   ``GIT_COMMITTER_*`` environment variables (the user's git config is never touched);
4. push over HTTPS with ``x-access-token:<token>`` embedded in a URL that is only
   ever passed on the ``git push`` command line — never written to ``.git/config``,
   never logged, and redacted from any error text (:func:`redact`);
5. open the pull request with PyGithub (``draft=True``); an already open pull
   request for the same head branch is returned instead of failing.

Nothing is merged, ever. Without a token the provider does nothing to the
workspace and returns ``UNAVAILABLE`` with manual instructions.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, ClassVar, Protocol

import git
from git.exc import GitCommandError, GitCommandNotFound, InvalidGitRepositoryError, NoSuchPathError
from github import Auth, Github, GithubException

from app.core.config import get_settings
from app.core.logging import get_stage_logger
from app.models.enums import PullRequestStatus
from app.services.github.base import GitProvider, PullRequestResult, PullRequestSpec
from app.services.github.instructions import build_manual_instructions
from app.services.repository.github_provider import parse_github_remote

log = get_stage_logger("GitHub")

COMMIT_AUTHOR_NAME = "Sentinel Chain"
COMMIT_AUTHOR_EMAIL = "sentinel-chain@localhost"

#: Environment for every git process that may talk to the network: never prompt for
#: credentials (a missing/invalid token must fail, not hang) and keep messages in English.
NETWORK_GIT_ENV: dict[str, str] = {
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_ASKPASS": "",
    "LANGUAGE": "C",
    "LC_ALL": "C",
}
#: Identity for the commit, passed per process so the user's global config stays untouched.
COMMIT_ENV: dict[str, str] = {
    "GIT_AUTHOR_NAME": COMMIT_AUTHOR_NAME,
    "GIT_AUTHOR_EMAIL": COMMIT_AUTHOR_EMAIL,
    "GIT_COMMITTER_NAME": COMMIT_AUTHOR_NAME,
    "GIT_COMMITTER_EMAIL": COMMIT_AUTHOR_EMAIL,
}

_TOKEN_IN_URL_RE = re.compile(r"(x-access-token:)[^@\s'\"]+@", re.IGNORECASE)
_CREDENTIALS_IN_URL_RE = re.compile(r"(https?://[^/\s@:]+:)[^@\s]+@", re.IGNORECASE)
_STDERR_WRAPPER_RE = re.compile(r"^\s*stderr:\s*'(?P<body>.*)'\s*$", re.DOTALL)
_DRAFT_UNSUPPORTED_MARKER = "draft pull requests are not supported"
_PR_EXISTS_MARKER = "pull request already exists"

_AUTH_MARKERS = (
    "authentication failed",
    "invalid username or password",
    "permission denied",
    "permission to",
    "http basic: access denied",
    "returned error: 401",
    "returned error: 403",
    "could not read username",
    "could not read password",
)
_NOT_FOUND_MARKERS = ("repository not found", "returned error: 404")
_NETWORK_MARKERS = (
    "could not resolve host",
    "unable to access",
    "connection refused",
    "failed to connect",
    "network is unreachable",
    "connection timed out",
    "operation timed out",
    "ssl",
)


def redact(text: Any, token: str | None) -> str:
    """Remove ``token`` (and any credential embedded in a URL) from ``text``."""
    out = "" if text is None else str(text)
    if token:
        out = out.replace(token, "***")
    out = _TOKEN_IN_URL_RE.sub(r"\1***@", out)
    return _CREDENTIALS_IN_URL_RE.sub(r"\1***@", out)


class GitRunner(Protocol):
    """Runs one git command in ``cwd`` and returns its stdout (raises ``GitCommandError``)."""

    def __call__(
        self,
        args: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> str: ...


def run_git(
    args: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str] | None = None,
    timeout: float | None = None,
) -> str:
    """Default :class:`GitRunner`: GitPython ``Git.execute`` with ``kill_after_timeout``.

    ``env`` is merged over the inherited environment for this process only.
    A ``timeout`` of ``None``/``0`` disables the watchdog.
    """
    command = [git.Git.GIT_PYTHON_GIT_EXECUTABLE, *args]
    output = git.Git(str(cwd)).execute(
        command,
        env=dict(env) if env else None,
        kill_after_timeout=timeout or None,
    )
    return output if isinstance(output, str) else output.decode("utf-8", "replace")


class _PullRequestFailure(Exception):
    """Internal: aborts the flow with a user-facing message and a result status."""

    def __init__(self, message: str, *, status: PullRequestStatus = PullRequestStatus.FAILED):
        super().__init__(message)
        self.message = message
        self.status = status


class GitHubProvider(GitProvider):
    """Creates draft pull requests on GitHub for a validated working copy."""

    name: ClassVar[str] = "github"

    def __init__(
        self,
        token: str | None,
        *,
        github_client: Any | None = None,
        git_runner: GitRunner | None = None,
        timeout: float | None = None,
    ):
        """``github_client`` is a PyGithub ``Github`` (or a fake); ``git_runner`` a :class:`GitRunner`.

        ``timeout`` (seconds) bounds the network git commands; defaults to
        ``settings.git_clone_timeout``.
        """
        self._token: str | None = (token or "").strip() or None
        self._github_client = github_client
        self._run: GitRunner = git_runner or run_git
        self._timeout: float | None = timeout if timeout is not None else get_settings().git_clone_timeout

    # ------------------------------------------------------------------ contract

    def is_configured(self) -> bool:
        return bool(self._token)

    def create_pull_request(self, spec: PullRequestSpec) -> PullRequestResult:
        branch = spec.head_branch
        if not self.is_configured():
            log.info("Pull request for branch %s not created: GITHUB_TOKEN is not configured", branch)
            return self._unavailable(spec, "GITHUB_TOKEN is not configured")
        try:
            return self._create(spec)
        except _PullRequestFailure as exc:
            message = self.redact(exc.message)
            log.warning("Pull request for branch %s %s: %s", branch, exc.status.lower(), message)
            if exc.status == PullRequestStatus.UNAVAILABLE:
                return self._unavailable(spec, message)
            return self._failed(spec, message)
        except Exception as exc:  # noqa: BLE001 - never leak a token or crash the caller
            message = self.redact(f"{type(exc).__name__}: {exc}")
            log.error("Pull request for branch %s failed unexpectedly: %s", branch, message)
            return self._failed(spec, message)

    # ------------------------------------------------------------------ flow

    def _create(self, spec: PullRequestSpec) -> PullRequestResult:
        workspace = Path(spec.workspace_path)
        repo = self._open_repo(workspace)
        try:
            full_name = self._resolve_full_name(spec, repo)
            remote_head = self._remote_head(workspace)
            self._prepare_branch(repo, workspace, spec.head_branch)
            commit_sha = self._stage_and_commit(repo, workspace, spec)
        finally:
            repo.close()  # stop GitPython's persistent cat-file helpers
        self._push(workspace, full_name, spec.head_branch)
        result = self._open_pull_request(spec, full_name, remote_head)
        result.commit_sha = commit_sha
        return result

    @staticmethod
    def _open_repo(workspace: Path) -> git.Repo:
        try:
            return git.Repo(workspace)
        except NoSuchPathError:
            raise _PullRequestFailure(f"Workspace {workspace} does not exist; run the remediation again") from None
        except InvalidGitRepositoryError:
            raise _PullRequestFailure(
                f"Workspace {workspace} is not a git repository; the change must be applied and pushed manually"
            ) from None

    @staticmethod
    def _resolve_full_name(spec: PullRequestSpec, repo: git.Repo) -> str:
        if spec.repo_full_name:
            return spec.repo_full_name
        try:
            origin_url = repo.remotes.origin.url
        except (AttributeError, IndexError, GitCommandError):
            origin_url = None
        full_name = parse_github_remote(origin_url)
        if not full_name:
            raise _PullRequestFailure(
                "Workspace is not a GitHub repository (no GitHub 'origin' remote); push the branch manually",
                status=PullRequestStatus.UNAVAILABLE,
            )
        return full_name

    def _remote_head(self, workspace: Path) -> str | None:
        """Branch ``refs/remotes/origin/HEAD`` points at (set by ``git clone``), if known."""
        try:
            ref = self._run(["symbolic-ref", "-q", "refs/remotes/origin/HEAD"], cwd=workspace).strip()
        except (GitCommandError, GitCommandNotFound):
            return None
        prefix = "refs/remotes/origin/"
        return ref[len(prefix):] if ref.startswith(prefix) else None

    def _prepare_branch(self, repo: git.Repo, workspace: Path, branch: str) -> None:
        """Check out ``branch`` at the current HEAD; a stale local branch is replaced."""
        if self._active_branch(repo) == branch:
            log.info("Branch %s is already checked out; reusing it", branch)
            return
        if branch in {head.name for head in repo.heads}:
            log.info("Deleting stale local branch %s", branch)
            self._git(["branch", "-D", branch], workspace)
        self._git(["checkout", "-b", branch], workspace)
        log.info("Created branch %s", branch)

    def _stage_and_commit(self, repo: git.Repo, workspace: Path, spec: PullRequestSpec) -> str:
        """Stage ``spec.changed_files`` and commit; returns the commit sha."""
        if not spec.changed_files:
            raise _PullRequestFailure("No changed files were given; nothing to commit")
        missing = [f for f in spec.changed_files if not (workspace / f).exists()]
        if missing:
            raise _PullRequestFailure(f"Changed file(s) not found in the workspace: {', '.join(missing)}")
        self._git(["add", "--", *spec.changed_files], workspace)
        staged = self._git(["diff", "--cached", "--name-only"], workspace).strip()
        if not staged:
            reused = self._reusable_commit(repo, spec.head_branch)
            if reused:
                log.info("No new changes; reusing existing Sentinel Chain commit %s", reused[:12])
                return reused
            raise _PullRequestFailure("No changes to commit: the workspace already matches HEAD")
        self._git(["-c", "commit.gpgsign=false", "commit", "-m", spec.commit_message], workspace, env=COMMIT_ENV)
        sha = self._git(["rev-parse", "HEAD"], workspace).strip()
        log.info("Committed %s on %s (%s)", ", ".join(staged.splitlines()), spec.head_branch, sha[:12])
        return sha

    def _reusable_commit(self, repo: git.Repo, branch: str) -> str | None:
        """The HEAD commit when it is a Sentinel Chain commit on ``branch`` (a retried push)."""
        if self._active_branch(repo) != branch:
            return None
        try:
            head = repo.head.commit
        except ValueError:
            return None
        if head.author.email == COMMIT_AUTHOR_EMAIL:
            return head.hexsha
        return None

    def _push(self, workspace: Path, full_name: str, branch: str) -> None:
        """``git push --force-with-lease`` to a one-off token URL given only on the command line."""
        url = f"https://x-access-token:{self._token}@github.com/{full_name}.git"
        expected = self._remote_branch_sha(workspace, url, branch)
        lease = f"--force-with-lease={branch}" + (f":{expected}" if expected else "")
        if expected:
            log.info("Remote branch %s exists on %s (%s); updating it", branch, full_name, expected[:12])
        args = ["-c", "credential.helper=", "push", lease, "--", url, f"HEAD:refs/heads/{branch}"]
        try:
            self._run(args, cwd=workspace, env=NETWORK_GIT_ENV, timeout=self._timeout)
        except GitCommandNotFound:
            raise _PullRequestFailure("git is not installed or not on PATH; cannot push") from None
        except GitCommandError as exc:
            raise _PullRequestFailure(self._describe_push_error(exc, full_name, branch)) from None
        log.info("Pushed %s to %s", branch, full_name)

    def _remote_branch_sha(self, workspace: Path, url: str, branch: str) -> str | None:
        """Current tip of ``refs/heads/<branch>`` on the remote (lease value), None when absent."""
        args = ["-c", "credential.helper=", "ls-remote", "--", url, f"refs/heads/{branch}"]
        try:
            output = self._run(args, cwd=workspace, env=NETWORK_GIT_ENV, timeout=self._timeout)
        except GitCommandNotFound:
            raise _PullRequestFailure("git is not installed or not on PATH; cannot push") from None
        except GitCommandError as exc:
            raise _PullRequestFailure(self._describe_push_error(exc, full_name_from_url(url), branch)) from None
        for line in output.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] == f"refs/heads/{branch}":
                return parts[0]
        return None

    def _describe_push_error(self, exc: GitCommandError, full_name: str, branch: str) -> str:
        stderr = self.redact(self._git_stderr(exc))
        lowered = stderr.lower()
        if lowered.startswith("timeout:") or "did not complete in" in lowered:
            return f"Pushing {branch} to {full_name} timed out after {self._timeout}s"
        if any(marker in lowered for marker in _AUTH_MARKERS):
            return (
                f"GitHub authentication failed or the token lacks push permission for {full_name}: {stderr}"
            )
        if any(marker in lowered for marker in _NOT_FOUND_MARKERS):
            return f"GitHub repository {full_name} not found or not accessible with the configured token: {stderr}"
        if "stale info" in lowered or "[rejected]" in lowered:
            return f"Push of {branch} to {full_name} was rejected (remote branch changed concurrently): {stderr}"
        if any(marker in lowered for marker in _NETWORK_MARKERS):
            return f"Network error while pushing {branch} to {full_name}: {stderr}"
        return f"git push of {branch} to {full_name} failed (exit {exc.status}): {stderr}"

    # ------------------------------------------------------------------ GitHub API

    def _open_pull_request(self, spec: PullRequestSpec, full_name: str, remote_head: str | None) -> PullRequestResult:
        client = self._github_client or Github(auth=Auth.Token(self._token or ""))
        gh_repo = self._api_call(lambda: client.get_repo(full_name), f"open repository {full_name}")
        base = spec.base_branch or remote_head or self._default_branch(gh_repo)
        if not base:
            raise _PullRequestFailure(f"Could not determine the base branch of {full_name}")
        owner = full_name.split("/", 1)[0]
        existing = self._existing_pull(gh_repo, owner, spec.head_branch)
        if existing is not None:
            return self._result_for(existing, spec.head_branch, full_name, reused=True)
        pull = self._create_pull(gh_repo, spec, base, owner)
        return self._result_for(pull, spec.head_branch, full_name, reused=False)

    def _create_pull(self, gh_repo: Any, spec: PullRequestSpec, base: str, owner: str) -> Any:
        kwargs = {"title": spec.title, "body": spec.body, "head": spec.head_branch, "base": base, "draft": spec.draft}
        try:
            return gh_repo.create_pull(**kwargs)
        except GithubException as exc:
            message = self._github_message(exc)
            lowered = message.lower()
            if exc.status == 422 and spec.draft and _DRAFT_UNSUPPORTED_MARKER in lowered:
                # Spec §17: default to a DRAFT PR. Opening a regular PR instead would silently
                # weaken that guarantee (audit F-12) — fail with manual instructions instead.
                raise _PullRequestFailure(
                    "GitHub does not support draft pull requests on this repository (plan/visibility limitation); "
                    "Sentinel Chain never opens non-draft pull requests. The branch was pushed — open the pull "
                    "request manually and mark it as a draft if possible."
                ) from None
            if exc.status == 422 and _PR_EXISTS_MARKER in lowered:
                existing = self._existing_pull(gh_repo, owner, spec.head_branch)
                if existing is not None:
                    return existing
            raise _PullRequestFailure(self._describe_github_error(exc, "create pull request")) from None
        except _PullRequestFailure:
            raise
        except Exception as exc:  # noqa: BLE001 - network / transport errors from PyGithub
            raise _PullRequestFailure(self._describe_transport_error(exc, "create pull request")) from None

    def _existing_pull(self, gh_repo: Any, owner: str, branch: str) -> Any | None:
        pulls = self._api_call(
            lambda: list(gh_repo.get_pulls(state="open", head=f"{owner}:{branch}")),
            f"list open pull requests for {owner}:{branch}",
        )
        return pulls[0] if pulls else None

    @staticmethod
    def _default_branch(gh_repo: Any) -> str | None:
        value = getattr(gh_repo, "default_branch", None)
        return str(value) if value else None

    def _api_call(self, call: Any, what: str) -> Any:
        try:
            return call()
        except GithubException as exc:
            raise _PullRequestFailure(self._describe_github_error(exc, what)) from None
        except Exception as exc:  # noqa: BLE001 - requests.ConnectionError & co.
            raise _PullRequestFailure(self._describe_transport_error(exc, what)) from None

    def _result_for(self, pull: Any, branch: str, full_name: str, *, reused: bool) -> PullRequestResult:
        status = PullRequestStatus.DRAFT if getattr(pull, "draft", False) else PullRequestStatus.OPEN
        number = getattr(pull, "number", None)
        url = getattr(pull, "html_url", None)
        log.info(
            "%s pull request #%s on %s (%s): %s",
            "Reusing existing" if reused else "Opened", number, full_name, status.lower(), url,
        )
        return PullRequestResult(status=status, branch=branch, url=url, number=number)

    def _describe_github_error(self, exc: GithubException, what: str) -> str:
        message = self.redact(self._github_message(exc))
        if exc.status in (401, 403):
            return (
                f"GitHub authentication failed or the token lacks permission to {what} "
                f"(HTTP {exc.status}): {message}"
            )
        if exc.status == 404:
            return f"GitHub repository not found or the token cannot see it (HTTP 404) while trying to {what}"
        if exc.status == 422:
            return f"GitHub rejected the request to {what} (HTTP 422): {message}"
        return f"GitHub API error while trying to {what} (HTTP {exc.status}): {message}"

    def _describe_transport_error(self, exc: Exception, what: str) -> str:
        return f"GitHub API unreachable while trying to {what}: {self.redact(f'{type(exc).__name__}: {exc}')}"

    @staticmethod
    def _github_message(exc: GithubException) -> str:
        data = exc.data if isinstance(exc.data, dict) else {}
        parts: list[str] = []
        top = data.get("message") or exc.message
        if top:
            parts.append(str(top))
        for error in data.get("errors") or []:
            text = error.get("message") if isinstance(error, dict) else error
            if text:
                parts.append(str(text))
        return "; ".join(parts) if parts else f"HTTP {exc.status}"

    # ------------------------------------------------------------------ helpers

    def _git(self, args: Sequence[str], workspace: Path, env: Mapping[str, str] | None = None) -> str:
        """Run a local git command through the runner, mapping failures to a FAILED result."""
        try:
            return self._run(args, cwd=workspace, env=env)
        except GitCommandNotFound:
            raise _PullRequestFailure("git is not installed or not on PATH") from None
        except GitCommandError as exc:
            what = _subcommand(args)
            raise _PullRequestFailure(f"git {what} failed: {self.redact(self._git_stderr(exc))}") from None

    @staticmethod
    def _active_branch(repo: git.Repo) -> str | None:
        try:
            return repo.active_branch.name
        except TypeError:  # detached HEAD
            return None

    @staticmethod
    def _git_stderr(exc: GitCommandError) -> str:
        raw = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode("utf-8", "replace")
        match = _STDERR_WRAPPER_RE.match(raw)
        text = (match.group("body") if match else raw).strip()
        return text or str(exc)

    def redact(self, text: Any) -> str:
        return redact(text, self._token)

    def _unavailable(self, spec: PullRequestSpec, reason: str) -> PullRequestResult:
        return PullRequestResult(
            status=PullRequestStatus.UNAVAILABLE,
            branch=spec.head_branch,
            instructions=self._instructions(spec, reason, failed=False),
            error=reason,
        )

    def _failed(self, spec: PullRequestSpec, reason: str) -> PullRequestResult:
        return PullRequestResult(
            status=PullRequestStatus.FAILED,
            branch=spec.head_branch,
            instructions=self._instructions(spec, reason, failed=True),
            error=reason,
        )

    @staticmethod
    def _instructions(spec: PullRequestSpec, reason: str, *, failed: bool) -> str:
        return build_manual_instructions(
            workspace_path=spec.workspace_path,
            branch=spec.head_branch,
            changed_files=spec.changed_files,
            title=spec.title,
            reason=reason,
            failed=failed,
        )


def _subcommand(args: Sequence[str]) -> str:
    """The git sub-command in ``args`` (skipping ``-c key=value`` overrides), for messages."""
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg == "-c":
            skip_next = True
            continue
        return arg
    return "command"


def full_name_from_url(url: str) -> str:
    """``owner/repo`` for a GitHub URL (token-free); used only for messages."""
    return parse_github_remote(_TOKEN_IN_URL_RE.sub("", url)) or "the repository"
