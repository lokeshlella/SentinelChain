"""GitHub repository provider: URL validation + cloning with GitPython.

Accepted locations (anything else is rejected with ``ValidationFailedError``)::

    https://github.com/owner/repo
    https://github.com/owner/repo.git
    https://github.com/owner/repo/tree/<branch>
    http(s)://www.github.com/owner/repo
    git@github.com:owner/repo.git

Every form is canonicalised to ``https://github.com/owner/repo`` and cloned
over HTTPS. When ``settings.github_token`` is configured it is embedded as
``https://x-access-token:<token>@github.com/...`` for the clone command only:
it is removed from the remote URL afterwards, never logged and redacted from
error messages.

Deviation from the contract's "clones with GitPython": the ``git clone`` /
``git ls-remote`` processes are started with :mod:`subprocess` in their own
process group (see :meth:`GitHubRepositoryProvider._run_git`) because
GitPython's ``kill_after_timeout`` cannot enforce ``settings.git_clone_timeout``:
it only kills the parent ``git`` and looks for children with ``ps --ppid``
(not available on macOS, and the ``git-remote-https`` helper is a grandchild
anyway), so the helper survives holding the output pipes and the call blocks
until the helper's own network timeout. GitPython is still used for everything
else (inspecting the clone, remote handling, error types).
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar
from urllib.parse import urlsplit

import git
from git.exc import GitCommandError, GitCommandNotFound, InvalidGitRepositoryError

from app.core.config import Settings, get_settings
from app.core.exceptions import RepositoryError, ValidationFailedError
from app.core.logging import get_stage_logger
from app.models.enums import SourceType
from app.services.repository.base import FetchedRepository, RepositoryProvider, RepositorySource

logger = get_stage_logger("Repository")

ACCEPTED_URL_FORMS: tuple[str, ...] = (
    "https://github.com/owner/repo",
    "https://github.com/owner/repo.git",
    "https://github.com/owner/repo/tree/<branch>",
    "git@github.com:owner/repo.git",
)
_ACCEPTED_HINT = "Accepted forms: " + ", ".join(ACCEPTED_URL_FORMS) + "."

_GITHUB_HOSTS = frozenset({"github.com", "www.github.com"})
_SSH_RE = re.compile(r"^git@github\.com:(?P<path>.+)$", re.IGNORECASE)
_SCHEMELESS_RE = re.compile(r"^(?:www\.)?github\.com/", re.IGNORECASE)
_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_TOKEN_IN_URL_RE = re.compile(r"(x-access-token:)[^@\s'\"]+@", re.IGNORECASE)
_STDERR_WRAPPER_RE = re.compile(r"^\s*stderr:\s*'(?P<body>.*)'\s*$", re.DOTALL)
_SYMREF_HEAD_RE = re.compile(r"^ref:\s*refs/heads/(?P<branch>\S+)\s+HEAD\s*$", re.MULTILINE)

# Seconds to wait for a killed git process group to release its pipes before giving up on it.
_KILL_GRACE_SECONDS = 5.0

# Environment for every git process we start: no interactive prompts (a missing token must
# fail, not hang) and English messages so the stderr markers below match.
_GIT_ENV_OVERRIDES: dict[str, str] = {
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_ASKPASS": "",
    "LANGUAGE": "C",
    "LC_ALL": "C",
}

# Substrings of git's stderr that identify a failure class (checked case-insensitively).
_NOT_ACCESSIBLE_MARKERS = (
    "repository not found",
    "not found",
    "does not exist",
    "does not appear to be a git repository",
    "could not read from remote repository",
    "could not read username",
    "authentication failed",
    "invalid username or password",
    "permission denied",
    "http basic: access denied",
    "the requested url returned error: 403",
    "the requested url returned error: 401",
)
_BRANCH_MARKERS = ("remote branch", "could not find remote branch")
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


@dataclass(frozen=True)
class ParsedGitHubUrl:
    """Result of :func:`parse_github_url`."""

    owner: str
    repo: str
    branch: str | None = None

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.repo}"

    @property
    def https_url(self) -> str:
        """Canonical, token-less URL stored as ``source_url``."""
        return f"https://github.com/{self.owner}/{self.repo}"

    @property
    def clone_url(self) -> str:
        return f"{self.https_url}.git"


def parse_github_url(location: str) -> ParsedGitHubUrl:
    """Parse and validate a GitHub repository location.

    Raises ``ValidationFailedError`` listing the accepted forms for anything that is
    not one of them (other hosts, ``owner/repo`` shorthands, ``/blob/...`` links,
    URLs with embedded credentials, ...).
    """
    text = (location or "").strip()
    if not text:
        raise ValidationFailedError("Repository URL is empty. " + _ACCEPTED_HINT)
    if any(ch.isspace() for ch in text):
        raise ValidationFailedError(f"Repository URL {text!r} contains whitespace. " + _ACCEPTED_HINT)

    ssh_match = _SSH_RE.match(text)
    if ssh_match:
        path = ssh_match.group("path")
    else:
        path = _path_from_http_url(text)

    segments = [segment for segment in path.split("/") if segment]
    if len(segments) < 2:
        raise ValidationFailedError(
            f"GitHub URL {text!r} must contain both an owner and a repository name. " + _ACCEPTED_HINT
        )
    owner, repo, rest = segments[0], segments[1], segments[2:]
    branch: str | None = None
    if rest:
        if rest[0] == "tree" and len(rest) >= 2:
            branch = "/".join(rest[1:])
        else:
            raise ValidationFailedError(
                f"Unsupported GitHub URL path '/{'/'.join(segments)}': only '/tree/<branch>' may follow "
                "the repository name. " + _ACCEPTED_HINT
            )
    if repo.lower().endswith(".git"):
        repo = repo[:-4]
    if not _OWNER_RE.match(owner):
        raise ValidationFailedError(f"Invalid GitHub owner {owner!r} in {text!r}. " + _ACCEPTED_HINT)
    if not _REPO_RE.match(repo) or repo in {".", ".."}:
        raise ValidationFailedError(f"Invalid GitHub repository name {repo!r} in {text!r}. " + _ACCEPTED_HINT)
    if branch is not None:
        validate_branch_name(branch)
    return ParsedGitHubUrl(owner=owner, repo=repo, branch=branch)


def _path_from_http_url(text: str) -> str:
    """Return the path of an ``http(s)://github.com/...`` URL or raise."""
    if _SCHEMELESS_RE.match(text):
        raise ValidationFailedError(
            f"GitHub URL {text!r} is missing the scheme; use https://{text}. " + _ACCEPTED_HINT
        )
    parsed = urlsplit(text)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValidationFailedError(f"{text!r} is not a supported GitHub URL. " + _ACCEPTED_HINT)
    if (parsed.hostname or "").lower() not in _GITHUB_HOSTS:
        raise ValidationFailedError(
            f"{text!r} does not point to github.com (host {parsed.hostname!r}). " + _ACCEPTED_HINT
        )
    if parsed.username or parsed.password:
        raise ValidationFailedError(
            "Do not embed credentials in the repository URL; configure GITHUB_TOKEN instead. " + _ACCEPTED_HINT
        )
    return parsed.path


_BRANCH_FORBIDDEN_RE = re.compile(r"[\s~^:?*\[\\\x00-\x1f\x7f]")


def validate_branch_name(name: str) -> None:
    """Reject branch names git would refuse or that could be mistaken for options."""
    problems: list[str] = []
    if not name:
        problems.append("is empty")
    if name.startswith("-"):
        problems.append("must not start with '-'")
    if _BRANCH_FORBIDDEN_RE.search(name):
        problems.append("contains whitespace or one of ~ ^ : ? * [ \\")
    if ".." in name or "@{" in name or "//" in name:
        problems.append("must not contain '..', '@{' or '//'")
    if name.endswith(("/", ".", ".lock")) or name.startswith("/"):
        problems.append("must not start or end with '/' or end with '.' or '.lock'")
    if any(part.startswith(".") for part in name.split("/")):
        problems.append("path components must not start with '.'")
    if problems:
        raise ValidationFailedError(f"Invalid branch name {name!r}: " + "; ".join(problems))


def parse_github_remote(url: str | None) -> str | None:
    """Lenient ``owner/repo`` extraction from a git remote URL (any common syntax).

    Used for the ``origin`` remote of local repositories; returns None for
    non-GitHub remotes instead of raising.
    """
    if not url:
        return None
    text = url.strip()
    match = re.match(r"^(?:ssh://)?git@github\.com[:/](?P<path>.+)$", text, re.IGNORECASE)
    if match:
        path = match.group("path")
    else:
        parsed = urlsplit(text)
        if (parsed.hostname or "").lower() not in _GITHUB_HOSTS:
            return None
        path = parsed.path
    segments = [segment for segment in path.split("/") if segment]
    if len(segments) < 2:
        return None
    owner, repo = segments[0], segments[1]
    if repo.lower().endswith(".git"):
        repo = repo[:-4]
    if not _OWNER_RE.match(owner) or not _REPO_RE.match(repo):
        return None
    return f"{owner}/{repo}"


class GitHubRepositoryProvider(RepositoryProvider):
    """Clones GitHub repositories into a workspace directory owned by Sentinel Chain."""

    source_type: ClassVar[SourceType] = SourceType.GITHUB

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()

    # ------------------------------------------------------------------ contract

    def supports(self, location: str) -> bool:
        """True when the location is *meant* for GitHub (strict validation happens in ``validate``)."""
        text = (location or "").strip().lower()
        if not text:
            return False
        if _SSH_RE.match(text) or _SCHEMELESS_RE.match(text):
            return True
        if text.startswith(("http://", "https://")):
            return (urlsplit(text).hostname or "") in _GITHUB_HOSTS
        return False

    def normalize(self, source: RepositorySource) -> RepositorySource:
        parsed = parse_github_url(source.location)
        branch = source.branch or parsed.branch
        if branch:
            validate_branch_name(branch)
        return RepositorySource(location=parsed.https_url, source_type=SourceType.GITHUB, branch=branch)

    def validate(self, source: RepositorySource) -> None:
        """Format validation only (no network); inaccessible repositories fail at ``fetch``."""
        self.normalize(source)

    def default_branch(self, source: RepositorySource) -> str | None:
        """Branch the remote ``HEAD`` points at (``git ls-remote --symref``), None if it has none.

        Uses the same URL, credentials, timeout and error mapping as the clone, so an
        inaccessible repository raises the RepositoryError the clone would raise.
        """
        parsed = parse_github_url(source.location)
        url, token_used = self._clone_url(parsed)
        command = self._git_command(token_used) + ["ls-remote", "--symref", "--", url, "HEAD"]
        try:
            output = self._run_git(command, timeout=self.settings.git_clone_timeout)
        except (GitCommandError, GitCommandNotFound) as exc:
            raise self._map_git_error(exc, parsed, None, action="ls-remote") from None
        match = _SYMREF_HEAD_RE.search(output)
        branch = match.group("branch") if match else None
        logger.info("Default branch of %s is %s", parsed.full_name, branch or "unknown")
        return branch

    def fetch(self, source: RepositorySource, destination: Path) -> FetchedRepository:
        parsed = parse_github_url(source.location)
        branch = source.branch or parsed.branch
        if branch:
            validate_branch_name(branch)
        clone_url, token_used = self._clone_url(parsed)
        destination = Path(destination)
        self._prepare_destination(destination)

        logger.info(
            "Cloning %s (branch=%s, auth=%s) into %s",
            parsed.https_url, branch or "default", "token" if token_used else "none", destination,
        )
        try:
            self._run_clone(clone_url, destination, branch)
        except (GitCommandError, GitCommandNotFound) as exc:
            self._remove_tree(destination)
            raise self._map_git_error(exc, parsed, branch) from None
        except OSError as exc:
            self._remove_tree(destination)
            raise RepositoryError(f"Could not clone {parsed.https_url}: {self._redact(str(exc))}") from exc

        try:
            repo = git.Repo(destination)
        except InvalidGitRepositoryError as exc:
            raise RepositoryError(f"Clone of {parsed.https_url} did not produce a git repository") from exc
        try:
            if token_used:
                self._strip_token_from_remote(repo, parsed)
            fetched = self._describe(repo, parsed, branch, destination)
        finally:
            repo.close()  # stop GitPython's persistent cat-file helpers
        logger.info(
            "Cloned %s @ %s (%s)", parsed.full_name, fetched.branch or "detached",
            (fetched.commit_sha or "no commits")[:12],
        )
        return fetched

    # ------------------------------------------------------------------ helpers

    def _clone_url(self, parsed: ParsedGitHubUrl) -> tuple[str, bool]:
        """Return (url used for the clone command, whether a token was embedded)."""
        token = (self.settings.github_token or "").strip()
        if not token:
            return parsed.clone_url, False
        return f"https://x-access-token:{token}@github.com/{parsed.owner}/{parsed.repo}.git", True

    def _run_clone(self, clone_url: str, destination: Path, branch: str | None) -> None:
        """Run ``git clone`` honouring ``settings.git_clone_timeout`` (see module docstring).

        ``clone_url`` may also be a local path (used by the offline tests).
        """
        command = self._clone_command(clone_url, destination, branch)
        self._run_git(command, timeout=self.settings.git_clone_timeout)

    def _clone_command(self, clone_url: str, destination: Path, branch: str | None) -> list[str]:
        command = self._git_command(token_embedded="x-access-token:" in clone_url)
        command += ["clone", "--single-branch"]
        if branch:
            command += ["--branch", branch]
        command += ["--", clone_url, str(destination)]
        return command

    @staticmethod
    def _git_command(token_embedded: bool) -> list[str]:
        command = [git.Git.GIT_PYTHON_GIT_EXECUTABLE]
        if token_embedded:
            # Never let a credential helper persist the embedded token.
            command += ["-c", "credential.helper="]
        return command

    def _run_git(self, command: list[str], *, timeout: float | None) -> str:
        """Run a git command to completion and return its stdout.

        The process is started in its own session/process group so that the whole tree
        (``git`` plus the ``git remote-https`` / ``git-remote-https`` helpers it forks) can
        be killed when ``timeout`` (seconds; None or 0 disables it) elapses. Failures are
        raised as GitPython's ``GitCommandError`` / ``GitCommandNotFound`` (token redacted)
        so :meth:`_map_git_error` can classify them; a timeout is a ``GitCommandError``
        with status -9 and a ``Timeout: ...`` stderr, the shape GitPython itself uses.
        """
        redacted = [self._redact(part) for part in command]
        env = {**os.environ, **_GIT_ENV_OVERRIDES}
        try:
            proc = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                start_new_session=True,
            )
        except FileNotFoundError as exc:
            raise GitCommandNotFound(redacted, exc) from exc

        try:
            stdout, stderr = proc.communicate(timeout=timeout or None)
        except subprocess.TimeoutExpired:
            self._kill_process_tree(proc)
            what = " ".join(redacted[:2])
            raise GitCommandError(
                redacted, -9, stderr=f'Timeout: the command "{what}" did not complete in {timeout} secs.'
            ) from None
        except BaseException:  # interrupted (KeyboardInterrupt, ...): do not leave git behind
            self._kill_process_tree(proc)
            raise
        if proc.returncode != 0:
            raise GitCommandError(redacted, proc.returncode, stderr=stderr, stdout=stdout)
        return stdout.decode("utf-8", "replace")

    @staticmethod
    def _kill_process_tree(proc: subprocess.Popen) -> None:
        """SIGKILL the process group started by :meth:`_run_git` and reap the direct child."""
        try:
            if hasattr(os, "killpg"):
                os.killpg(proc.pid, signal.SIGKILL)
            else:  # pragma: no cover - Windows has no process groups in this sense
                proc.kill()
        except ProcessLookupError:
            pass
        try:
            proc.communicate(timeout=_KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:  # pragma: no cover - a helper outside the group kept a pipe open
            for stream in (proc.stdout, proc.stderr):
                if stream is not None:
                    stream.close()
            proc.wait()

    def _strip_token_from_remote(self, repo: git.Repo, parsed: ParsedGitHubUrl) -> None:
        """Reset ``origin`` to the token-less URL so the token never stays in ``.git/config``."""
        try:
            repo.remotes.origin.set_url(parsed.clone_url)
        except (GitCommandError, AttributeError, IndexError) as exc:
            # Do not leave a token behind: drop the remote entirely rather than keep it.
            logger.warning("Could not rewrite origin URL for %s (%s); removing remote", parsed.full_name, exc)
            try:
                repo.delete_remote("origin")
            except (GitCommandError, ValueError):
                pass

    @staticmethod
    def _describe(repo: git.Repo, parsed: ParsedGitHubUrl, requested_branch: str | None, destination: Path) -> FetchedRepository:
        warnings: list[str] = []
        try:
            branch: str | None = repo.active_branch.name
        except TypeError:
            branch = requested_branch
            warnings.append("Clone has a detached HEAD")
        try:
            sha: str | None = repo.head.commit.hexsha
        except ValueError:
            sha = None
            warnings.append("Repository has no commits")
        return FetchedRepository(
            name=parsed.repo,
            source_url=parsed.https_url,
            source_type=SourceType.GITHUB,
            local_path=destination,
            branch=branch,
            commit_sha=sha,
            is_git=True,
            github_full_name=parsed.full_name,
            warnings=warnings,
        )

    @staticmethod
    def _prepare_destination(destination: Path) -> None:
        if destination.exists():
            shutil.rmtree(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _remove_tree(path: Path) -> None:
        shutil.rmtree(path, ignore_errors=True)

    def _redact(self, text: str) -> str:
        """Remove the configured token (and any x-access-token credential) from ``text``."""
        token = (self.settings.github_token or "").strip()
        if token:
            text = text.replace(token, "***")
        return _TOKEN_IN_URL_RE.sub(r"\1***@", text)

    @staticmethod
    def _git_stderr(exc: GitCommandError) -> str:
        raw = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode("utf-8", "replace")
        match = _STDERR_WRAPPER_RE.match(raw)
        return (match.group("body") if match else raw).strip()

    def _map_git_error(
        self,
        exc: GitCommandError | GitCommandNotFound,
        parsed: ParsedGitHubUrl,
        branch: str | None,
        action: str = "clone",
    ) -> RepositoryError:
        """Translate a git failure into a RepositoryError with a clear, token-free message.

        ``action`` is the git sub-command that failed (``clone`` or ``ls-remote``).
        """
        details = {"source_url": parsed.https_url, "branch": branch}
        if isinstance(exc, GitCommandNotFound):
            return RepositoryError("git is not installed or not on PATH; cannot clone repositories", details=details)
        stderr = self._redact(self._git_stderr(exc))
        lowered = stderr.lower()
        details["git_status"] = exc.status
        details["git_stderr"] = stderr[-1000:]
        timeout = self.settings.git_clone_timeout
        target = f"{parsed.https_url}" + (f" (branch '{branch}')" if branch else "")
        doing = "Cloning" if action == "clone" else f"Querying (git {action})"

        if lowered.startswith("timeout:") or "did not complete in" in lowered:
            return RepositoryError(f"{doing} {target} timed out after {timeout}s", details=details)
        if branch and any(marker in lowered for marker in _BRANCH_MARKERS):
            return RepositoryError(f"Branch '{branch}' not found in {parsed.https_url}", details=details)
        if any(marker in lowered for marker in _NOT_ACCESSIBLE_MARKERS):
            hint = (
                "Check the URL; for private repositories configure GITHUB_TOKEN."
                if not self.settings.github_token
                else "Check the URL and that GITHUB_TOKEN has access to this repository."
            )
            return RepositoryError(f"Repository not found or not accessible: {target}. {hint}", details=details)
        if any(marker in lowered for marker in _NETWORK_MARKERS):
            return RepositoryError(f"Network error while {doing.lower()} {target}: {stderr}", details=details)
        return RepositoryError(f"git {action} of {target} failed (exit {exc.status}): {stderr}", details=details)
