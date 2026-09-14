"""Local directory provider: copies a repository on disk into the workspace.

The user's original directory is never modified; Sentinel Chain works on the
copy. Build artefacts and virtual environments are not copied (see
:mod:`app.services.repository.ignore`), ``.git`` is kept so commit metadata and
GitHub remotes stay available for evidence and pull requests.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import ClassVar

import git
from git.exc import GitCommandError, InvalidGitRepositoryError, NoSuchPathError

from app.core.config import Settings, get_settings
from app.core.exceptions import RepositoryError, ValidationFailedError
from app.core.logging import get_stage_logger
from app.models.enums import SourceType
from app.services.repository.base import FetchedRepository, RepositoryProvider, RepositorySource
from app.services.repository.github_provider import parse_github_remote
from app.services.repository.ignore import copytree_ignore

logger = get_stage_logger("Repository")

_MAX_COPY_WARNINGS = 5


def _looks_like_url(location: str) -> bool:
    return "://" in location or location.startswith("git@")


_SYSTEM_ROOTS = ("/usr", "/etc", "/bin", "/sbin", "/lib", "/var", "/private", "/System", "/Library",
                 "/Applications", "/opt", "/dev", "/proc", "/sys", "/boot", "/root")


def _is_system_root(path: Path) -> bool:
    """Filesystem anchors, the home directory and well-known system trees are never repositories."""
    resolved = path.resolve()
    if resolved == Path(resolved.anchor):
        return True
    try:
        if resolved == Path.home().resolve():
            return True
    except RuntimeError:  # no home directory (containers)
        pass
    return any(resolved == Path(root) for root in _SYSTEM_ROOTS)


class LocalRepositoryProvider(RepositoryProvider):
    """Copies an existing local directory into ``destination``."""

    source_type: ClassVar[SourceType] = SourceType.LOCAL

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()

    # ------------------------------------------------------------------ contract

    def supports(self, location: str) -> bool:
        """True when ``location`` is an existing directory (URLs are never local)."""
        text = (location or "").strip()
        if not text or _looks_like_url(text):
            return False
        try:
            return Path(text).expanduser().is_dir()
        except OSError:
            return False

    def normalize(self, source: RepositorySource) -> RepositorySource:
        # A local directory is copied exactly as checked out; a requested branch cannot
        # be honoured, so it is dropped here (the checked-out branch is recorded after
        # fetch) rather than stored as a misleading label.
        return RepositorySource(
            location=str(self._resolve(source.location)),
            source_type=SourceType.LOCAL,
            branch=None,
        )

    def validate(self, source: RepositorySource) -> None:
        """The path must exist, be a readable directory and not be Sentinel Chain's workspace."""
        path = self._resolve(source.location)
        if not path.exists():
            raise RepositoryError(f"Local path does not exist: {path}")
        if not path.is_dir():
            raise RepositoryError(f"Local path is not a directory: {path}")
        if not os.access(path, os.R_OK | os.X_OK):
            raise RepositoryError(f"Local path is not readable: {path}")
        if _is_system_root(path):
            raise ValidationFailedError(
                f"Refusing to copy a filesystem root or system directory as a repository: {path}",
                details={"path": str(path)},
            )
        workspace = self._workspace()
        if workspace is not None and (path == workspace or workspace in path.parents):
            raise ValidationFailedError(
                f"Refusing to use the Sentinel Chain workspace ({workspace}) as a repository source",
                details={"path": str(path), "workspace": str(workspace)},
            )

    def fetch(self, source: RepositorySource, destination: Path) -> FetchedRepository:
        self.validate(source)
        src = self._resolve(source.location)
        destination = Path(destination)
        if destination.exists():
            shutil.rmtree(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)

        warnings: list[str] = []
        skip: list[Path] = []
        workspace = self._workspace()
        if workspace is not None and src in workspace.parents:
            skip.append(workspace)
            warnings.append(f"Skipped the Sentinel Chain workspace ({workspace}) inside the source directory")

        logger.info("Copying local repository %s into %s", src, destination)
        try:
            shutil.copytree(src, destination, symlinks=True, ignore=copytree_ignore(skip))
        except shutil.Error as exc:
            # copytree keeps going after per-file problems and reports them all at the end.
            warnings.extend(self._copy_warnings(exc))
        except OSError as exc:
            shutil.rmtree(destination, ignore_errors=True)
            raise RepositoryError(f"Could not copy {src} into the workspace: {exc}") from exc
        if not destination.is_dir():
            raise RepositoryError(f"Could not copy {src} into the workspace: destination missing after copy")

        fetched = FetchedRepository(
            name=self._name_for(src),
            source_url=str(src),
            source_type=SourceType.LOCAL,
            local_path=destination,
            branch=source.branch,
            warnings=warnings,
        )
        if (destination / ".git").exists():
            self._read_git_metadata(destination, fetched)
            if source.branch and fetched.branch and fetched.branch != source.branch:
                fetched.warnings.append(
                    f"Requested branch '{source.branch}' but '{fetched.branch}' is checked out; "
                    "the checked-out state of the local directory is analysed"
                )
        logger.info(
            "Copied %s (git=%s, branch=%s, remote=%s)",
            fetched.name, fetched.is_git, fetched.branch or "-", fetched.github_full_name or "-",
        )
        return fetched

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _resolve(location: str) -> Path:
        text = (location or "").strip()
        if not text:
            raise RepositoryError("Local path is empty")
        return Path(text).expanduser().resolve()

    def _workspace(self) -> Path | None:
        try:
            return self.settings.workspace_path
        except OSError:  # workspace could not be created; nothing to protect
            return None

    @staticmethod
    def _name_for(path: Path) -> str:
        return path.name or "repository"

    @staticmethod
    def _copy_warnings(exc: shutil.Error) -> list[str]:
        errors = exc.args[0] if exc.args and isinstance(exc.args[0], list) else [(None, None, str(exc))]
        messages = [f"Could not copy {src}: {why}" for src, _dst, why in errors]
        if len(messages) > _MAX_COPY_WARNINGS:
            messages = messages[:_MAX_COPY_WARNINGS] + [f"... {len(messages) - _MAX_COPY_WARNINGS} more copy errors"]
        return messages

    @staticmethod
    def _read_git_metadata(path: Path, fetched: FetchedRepository) -> None:
        """Fill branch / sha / github_full_name from the copied ``.git``; tolerant of odd states."""
        try:
            repo = git.Repo(path)
        except (InvalidGitRepositoryError, NoSuchPathError, GitCommandError) as exc:
            fetched.warnings.append(f".git directory present but unreadable: {exc}")
            return
        fetched.is_git = True
        try:
            try:
                fetched.branch = repo.active_branch.name
            except (TypeError, GitCommandError):
                fetched.warnings.append("Repository is in detached HEAD state")
            try:
                fetched.commit_sha = repo.head.commit.hexsha
            except (ValueError, GitCommandError):
                fetched.warnings.append("Repository has no commits")
            try:
                remote_url = repo.remotes.origin.url if "origin" in [r.name for r in repo.remotes] else None
            except (GitCommandError, AttributeError, ValueError):
                remote_url = None
        finally:
            repo.close()
        fetched.github_full_name = parse_github_remote(remote_url)
