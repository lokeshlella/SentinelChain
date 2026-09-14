"""Repository service: register / ingest / get / list / delete.

``register`` validates the location with the matching provider, creates the
``Repository`` row (so the workspace directory can be named after its id) and
immediately ingests it: the provider fetches a copy into
``workspace/repos/<repository_id>``, the analyser profiles it and the
components are upserted. A failed first ingest removes the row again so a bad
URL leaves nothing behind.
"""

from __future__ import annotations

import shutil
from collections.abc import Sequence
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.exceptions import ConflictError, NotFoundError, RepositoryError, SentinelError, ValidationFailedError
from app.core.paths import resolve_workspace_path, to_workspace_relative
from app.core.logging import get_stage_logger
from app.models import Component, Repository
from app.models.enums import RepositoryStatus, SourceType
from app.services.repository.analyzer import RepositoryAnalyzer, RepositoryProfile
from app.services.repository.base import RepositoryProvider, RepositorySource
from app.services.repository.github_provider import ACCEPTED_URL_FORMS, GitHubRepositoryProvider
from app.services.repository.local_provider import LocalRepositoryProvider

logger = get_stage_logger("Repository")

REPOS_SUBDIR = "repos"


def _provisional_name(location: str) -> str:
    """Last path segment of a URL / path, used until the provider reports the real name."""
    text = location.rstrip("/").rstrip("\\")
    segment = text.replace("\\", "/").split("/")[-1].split(":")[-1]
    if segment.lower().endswith(".git"):
        segment = segment[:-4]
    return segment or "repository"


def _coerce_source_type(value: SourceType | str | None) -> SourceType | None:
    if value is None or value == "":
        return None
    try:
        return SourceType(value)
    except ValueError as exc:
        raise ValidationFailedError(
            f"Unsupported source_type {value!r}; expected one of: {', '.join(t.value for t in SourceType)}"
        ) from exc


class RepositoryService:
    """Owns the lifecycle of ``Repository`` rows and their workspace copies."""

    def __init__(
        self,
        db: Session,
        settings: Settings | None = None,
        providers: Sequence[RepositoryProvider] | None = None,
        analyzer: RepositoryAnalyzer | None = None,
    ):
        self.db = db
        self.settings = settings or get_settings()
        self.providers: list[RepositoryProvider] = (
            list(providers)
            if providers is not None
            else [GitHubRepositoryProvider(self.settings), LocalRepositoryProvider(self.settings)]
        )
        self.analyzer = analyzer or RepositoryAnalyzer()

    # ------------------------------------------------------------------ public API

    def register(
        self,
        source_url: str,
        source_type: SourceType | str | None = None,
        branch: str | None = None,
        *,
        ingest: bool = True,
    ) -> Repository:
        """Validate and create the row; ingest synchronously unless ``ingest=False``.

        Raises ConflictError for an already registered source. With ``ingest=False`` the
        row is left in status PENDING for a background :meth:`ingest_job` (the API path,
        audit finding F-05: a clone must not block the request thread).
        """
        location = (source_url or "").strip()
        if not location:
            raise ValidationFailedError("source_url is required")
        requested_branch = (branch or "").strip() or None

        provider = self._select_provider(location, _coerce_source_type(source_type))
        source = provider.normalize(RepositorySource(location, provider.source_type, requested_branch))
        provider.validate(source)
        self._ensure_not_registered(provider, source)

        repository = Repository(
            name=_provisional_name(source.location),
            source_url=source.location,
            source_type=provider.source_type.value,
            branch=source.branch,
            status=RepositoryStatus.PENDING,
        )
        self.db.add(repository)
        try:
            self.db.commit()  # obtain repository_id for the workspace directory
        except IntegrityError as exc:
            # uq_repositories_source_branch fired: a concurrent registration won the race (audit F-14).
            self.db.rollback()
            raise ConflictError(
                f"Repository {source.location} was registered concurrently; refresh the list",
                details={"source_url": source.location, "branch": source.branch},
            ) from exc
        logger.info("Registered %s repository %s as id=%s", provider.source_type.value, source.location, repository.repository_id)
        if not ingest:
            return repository
        try:
            return self.ingest(repository, refresh=True)
        except Exception:
            self._discard(repository)
            raise

    def ingest_job(self, repository_id: int, *, refresh: bool = True) -> Repository:
        """Background entry point: ingest and record READY / FAILED on the row (never raises)."""
        repository = self.get(repository_id)
        repository.status = RepositoryStatus.PENDING
        repository.error_message = None
        self.db.commit()
        try:
            return self.ingest(repository, refresh=refresh)
        except Exception as exc:  # noqa: BLE001 - the user sees the reason on the repository page
            self.db.rollback()
            repository = self.get(repository_id)
            repository.status = RepositoryStatus.FAILED
            repository.error_message = getattr(exc, "message", None) or f"{exc.__class__.__name__}: {exc}"
            self.db.commit()
            logger.error("Ingestion of repository %s failed: %s", repository_id, repository.error_message)
            return repository

    def ingest(self, repository: Repository, refresh: bool = False) -> Repository:
        """Fetch (when missing or ``refresh``), analyse and store profile + components."""
        provider = self._provider_for_type(repository.source_type)
        destination = self.workspace_dir(repository.repository_id)
        source = RepositorySource(
            location=repository.source_url,
            source_type=SourceType(repository.source_type),
            branch=repository.branch,
        )

        if refresh or not self._has_working_copy(destination):
            fetched = self._fetch(provider, source, destination)
            repository.name = fetched.name or repository.name
            repository.branch = fetched.branch or repository.branch
            repository.commit_sha = fetched.commit_sha
            for warning in fetched.warnings:
                logger.warning("%s: %s", repository.name, warning)
        else:
            logger.info("Using existing working copy of %s at %s", repository.name, destination)
        repository.local_path = to_workspace_relative(destination, self.settings)

        profile = self._analyze(destination, repository)
        repository.profile = profile.to_dict()
        repository.language = profile.language
        added, updated, removed = self._sync_components(repository, profile)
        repository.status = RepositoryStatus.READY
        repository.error_message = None
        self.db.commit()
        logger.info(
            "Repository '%s' (id=%s) ingested: %d files, language=%s, components +%d/~%d/-%d, %d dependency files",
            repository.name, repository.repository_id, profile.total_files, profile.language or "unknown",
            added, updated, removed, len(profile.dependency_files),
        )
        return repository

    def get(self, repository_id: int) -> Repository:
        repository = self.db.get(Repository, repository_id)
        if repository is None:
            raise NotFoundError(f"Repository {repository_id} not found", details={"repository_id": repository_id})
        return repository

    def list(self) -> list[Repository]:
        stmt = select(Repository).order_by(Repository.created_at.desc(), Repository.repository_id.desc())
        return list(self.db.scalars(stmt))

    def delete(self, repository_id: int) -> None:
        """Delete the row (cascading to analyses, findings, ...) and its workspace directory."""
        repository = self.get(repository_id)
        paths = {self.workspace_dir(repository_id)}
        if repository.local_path:
            owned = self._owned_workspace_path(repository_id, resolve_workspace_path(repository.local_path, self.settings))
            if owned is not None:
                paths.add(owned)
            else:
                logger.warning(
                    "Repository %s has local_path %s outside its workspace directory %s; leaving it in place",
                    repository_id, repository.local_path, self.workspace_dir(repository_id),
                )
        # Artefacts keyed by remediation / validation id live outside workspace/repos/<id>;
        # collect them before the cascade removes the rows (audit finding F-07).
        paths.update(self._artefact_dirs(repository_id))
        name = repository.name
        self.db.delete(repository)
        self.db.commit()
        removed = 0
        for path in sorted(paths):
            removed += int(self._remove_dir(path))
        logger.info("Deleted repository '%s' (id=%s): %d workspace directories removed", name, repository_id, removed)

    def _artefact_dirs(self, repository_id: int) -> set[Path]:
        """Remediation working copies, validation logs and reports of every finding of the repository."""
        from sqlalchemy import select

        from app.models import Analysis, Finding, Remediation, Validation

        remediation_ids = list(
            self.db.scalars(
                select(Remediation.remediation_id)
                .join(Finding, Finding.finding_id == Remediation.finding_id)
                .join(Analysis, Analysis.analysis_id == Finding.analysis_id)
                .where(Analysis.repository_id == repository_id)
            )
        )
        validation_ids = list(
            self.db.scalars(select(Validation.validation_id).where(Validation.remediation_id.in_(remediation_ids)))
        ) if remediation_ids else []
        root = self.settings.workspace_path
        dirs: set[Path] = set()
        for rid in remediation_ids:
            dirs.add(root / "remediations" / str(rid))
            dirs.add(root / "reports" / str(rid))
        for vid in validation_ids:
            dirs.add(root / "validations" / str(vid))
        return dirs

    # ------------------------------------------------------------------ helpers

    def workspace_dir(self, repository_id: int) -> Path:
        return self.settings.workspace_path / REPOS_SUBDIR / str(repository_id)

    def local_path_of(self, repository: Repository) -> Path | None:
        """The working copy of ``repository`` on this instance (stored relative to the workspace)."""
        return resolve_workspace_path(repository.local_path, self.settings)

    def profile_of(self, repository: Repository) -> RepositoryProfile:
        """Typed view of ``repository.profile``."""
        return RepositoryProfile.from_dict(repository.profile)

    def _select_provider(self, location: str, source_type: SourceType | None) -> RepositoryProvider:
        if source_type is not None:
            return self._provider_for_type(source_type)
        for provider in self.providers:
            if provider.supports(location):
                return provider
        raise ValidationFailedError(
            f"Unsupported repository location {location!r}: expected a GitHub URL "
            f"({', '.join(ACCEPTED_URL_FORMS)}) or the path of an existing local directory",
            details={"source_url": location},
        )

    def _provider_for_type(self, source_type: SourceType | str) -> RepositoryProvider:
        wanted = SourceType(source_type)
        for provider in self.providers:
            if provider.source_type == wanted:
                return provider
        raise ValidationFailedError(
            f"No repository provider configured for source_type '{wanted.value}'",
            details={"source_type": wanted.value},
        )

    def _ensure_not_registered(self, provider: RepositoryProvider, source: RepositorySource) -> None:
        """Raise ConflictError when ``source`` (location + branch) is already registered.

        Rows without a branch (local directories, where branches do not apply) conflict
        with every request for the same location. A request without a branch means the
        source's *default* branch: it only conflicts with the row for that branch, so
        rows registered for other branches never block it. The provider is asked which
        branch is the default only when such rows exist; if it cannot tell, every row
        counts as a duplicate rather than risk registering the same branch twice.
        """
        # GitHub owner/repo names are case-insensitive; local paths are compared as resolved.
        stmt = (
            select(Repository)
            .where(
                func.lower(Repository.source_url) == source.location.lower(),
                Repository.source_type == source.source_type.value,
            )
            .order_by(Repository.repository_id)
        )
        candidates = list(self.db.scalars(stmt))
        if not candidates:
            return

        if source.source_type == SourceType.LOCAL:
            # A local directory is copied as checked out: branches cannot be selected, so
            # any existing registration of the same directory is a duplicate.
            existing = candidates[0]
            raise ConflictError(
                f"Local repository {source.location} is already registered (id={existing.repository_id})",
                details={"repository_id": existing.repository_id, "branch": existing.branch},
            )

        wanted = source.branch
        hint = "specify a different branch to register another one"
        existing = next((row for row in candidates if row.branch is None), None)
        if existing is None and wanted is None:
            wanted = provider.default_branch(source)
            if wanted is None:
                existing = candidates[0]
                hint = (
                    "its default branch could not be determined; "
                    "specify the branch explicitly to register another one"
                )
        if existing is None:
            existing = next((row for row in candidates if row.branch == wanted), None)
        if existing is None:
            return
        raise ConflictError(
            f"Repository {source.location} is already registered (id={existing.repository_id}, "
            f"branch={existing.branch or 'default'}); {hint}",
            details={"repository_id": existing.repository_id, "branch": existing.branch},
        )

    @staticmethod
    def _has_working_copy(destination: Path) -> bool:
        try:
            return destination.is_dir() and any(destination.iterdir())
        except OSError:
            return False

    @staticmethod
    def _fetch(provider: RepositoryProvider, source: RepositorySource, destination: Path):
        try:
            return provider.fetch(source, destination)
        except SentinelError:
            raise
        except Exception as exc:  # noqa: BLE001 - surface unexpected provider failures clearly
            raise RepositoryError(f"Could not fetch {source.location}: {exc}") from exc

    def _analyze(self, destination: Path, repository: Repository) -> RepositoryProfile:
        try:
            return self.analyzer.analyze(destination, default_name=repository.name)
        except Exception as exc:  # noqa: BLE001 - the analyser should never raise; be explicit if it does
            raise RepositoryError(f"Repository analysis of {repository.name} failed: {exc}") from exc

    def _sync_components(self, repository: Repository, profile: RepositoryProfile) -> tuple[int, int, int]:
        """Upsert components by path; remove the ones that disappeared. Returns (added, updated, removed)."""
        existing = {component.path: component for component in repository.components}
        seen: set[str] = set()
        added = updated = 0
        for info in profile.components:
            seen.add(info.path)
            component = existing.get(info.path)
            if component is None:
                component = Component(path=info.path)
                repository.components.append(component)
                added += 1
            else:
                updated += 1
            component.name = info.name
            component.component_type = info.component_type
            component.description = info.description
            component.file_count = info.file_count
        stale = [component for path, component in existing.items() if path not in seen]
        for component in stale:
            repository.components.remove(component)  # delete-orphan cascade removes the row
        return added, updated, len(stale)

    def _discard(self, repository: Repository) -> None:
        """Remove a repository whose first ingest failed (row + partial workspace)."""
        repository_id = repository.repository_id
        try:
            self.db.rollback()
            self.db.delete(repository)
            self.db.commit()
        except Exception as exc:  # noqa: BLE001 - never mask the original error
            self.db.rollback()
            logger.warning("Could not remove repository row %s after a failed ingest: %s", repository_id, exc)
        self._remove_dir(self.workspace_dir(repository_id))

    def _owned_workspace_path(self, repository_id: int, path: Path) -> Path | None:
        """``path`` resolved, if it is the repository's own ``workspace/repos/<id>`` directory or below it.

        Anything else (the workspace root, the ``repos`` directory, another repository's
        copy, the user's original directory, ...) must never be removed on delete; the
        only legitimate ``local_path`` is the one ``ingest`` writes.
        """
        try:
            own_dir = self.workspace_dir(repository_id).resolve()
            resolved = path.resolve()
        except OSError:
            return None
        if resolved == own_dir or own_dir in resolved.parents:
            return resolved
        return None

    @staticmethod
    def _remove_dir(path: Path) -> bool:
        if not path.exists() and not path.is_symlink():
            return False
        try:
            if path.is_symlink():
                path.unlink()
            else:
                shutil.rmtree(path)
            return True
        except OSError as exc:
            logger.warning("Could not remove workspace directory %s: %s", path, exc)
            return False
