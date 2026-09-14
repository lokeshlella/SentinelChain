"""Repository provider contract (GitHub, local, ... )."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from app.models.enums import SourceType


@dataclass
class RepositorySource:
    """What the user asked us to analyse."""

    location: str  # GitHub URL or local filesystem path
    source_type: SourceType
    branch: str | None = None


@dataclass
class FetchedRepository:
    """A repository that Sentinel Chain now has its own working copy of."""

    name: str
    source_url: str
    source_type: SourceType
    local_path: Path  # the copy owned by Sentinel Chain (never the user's original)
    branch: str | None = None
    commit_sha: str | None = None
    is_git: bool = False
    # "owner/repo" when the repository has a GitHub remote (used for PR creation)
    github_full_name: str | None = None
    warnings: list[str] = field(default_factory=list)


class RepositoryProvider(ABC):
    """Fetches a repository into a workspace directory owned by Sentinel Chain."""

    source_type: ClassVar[SourceType]

    @abstractmethod
    def supports(self, location: str) -> bool:
        """True if this provider can handle ``location``."""

    def normalize(self, source: RepositorySource) -> RepositorySource:
        """Return the canonical form of ``source`` (helper; default: unchanged).

        Providers may canonicalise the location (e.g. ``git@github.com:o/r.git`` ->
        ``https://github.com/o/r``) and fill in a branch encoded in the location.
        Must not touch the network. May raise ValidationFailedError.
        """
        return source

    def default_branch(self, source: RepositorySource) -> str | None:
        """Name of the branch a fetch of ``source`` without a branch would produce.

        Optional helper used to tell a registration of the default branch apart from
        registrations of other branches of the same source. May contact the source
        (GitHub does a ``git ls-remote``). Returns None when the provider cannot tell
        (local directories have no meaningful branch); may raise RepositoryError when
        the source is not accessible.
        """
        return None

    @abstractmethod
    def validate(self, source: RepositorySource) -> None:
        """Raise RepositoryError / ValidationFailedError for invalid or inaccessible sources."""

    @abstractmethod
    def fetch(self, source: RepositorySource, destination: Path) -> FetchedRepository:
        """Clone / copy the repository into ``destination`` (created or replaced)."""
