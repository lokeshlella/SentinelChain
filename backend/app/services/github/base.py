"""Git hosting provider contract (GitHub in V1)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from app.models.enums import PullRequestStatus


@dataclass
class PullRequestSpec:
    workspace_path: Path  # validated temporary working copy (a git clone) containing the change
    base_branch: str
    head_branch: str
    title: str
    body: str
    commit_message: str
    changed_files: list[str] = field(default_factory=list)  # relative paths to stage
    repo_full_name: str | None = None  # "owner/repo"; None when unknown
    draft: bool = True


@dataclass
class PullRequestResult:
    status: PullRequestStatus  # DRAFT | OPEN | UNAVAILABLE | FAILED
    branch: str
    url: str | None = None
    number: int | None = None
    commit_sha: str | None = None
    instructions: str | None = None  # manual steps when the PR could not be created
    error: str | None = None


class GitProvider(ABC):
    name: ClassVar[str]

    @abstractmethod
    def is_configured(self) -> bool: ...

    @abstractmethod
    def create_pull_request(self, spec: PullRequestSpec) -> PullRequestResult:
        """Create branch, commit, push and open a DRAFT pull request. Never merges."""
