"""Dependency extractor contract."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from app.models.enums import DependencyScope, Ecosystem


@dataclass
class ExtractedDependency:
    package_name: str
    ecosystem: Ecosystem
    source_file: str  # path relative to the repository root, POSIX separators
    version: str | None = None  # concrete version when reliably known
    version_spec: str | None = None  # raw specifier / range as written
    scope: DependencyScope = DependencyScope.UNKNOWN
    dev: bool = False  # development-only dependency when the manifest says so
    line_number: int | None = None

    @property
    def is_pinned(self) -> bool:
        return self.version is not None


@dataclass
class ExtractedRelation:
    """parent -> child edge (parent depends on child)."""

    parent_name: str
    parent_version: str | None
    child_name: str
    child_version: str | None
    ecosystem: Ecosystem
    relation_type: str = "depends_on"


@dataclass
class ExtractionResult:
    dependencies: list[ExtractedDependency] = field(default_factory=list)
    relations: list[ExtractedRelation] = field(default_factory=list)
    files: list[str] = field(default_factory=list)  # dependency files that were parsed
    warnings: list[str] = field(default_factory=list)

    def merge(self, other: "ExtractionResult") -> "ExtractionResult":
        self.dependencies.extend(other.dependencies)
        self.relations.extend(other.relations)
        self.files.extend(other.files)
        self.warnings.extend(other.warnings)
        return self


class DependencyExtractor(ABC):
    ecosystem: ClassVar[Ecosystem]

    @abstractmethod
    def detect(self, repo_path: Path) -> list[Path]:
        """Return the dependency files this extractor understands (absolute paths)."""

    @abstractmethod
    def extract(self, repo_path: Path) -> ExtractionResult:
        """Parse every detected file. Must never raise for malformed files: record a warning instead."""
