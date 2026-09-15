"""Dependency extraction service: runs every extractor, persists a per-analysis snapshot.

The service is deliberately thin: extractors do the parsing, this module composes
them, de-duplicates identities, writes ``Dependency`` / ``DependencyRelation``
rows for one ``Analysis`` and produces the counters shown in the analysis summary.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import RepositoryError, UnsupportedProjectError
from app.core.logging import get_stage_logger
from app.core.redaction import redact_secrets
from app.core.versions import normalize_package_name
from app.models.analysis import Analysis
from app.models.dependency import Dependency, DependencyRelation
from app.models.enums import DependencyScope, VulnerabilityStatus
from app.models.repository import Repository
from app.services.dependencies.base import (
    DependencyExtractor,
    ExtractedDependency,
    ExtractedRelation,
    ExtractionResult,
)
from app.services.dependencies.javascript_extractor import JavaScriptDependencyExtractor
from app.services.dependencies.python_extractor import PythonDependencyExtractor

log = get_stage_logger("Dependencies")

SUPPORTED_FILES = (
    "requirements.txt (also requirements-*.txt, requirements_*.txt, requirements/*.txt)",
    "package.json (+ package-lock.json)",
)

# Column limits of the ``dependencies`` table; values are truncated defensively.
_PACKAGE_NAME_MAX = 255
_VERSION_MAX = 100
_VERSION_SPEC_MAX = 255

Identity = tuple[str, str, str | None]  # (ecosystem, normalised name, version)
RowIdentity = tuple[str, str, str | None, str]  # + source_file


def get_extractors() -> list[DependencyExtractor]:
    """The extractors enabled in V1 (one per supported ecosystem)."""
    return [PythonDependencyExtractor(), JavaScriptDependencyExtractor()]


def dependency_identity(dep: ExtractedDependency) -> Identity:
    """Identity used to match dependencies and relations: ecosystem + canonical name + version."""
    ecosystem = str(dep.ecosystem)
    # Truncate exactly like _to_row does, so two names that only differ beyond the
    # column width map to the same identity instead of violating uq_dependency_identity.
    name = dep.package_name[:_PACKAGE_NAME_MAX]
    version = dep.version[:_VERSION_MAX] if dep.version else None
    return (ecosystem, normalize_package_name(name, ecosystem), version)


class DependencyService:
    """Extract dependencies from a repository working copy and persist them for an analysis."""

    def __init__(self, extractors: list[DependencyExtractor] | None = None):
        self.extractors = extractors if extractors is not None else get_extractors()

    def get_extractors(self) -> list[DependencyExtractor]:
        return list(self.extractors)

    # ---------------------------------------------------------------- extract
    def extract(self, repo_path: Path | str) -> ExtractionResult:
        """Run every extractor; raise ``UnsupportedProjectError`` when no dependency file exists."""
        path = Path(repo_path)
        if not path.is_dir():
            raise RepositoryError(f"Repository path does not exist or is not a directory: {path}")
        path = path.resolve()
        result = ExtractionResult()
        detected_any = False
        for extractor in self.extractors:
            name = type(extractor).__name__
            try:
                files = extractor.detect(path)
            except Exception as exc:  # noqa: BLE001 - one broken extractor must not hide the others
                log.exception("%s failed while detecting files", name)
                result.warnings.append(f"{name}: detection failed ({exc})")
                continue
            if not files:
                log.info("%s: no %s dependency files found", name, extractor.ecosystem)
                continue
            detected_any = True
            try:
                result.merge(extractor.extract(path))
            except Exception as exc:  # noqa: BLE001
                log.exception("%s failed while extracting", name)
                result.warnings.append(f"{name}: extraction failed ({exc})")
        if not detected_any:
            raise UnsupportedProjectError(
                f"No supported dependency files found in the repository. "
                f"Sentinel Chain V1 supports: {'; '.join(SUPPORTED_FILES)}.",
                details={"repo_path": str(path), "supported_files": list(SUPPORTED_FILES)},
            )
        by_ecosystem = Counter(str(dep.ecosystem) for dep in result.dependencies)
        breakdown = ", ".join(f"{eco}={count}" for eco, count in sorted(by_ecosystem.items())) or "none"
        log.info(
            "%d dependencies extracted (%s), %d relations, %d files, %d warnings",
            len(result.dependencies), breakdown, len(result.relations), len(result.files), len(result.warnings),
        )
        # Manifest text may carry credentials (index URLs, VCS requirements): redact before
        # anything is logged or stored (audit V2-04). Extractors quote the offending lines.
        result.warnings = [redact_secrets(w) or "" for w in result.warnings]
        for dep in result.dependencies:
            dep.version_spec = redact_secrets(dep.version_spec)
        for warning in result.warnings:
            log.warning(warning)
        return result

    # ---------------------------------------------------------------- persist
    def persist(
        self, db: Session, repository: Repository, analysis: Analysis, result: ExtractionResult
    ) -> list[Dependency]:
        """Write the snapshot rows for ``analysis`` and return every dependency row of the analysis.

        Identical identities (ecosystem, normalised name, version, source file) are stored
        once; relations are resolved by (ecosystem, normalised name, version) and skipped
        when either end is unknown. The call is idempotent for an analysis.
        """
        rows_by_identity = self._existing_rows(db, analysis)
        existing = len(rows_by_identity)
        created: list[Dependency] = []
        for dep in result.dependencies:
            identity = (*dependency_identity(dep), dep.source_file)
            if identity in rows_by_identity:
                continue
            row = self._to_row(dep, repository, analysis)
            db.add(row)
            rows_by_identity[identity] = row
            created.append(row)
        db.flush()  # assigns dependency_id values needed by the relations

        index: dict[Identity, int] = {}
        for identity, row in rows_by_identity.items():
            index.setdefault(identity[:3], row.dependency_id)
        relations, unresolved = self._build_relations(db, analysis, result.relations, index)
        db.add_all(relations)
        db.commit()
        log.info(
            "%d dependencies persisted for analysis %s (%d duplicates skipped, %d already present); "
            "%d relations stored (%d unresolved)",
            len(created), analysis.analysis_id, len(result.dependencies) - len(created), existing,
            len(relations), unresolved,
        )
        return list(rows_by_identity.values())

    @staticmethod
    def _existing_rows(db: Session, analysis: Analysis) -> dict[RowIdentity, Dependency]:
        rows = db.scalars(
            select(Dependency).where(Dependency.analysis_id == analysis.analysis_id).order_by(Dependency.dependency_id)
        ).all()
        return {
            (row.ecosystem, normalize_package_name(row.package_name, row.ecosystem), row.version, row.source_file): row
            for row in rows
        }

    @staticmethod
    def _to_row(dep: ExtractedDependency, repository: Repository, analysis: Analysis) -> Dependency:
        return Dependency(
            repository_id=repository.repository_id,
            analysis_id=analysis.analysis_id,
            package_name=dep.package_name[:_PACKAGE_NAME_MAX],
            version=dep.version[:_VERSION_MAX] if dep.version else None,
            version_spec=dep.version_spec[:_VERSION_SPEC_MAX] if dep.version_spec else None,
            ecosystem=str(dep.ecosystem),
            direct_or_transitive=str(dep.scope),
            source_file=dep.source_file,
            vulnerability_status=str(VulnerabilityStatus.UNCHECKED),
        )

    @staticmethod
    def _build_relations(
        db: Session, analysis: Analysis, extracted: list[ExtractedRelation], index: dict[Identity, int]
    ) -> tuple[list[DependencyRelation], int]:
        """Resolve extracted relations to dependency ids; returns (new rows, unresolved count)."""
        stored = db.execute(
            select(DependencyRelation.parent_dependency_id, DependencyRelation.child_dependency_id)
            .join(Dependency, Dependency.dependency_id == DependencyRelation.parent_dependency_id)
            .where(Dependency.analysis_id == analysis.analysis_id)
        ).all()
        seen: set[tuple[int, int]] = {(parent, child) for parent, child in stored}
        rows: list[DependencyRelation] = []
        unresolved = 0
        for relation in extracted:
            ecosystem = str(relation.ecosystem)
            parent_id = index.get((ecosystem, normalize_package_name(relation.parent_name, ecosystem), relation.parent_version))
            child_id = index.get((ecosystem, normalize_package_name(relation.child_name, ecosystem), relation.child_version))
            if parent_id is None or child_id is None:
                unresolved += 1
                continue
            if parent_id == child_id or (parent_id, child_id) in seen:
                continue
            seen.add((parent_id, child_id))
            rows.append(
                DependencyRelation(
                    parent_dependency_id=parent_id,
                    child_dependency_id=child_id,
                    relation_type=relation.relation_type or "depends_on",
                )
            )
        return rows, unresolved

    # -------------------------------------------------------------- summarize
    @staticmethod
    def summarize(result: ExtractionResult) -> dict:
        """Counters for the analysis summary (by ecosystem, scope and pinning) plus files/warnings."""
        deps = result.dependencies
        by_ecosystem = Counter(str(dep.ecosystem) for dep in deps)
        scopes = Counter(str(dep.scope) for dep in deps)
        pinned = sum(1 for dep in deps if dep.is_pinned)
        return {
            "total": len(deps),
            "by_ecosystem": dict(sorted(by_ecosystem.items())),
            "direct": scopes.get(str(DependencyScope.DIRECT), 0),
            "transitive": scopes.get(str(DependencyScope.TRANSITIVE), 0),
            "unknown_scope": scopes.get(str(DependencyScope.UNKNOWN), 0),
            "pinned": pinned,
            "unpinned": len(deps) - pinned,
            "files": list(result.files),
            "warnings": list(result.warnings),
        }


__all__ = ["DependencyService", "get_extractors", "dependency_identity", "SUPPORTED_FILES"]
