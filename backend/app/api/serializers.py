"""Helpers that turn ORM rows into response models (shared by several route modules)."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Analysis, Dependency, Finding, Repository
from app.models.enums import AnalysisStatus, VulnerabilityStatus
from app.schemas.entities import (
    AnalysisSummary,
    DependencySummary,
    FindingSummary,
    RepositoryDetail,
    RepositorySummary,
    VulnerabilitySummary,
)


def analysis_summary(db: Session, analysis: Analysis) -> AnalysisSummary:
    findings = db.scalar(select(func.count(Finding.finding_id)).where(Finding.analysis_id == analysis.analysis_id)) or 0
    deps = db.scalar(select(func.count(Dependency.dependency_id)).where(Dependency.analysis_id == analysis.analysis_id)) or 0
    out = AnalysisSummary.model_validate(analysis)
    out.findings_count = findings
    out.dependencies_count = deps
    return out


def latest_analysis(db: Session, repository_id: int, *, completed_only: bool = False) -> Analysis | None:
    stmt = select(Analysis).where(Analysis.repository_id == repository_id)
    if completed_only:
        stmt = stmt.where(Analysis.status == AnalysisStatus.COMPLETED)
    return db.scalar(stmt.order_by(Analysis.analysis_id.desc()).limit(1))


def snapshot_analysis(db: Session, repository_id: int) -> Analysis | None:
    """The analysis whose dependency snapshot represents the repository's current state."""
    return latest_analysis(db, repository_id, completed_only=True) or latest_analysis(db, repository_id)


def dependency_counts(db: Session, analysis: Analysis | None) -> tuple[int, int]:
    if analysis is None:
        return 0, 0
    total = db.scalar(select(func.count(Dependency.dependency_id)).where(Dependency.analysis_id == analysis.analysis_id)) or 0
    vulnerable = db.scalar(
        select(func.count(Dependency.dependency_id)).where(
            Dependency.analysis_id == analysis.analysis_id,
            Dependency.vulnerability_status == VulnerabilityStatus.VULNERABLE,
        )
    ) or 0
    return total, vulnerable


def repository_summary(db: Session, repository: Repository) -> RepositorySummary:
    out = RepositorySummary.model_validate(repository)
    latest = latest_analysis(db, repository.repository_id)
    out.latest_analysis = analysis_summary(db, latest) if latest else None
    out.dependencies_count, out.vulnerable_count = dependency_counts(db, snapshot_analysis(db, repository.repository_id))
    return out


def repository_detail(db: Session, repository: Repository) -> RepositoryDetail:
    base = repository_summary(db, repository)
    out = RepositoryDetail.model_validate(repository)
    out.latest_analysis = base.latest_analysis
    out.dependencies_count, out.vulnerable_count = base.dependencies_count, base.vulnerable_count
    analyses = db.scalars(
        select(Analysis).where(Analysis.repository_id == repository.repository_id).order_by(Analysis.analysis_id.desc())
    ).all()
    out.analyses = [analysis_summary(db, a) for a in analyses]
    return out


def finding_summary(finding: Finding) -> FindingSummary:
    out = FindingSummary.model_validate(finding)
    out.dependency = DependencySummary.model_validate(finding.dependency)
    out.vulnerability = VulnerabilitySummary.model_validate(finding.vulnerability)
    return out
