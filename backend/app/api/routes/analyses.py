from __future__ import annotations

from fastapi import APIRouter, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api import deps
from app.api.serializers import analysis_summary, finding_summary, repository_summary
from app.core.exceptions import NotFoundError
from app.models import Analysis, Dependency, Finding
from app.schemas.entities import AnalysisDetail, AnalysisSummary, DependencySummary, FindingSummary

router = APIRouter(prefix="/analyses", tags=["analyses"])


def _get(db: Session, analysis_id: int) -> Analysis:
    analysis = db.get(Analysis, analysis_id)
    if analysis is None:
        raise NotFoundError(f"Analysis {analysis_id} not found")
    return analysis


@router.get("", response_model=list[AnalysisSummary])
def list_analyses(limit: int = Query(default=50, ge=1, le=500), db: Session = deps.DbDep):
    rows = db.scalars(select(Analysis).order_by(Analysis.analysis_id.desc()).limit(limit)).all()
    return [analysis_summary(db, a) for a in rows]


@router.get("/{analysis_id}", response_model=AnalysisDetail)
def get_analysis(analysis_id: int, db: Session = deps.DbDep):
    analysis = _get(db, analysis_id)
    base = analysis_summary(db, analysis)
    out = AnalysisDetail.model_validate(analysis)
    out.findings_count, out.dependencies_count = base.findings_count, base.dependencies_count
    out.repository = repository_summary(db, analysis.repository)
    return out


@router.get("/{analysis_id}/findings", response_model=list[FindingSummary])
def list_analysis_findings(analysis_id: int, db: Session = deps.DbDep):
    _get(db, analysis_id)
    rows = db.scalars(select(Finding).where(Finding.analysis_id == analysis_id).order_by(Finding.finding_id)).all()
    return [finding_summary(f) for f in rows]


@router.get("/{analysis_id}/dependencies", response_model=list[DependencySummary])
def list_analysis_dependencies(
    analysis_id: int,
    status_filter: str | None = Query(default=None, alias="status"),
    db: Session = deps.DbDep,
):
    _get(db, analysis_id)
    stmt = select(Dependency).where(Dependency.analysis_id == analysis_id)
    if status_filter:
        stmt = stmt.where(Dependency.vulnerability_status == status_filter.upper())
    rows = db.scalars(stmt.order_by(Dependency.ecosystem, Dependency.package_name, Dependency.version)).all()
    return [DependencySummary.model_validate(d) for d in rows]
