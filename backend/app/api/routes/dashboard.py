from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api import deps
from app.api.serializers import analysis_summary, dependency_counts, finding_summary, repository_summary, snapshot_analysis
from app.models import Analysis, Finding, PullRequest, Remediation, Repository, Validation
from app.schemas.entities import DashboardOut

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard", response_model=DashboardOut)
def dashboard(db: Session = deps.DbDep) -> DashboardOut:
    repositories = db.scalars(select(Repository).order_by(Repository.repository_id.desc())).all()
    dependencies = vulnerable = 0
    for repo in repositories:
        total, vuln = dependency_counts(db, snapshot_analysis(db, repo.repository_id))
        dependencies += total
        vulnerable += vuln
    by_risk = {
        (level or "UNKNOWN"): count
        for level, count in db.execute(select(Finding.risk_level, func.count()).group_by(Finding.risk_level)).all()
    }
    recent = db.scalars(select(Analysis).order_by(Analysis.analysis_id.desc()).limit(10)).all()
    high_risk = db.scalars(
        select(Finding).where(Finding.risk_level.in_(["CRITICAL", "HIGH"])).order_by(Finding.finding_id.desc()).limit(10)
    ).all()
    return DashboardOut(
        repositories=len(repositories),
        analyses=db.scalar(select(func.count(Analysis.analysis_id))) or 0,
        dependencies=dependencies,
        vulnerable_dependencies=vulnerable,
        findings=db.scalar(select(func.count(Finding.finding_id))) or 0,
        findings_by_risk=by_risk,
        remediations=db.scalar(select(func.count(Remediation.remediation_id))) or 0,
        validations=db.scalar(select(func.count(Validation.validation_id))) or 0,
        pull_requests=db.scalar(select(func.count(PullRequest.pr_id))) or 0,
        recent_analyses=[analysis_summary(db, a) for a in recent],
        high_risk_findings=[finding_summary(f) for f in high_risk],
        recent_repositories=[repository_summary(db, r) for r in repositories[:10]],
    )
