from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api import deps
from app.api.serializers import finding_summary, repository_summary
from app.core.exceptions import ConflictError, NotFoundError
from app.db.base import utcnow
from app.models.enums import AIStatus
from app.services.jobs import expire_if_stale
from app.models import Finding
from app.schemas.entities import FindingDetail, FindingSummary, RemediationSummary, VulnerabilityDetail
from app.services.analysis.usage import usage_verdict

router = APIRouter(prefix="/findings", tags=["findings"])


def _get(db: Session, finding_id: int) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise NotFoundError(f"Finding {finding_id} not found")
    return finding


def finding_detail(db: Session, finding: Finding) -> FindingDetail:
    base = finding_summary(finding)
    out = FindingDetail.model_validate(finding)
    out.usage_verdict = usage_verdict(finding.usage_evidence, finding.dependency.direct_or_transitive).to_dict()
    out.dependency = base.dependency
    out.vulnerability = VulnerabilityDetail.model_validate(finding.vulnerability)
    out.repository = repository_summary(db, finding.analysis.repository)
    out.remediations = [RemediationSummary.model_validate(r) for r in sorted(finding.remediations, key=lambda r: r.remediation_id)]
    return out


@router.get("", response_model=list[FindingSummary])
def list_findings(
    analysis_id: int | None = None,
    risk_level: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = deps.DbDep,
):
    stmt = select(Finding)
    if analysis_id is not None:
        stmt = stmt.where(Finding.analysis_id == analysis_id)
    if risk_level:
        stmt = stmt.where(Finding.risk_level == risk_level.upper())
    rows = db.scalars(stmt.order_by(Finding.finding_id.desc()).limit(limit)).all()
    return [finding_summary(f) for f in rows]


@router.get("/{finding_id}", response_model=FindingDetail)
def get_finding(finding_id: int, db: Session = deps.DbDep):
    finding = _get(db, finding_id)
    expire_if_stale(db, finding)
    return finding_detail(db, finding)


@router.post("/{finding_id}/analyze", response_model=FindingDetail, status_code=status.HTTP_202_ACCEPTED, summary="Run the AI agents for one finding (background; poll ai_status)")
def analyze_finding(
    finding_id: int,
    background: BackgroundTasks,
    db: Session = deps.DbDep,
    pipeline_factory=Depends(deps.get_pipeline_factory),
    session_maker=Depends(deps.get_session_maker),
):
    finding = _get(db, finding_id)
    if finding.ai_status == AIStatus.RUNNING and not expire_if_stale(db, finding):
        raise ConflictError("AI analysis is already running for this finding", details={"finding_id": finding_id})
    finding.ai_status = AIStatus.RUNNING
    finding.ai_error = None
    finding.ai_updated_at = utcnow()
    db.commit()
    background.add_task(deps.run_finding_ai_job, finding_id, session_maker=session_maker, pipeline_factory=pipeline_factory)
    return finding_detail(db, finding)
