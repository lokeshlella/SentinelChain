from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api import deps
from app.api.serializers import finding_summary
from app.core.exceptions import NotFoundError
from app.services.jobs import expire_if_stale
from app.models import PullRequest, Remediation, Validation
from app.models.enums import ValidationStatus
from app.schemas.entities import (
    PullRequestDetail,
    PullRequestSummary,
    RemediationDetail,
    ValidationDetail,
    ValidationSummary,
)
from pydantic import BaseModel

router = APIRouter(tags=["remediation"])


class PullRequestRequest(BaseModel):
    force: bool = False


def _get_remediation(db: Session, remediation_id: int) -> Remediation:
    row = db.get(Remediation, remediation_id)
    if row is None:
        raise NotFoundError(f"Remediation {remediation_id} not found")
    return row


def remediation_detail(remediation: Remediation) -> RemediationDetail:
    out = RemediationDetail.model_validate(remediation)
    out.finding = finding_summary(remediation.finding)
    out.validations = [ValidationSummary.model_validate(v) for v in sorted(remediation.validations, key=lambda v: v.validation_id)]
    out.pull_requests = [PullRequestSummary.model_validate(p) for p in sorted(remediation.pull_requests, key=lambda p: p.pr_id)]
    return out


def validation_detail(validation: Validation, logs: str | None) -> ValidationDetail:
    out = ValidationDetail.model_validate(validation)
    out.logs = logs
    return out


def report_response(report_service, finding_id: int, remediation_id: int | None, fmt: str) -> Response:
    report = report_service.build(finding_id, remediation_id)
    if fmt == "markdown":
        return Response(content=report_service.to_markdown(report), media_type="text/markdown; charset=utf-8")
    from fastapi.responses import JSONResponse

    return JSONResponse(content=report_service.to_json(report))


# ---------------------------------------------------------------- findings → remediation / report


@router.post("/findings/{finding_id}/remediate", response_model=RemediationDetail, status_code=status.HTTP_202_ACCEPTED, summary="Generate a remediation (background; poll the remediation until status != PENDING)")
def remediate_finding(
    finding_id: int,
    background: BackgroundTasks,
    db: Session = deps.DbDep,
    factory=Depends(deps.get_remediation_factory),
    session_maker=Depends(deps.get_session_maker),
):
    remediation = factory(db).start(finding_id)  # synchronous pre-checks (lock files, unpinned, missing copy) → 400
    background.add_task(deps.run_remediation_job, remediation.remediation_id, session_maker=session_maker, remediation_factory=factory)
    db.refresh(remediation)
    return remediation_detail(remediation)


@router.get("/findings/{finding_id}/report", summary="Evidence report for a finding (json | markdown)")
def finding_report(
    finding_id: int,
    format: str = Query(default="json", pattern="^(json|markdown)$"),
    db: Session = deps.DbDep,
    factory=Depends(deps.get_report_factory),
):
    return report_response(factory(db), finding_id, None, format)


# ---------------------------------------------------------------- remediations


@router.get("/remediations/{remediation_id}", response_model=RemediationDetail)
def get_remediation(remediation_id: int, db: Session = deps.DbDep):
    remediation = _get_remediation(db, remediation_id)
    expire_if_stale(db, remediation)
    return remediation_detail(remediation)


@router.get("/remediations/{remediation_id}/validations", response_model=list[ValidationSummary])
def list_validations(remediation_id: int, db: Session = deps.DbDep):
    _get_remediation(db, remediation_id)
    rows = db.scalars(select(Validation).where(Validation.remediation_id == remediation_id).order_by(Validation.validation_id)).all()
    return [ValidationSummary.model_validate(v) for v in rows]


@router.post("/remediations/{remediation_id}/validate", response_model=ValidationDetail, status_code=status.HTTP_202_ACCEPTED, summary="Validate in the Docker sandbox (background)")
def validate_remediation(
    remediation_id: int,
    background: BackgroundTasks,
    db: Session = deps.DbDep,
    factory=Depends(deps.get_validation_factory),
    session_maker=Depends(deps.get_session_maker),
):
    remediation = _get_remediation(db, remediation_id)
    running = db.scalar(
        select(Validation).where(
            Validation.remediation_id == remediation.remediation_id,
            Validation.status.in_([ValidationStatus.PENDING, ValidationStatus.RUNNING]),
        )
    )
    if running is not None and expire_if_stale(db, running):
        running = None  # dead job, just marked FAILED by the watchdog
    if running is not None:
        from app.core.exceptions import ConflictError

        raise ConflictError(f"Validation {running.validation_id} is already {running.status}", details={"validation_id": running.validation_id})
    validation = factory(db).start(remediation_id)
    background.add_task(deps.run_validation_job, validation.validation_id, session_maker=session_maker, validation_factory=factory)
    return validation_detail(validation, None)


@router.get("/remediations/{remediation_id}/report", summary="Evidence report for a remediation (json | markdown)")
def remediation_report(
    remediation_id: int,
    format: str = Query(default="json", pattern="^(json|markdown)$"),
    db: Session = deps.DbDep,
    factory=Depends(deps.get_report_factory),
):
    remediation = _get_remediation(db, remediation_id)
    return report_response(factory(db), remediation.finding_id, remediation_id, format)


@router.post("/remediations/{remediation_id}/pull-request", response_model=PullRequestDetail, status_code=status.HTTP_201_CREATED, summary="Create a draft GitHub pull request")
def create_pull_request(
    remediation_id: int,
    payload: PullRequestRequest | None = None,
    db: Session = deps.DbDep,
    factory=Depends(deps.get_pull_request_factory),
):
    payload = payload or PullRequestRequest()
    pr = factory(db).create(remediation_id, force=payload.force)
    db.refresh(pr)
    return PullRequestDetail.model_validate(pr)


# ---------------------------------------------------------------- validations


@router.get("/validations/{validation_id}", response_model=ValidationDetail)
def get_validation(validation_id: int, db: Session = deps.DbDep, factory=Depends(deps.get_validation_factory)):
    validation = db.get(Validation, validation_id)
    if validation is None:
        raise NotFoundError(f"Validation {validation_id} not found")
    expire_if_stale(db, validation)
    logs = factory(db).read_logs(validation) if validation.logs_path else None
    return validation_detail(validation, logs)


@router.get("/validations/{validation_id}/logs", response_class=Response, summary="Raw sandbox logs")
def get_validation_logs(validation_id: int, db: Session = deps.DbDep, factory=Depends(deps.get_validation_factory)):
    validation = db.get(Validation, validation_id)
    if validation is None:
        raise NotFoundError(f"Validation {validation_id} not found")
    return Response(content=factory(db).read_logs(validation), media_type="text/plain; charset=utf-8")


# ---------------------------------------------------------------- pull requests


@router.get("/pull-requests", response_model=list[PullRequestSummary])
def list_pull_requests(db: Session = deps.DbDep):
    rows = db.scalars(select(PullRequest).order_by(PullRequest.pr_id.desc())).all()
    return [PullRequestSummary.model_validate(p) for p in rows]


@router.get("/pull-requests/{pr_id}", response_model=PullRequestDetail)
def get_pull_request(pr_id: int, db: Session = deps.DbDep):
    pr = db.get(PullRequest, pr_id)
    if pr is None:
        raise NotFoundError(f"Pull request {pr_id} not found")
    return PullRequestDetail.model_validate(pr)
