from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api import deps
from app.api.serializers import (
    analysis_summary,
    finding_summary,
    repository_detail,
    repository_summary,
    snapshot_analysis,
)
from app.core.exceptions import ConflictError, NotFoundError
from app.core.logging import get_stage_logger
from app.models import Analysis, Dependency, Finding
from app.models.enums import AnalysisStatus, RepositoryStatus
from app.services.jobs import expire_if_stale
from app.schemas.entities import (
    AnalysisDetail,
    AnalysisSummary,
    AnalyzeRequest,
    DependencySummary,
    FindingSummary,
    RepositoryCreate,
    RepositoryDetail,
    RepositorySummary,
)
from app.services.knowledge_graph.service import KnowledgeGraphService
from app.services.repository.service import RepositoryService

router = APIRouter(prefix="/repositories", tags=["repositories"])
log = get_stage_logger("API")


@router.post("", response_model=RepositoryDetail, status_code=status.HTTP_202_ACCEPTED, summary="Register a repository (ingestion runs in the background)")
def create_repository(
    payload: RepositoryCreate,
    background: BackgroundTasks,
    db: Session = deps.DbDep,
    service: RepositoryService = Depends(deps.get_repository_service),
    session_maker=Depends(deps.get_session_maker),
    repository_factory=Depends(deps.get_repository_service_factory),
) -> RepositoryDetail:
    """Validates the source (URL/path format, duplicates) synchronously; the clone/copy and the
    structure profile run as a background job. Poll ``GET /repositories/{id}`` until ``status``
    is ``READY`` (or ``FAILED`` with ``error_message``)."""
    repository = service.register(payload.source_url, payload.source_type, payload.branch, ingest=False)
    background.add_task(
        deps.run_ingest_job, repository.repository_id, refresh=True, session_maker=session_maker, repository_factory=repository_factory
    )
    log.info("Repository %d registered: %s (ingestion queued)", repository.repository_id, repository.source_url)
    return repository_detail(db, repository)


@router.post("/{repository_id}/ingest", response_model=RepositoryDetail, status_code=status.HTTP_202_ACCEPTED, summary="Re-run ingestion (retry a failed clone/copy or refresh the working copy)")
def ingest_repository(
    repository_id: int,
    background: BackgroundTasks,
    db: Session = deps.DbDep,
    service: RepositoryService = Depends(deps.get_repository_service),
    session_maker=Depends(deps.get_session_maker),
    repository_factory=Depends(deps.get_repository_service_factory),
) -> RepositoryDetail:
    repository = service.get(repository_id)
    expire_if_stale(db, repository)
    if repository.status == RepositoryStatus.PENDING:
        raise ConflictError("Ingestion is already in progress for this repository", details={"repository_id": repository_id})
    repository.status = RepositoryStatus.PENDING
    repository.error_message = None
    db.commit()
    background.add_task(
        deps.run_ingest_job, repository.repository_id, refresh=True, session_maker=session_maker, repository_factory=repository_factory
    )
    return repository_detail(db, repository)


@router.get("", response_model=list[RepositorySummary])
def list_repositories(db: Session = deps.DbDep, service: RepositoryService = Depends(deps.get_repository_service)):
    return [repository_summary(db, r) for r in service.list()]


@router.get("/{repository_id}", response_model=RepositoryDetail)
def get_repository(repository_id: int, db: Session = deps.DbDep, service: RepositoryService = Depends(deps.get_repository_service)):
    repository = service.get(repository_id)
    expire_if_stale(db, repository)  # a dead ingestion job becomes FAILED instead of PENDING forever
    return repository_detail(db, repository)


@router.delete("/{repository_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_repository(
    repository_id: int,
    service: RepositoryService = Depends(deps.get_repository_service),
    graph: KnowledgeGraphService = Depends(deps.get_graph_service),
) -> Response:
    service.delete(repository_id)
    try:
        graph.remove_repository(repository_id)
    except Exception as exc:  # noqa: BLE001 - graph cleanup is best effort
        log.warning("Could not remove repository %d from the graph: %s", repository_id, exc)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{repository_id}/dependencies", response_model=list[DependencySummary], summary="Dependencies of the latest analysis")
def list_repository_dependencies(
    repository_id: int,
    status_filter: str | None = Query(default=None, alias="status", description="SAFE | VULNERABLE | UNKNOWN | UNCHECKED"),
    db: Session = deps.DbDep,
    service: RepositoryService = Depends(deps.get_repository_service),
):
    service.get(repository_id)
    analysis = snapshot_analysis(db, repository_id)
    if analysis is None:
        return []
    stmt = select(Dependency).where(Dependency.analysis_id == analysis.analysis_id)
    if status_filter:
        stmt = stmt.where(Dependency.vulnerability_status == status_filter.upper())
    rows = db.scalars(stmt.order_by(Dependency.ecosystem, Dependency.package_name, Dependency.version)).all()
    return [DependencySummary.model_validate(d) for d in rows]


@router.get("/{repository_id}/analyses", response_model=list[AnalysisSummary])
def list_repository_analyses(repository_id: int, db: Session = deps.DbDep, service: RepositoryService = Depends(deps.get_repository_service)):
    service.get(repository_id)
    rows = db.scalars(select(Analysis).where(Analysis.repository_id == repository_id).order_by(Analysis.analysis_id.desc())).all()
    return [analysis_summary(db, a) for a in rows]


@router.get("/{repository_id}/findings", response_model=list[FindingSummary], summary="Findings of the latest completed analysis")
def list_repository_findings(repository_id: int, db: Session = deps.DbDep, service: RepositoryService = Depends(deps.get_repository_service)):
    service.get(repository_id)
    analysis = snapshot_analysis(db, repository_id)
    if analysis is None:
        return []
    rows = db.scalars(select(Finding).where(Finding.analysis_id == analysis.analysis_id).order_by(Finding.finding_id)).all()
    return [finding_summary(f) for f in rows]


@router.get("/{repository_id}/graph", summary="Knowledge-graph nodes and edges for the repository")
def repository_graph(
    repository_id: int,
    limit: int = Query(default=500, ge=1, le=5000),
    service: RepositoryService = Depends(deps.get_repository_service),
    graph: KnowledgeGraphService = Depends(deps.get_graph_service),
) -> dict:
    service.get(repository_id)
    if not graph.available():
        return {"available": False, "nodes": [], "edges": [], "message": "Knowledge graph unavailable: Neo4j could not be reached"}
    return {"available": True, **graph.repository_graph(repository_id, limit=limit)}


@router.post("/{repository_id}/analyze", response_model=AnalysisDetail, status_code=status.HTTP_202_ACCEPTED, summary="Start an analysis (background)")
def analyze_repository(
    repository_id: int,
    background: BackgroundTasks,
    payload: AnalyzeRequest | None = None,
    db: Session = deps.DbDep,
    service: RepositoryService = Depends(deps.get_repository_service),
    session_maker=Depends(deps.get_session_maker),
    pipeline_factory=Depends(deps.get_pipeline_factory),
) -> AnalysisDetail:
    payload = payload or AnalyzeRequest()
    repository = service.get(repository_id)
    expire_if_stale(db, repository)
    if repository.status == RepositoryStatus.PENDING:
        raise ConflictError(
            "Repository ingestion is still in progress; wait until its status is READY",
            details={"repository_id": repository_id, "status": repository.status},
        )
    running = db.scalar(
        select(Analysis).where(
            Analysis.repository_id == repository_id,
            Analysis.status.in_([AnalysisStatus.PENDING, AnalysisStatus.RUNNING]),
        )
    )
    if running is not None and expire_if_stale(db, running):
        running = None  # the previous job died; the watchdog just marked it FAILED
    if running is not None:
        raise ConflictError(
            f"Analysis {running.analysis_id} is already {running.status} for this repository",
            details={"analysis_id": running.analysis_id},
        )
    analysis = Analysis(repository_id=repository_id, status=AnalysisStatus.PENDING, triggered_by="api")
    db.add(analysis)
    db.commit()
    db.refresh(analysis)
    background.add_task(
        deps.run_analysis_job,
        analysis.analysis_id,
        run_ai=payload.run_ai,
        refresh=payload.refresh,
        session_maker=session_maker,
        pipeline_factory=pipeline_factory,
    )
    log.info("Analysis %d queued for repository %d (run_ai=%s)", analysis.analysis_id, repository_id, payload.run_ai)
    out = AnalysisDetail.model_validate(analysis)
    out.repository = repository_summary(db, repository)
    return out


def _require(db: Session, model, key: int, label: str):
    row = db.get(model, key)
    if row is None:
        raise NotFoundError(f"{label} {key} not found")
    return row
