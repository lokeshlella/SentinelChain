"""Background-job bookkeeping: heartbeats and the stale-job watchdog (audit finding F-06).

Long stages run as FastAPI background tasks inside the API process. If that
process dies (or the task thread is killed) the row stays ``RUNNING`` forever
and every later request answers ``409 already running``. Every job therefore
touches a heartbeat column on each commit, and the API expires a job whose
heartbeat is older than :func:`heartbeat_timeout` whenever it is read or a
new job is requested — no restart needed.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.logging import get_stage_logger
from app.db.base import utcnow
from app.models import Analysis, Finding, Remediation, Repository, Validation
from app.models.enums import AIStatus, AnalysisStatus, RemediationStatus, RepositoryStatus, StageStatus, ValidationStatus

log = get_stage_logger("Jobs")

STALE_REASON = "Background job stopped reporting progress for {age}s (backend crash or restart); start it again"
RESTART_REASON = "Interrupted by a backend restart; start it again"


def heartbeat_timeout(settings: Settings | None = None) -> int:
    """Seconds a job may go without a heartbeat: the configured value, but never less than the
    longest single step (a sandbox run or the full LLM retry budget) plus a margin."""
    settings = settings or get_settings()
    llm_budget = settings.ollama_timeout * (settings.llm_max_retries + 1) + 60
    return max(int(settings.job_heartbeat_timeout), int(settings.docker_timeout) + 120, llm_budget)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def is_stale(last_seen: datetime | None, timeout_seconds: int, now: datetime | None = None) -> bool:
    last_seen = _aware(last_seen)
    if last_seen is None:
        return True
    return (now or utcnow()) - last_seen > timedelta(seconds=timeout_seconds)


def _age(last_seen: datetime | None, now: datetime) -> int:
    last_seen = _aware(last_seen)
    return int((now - last_seen).total_seconds()) if last_seen else -1


# ------------------------------------------------------------------ per-row expiry (used on read and on job start)


def expire_if_stale(db: Session, row: object, settings: Settings | None = None, *, reason: str | None = None) -> bool:
    """Mark ``row`` FAILED when it claims to be in progress but its heartbeat is stale. Returns True when changed."""
    settings = settings or get_settings()
    timeout = heartbeat_timeout(settings)
    now = utcnow()
    changed = False
    if isinstance(row, Analysis) and row.status in (AnalysisStatus.PENDING, AnalysisStatus.RUNNING):
        last = row.heartbeat_at or row.started_at or row.created_at
        if is_stale(last, timeout, now):
            stages = dict(row.stages or {})
            for stage, status in stages.items():
                if status in (StageStatus.RUNNING, StageStatus.PENDING):
                    stages[stage] = StageStatus.FAILED if status == StageStatus.RUNNING else StageStatus.SKIPPED
            row.stages = stages
            row.status = AnalysisStatus.FAILED
            row.error_message = reason or STALE_REASON.format(age=_age(last, now))
            row.completed_at = now
            changed = True
    elif isinstance(row, Validation) and row.status in (ValidationStatus.PENDING, ValidationStatus.RUNNING):
        last = row.heartbeat_at or row.created_at
        if is_stale(last, timeout, now):
            row.status = ValidationStatus.FAILED
            row.error_message = reason or STALE_REASON.format(age=_age(last, now))
            changed = True
            remediation = row.remediation
            if remediation is not None and remediation.status == RemediationStatus.VALIDATING:
                remediation.status = RemediationStatus.VALIDATION_FAILED
    elif isinstance(row, Remediation) and row.status == RemediationStatus.PENDING:
        last = row.heartbeat_at or row.created_at
        if is_stale(last, timeout, now):
            row.status = RemediationStatus.FAILED
            row.error_message = reason or STALE_REASON.format(age=_age(last, now))
            changed = True
    elif isinstance(row, Finding) and row.ai_status == AIStatus.RUNNING:
        last = row.ai_updated_at or row.detected_at
        if is_stale(last, timeout, now):
            row.ai_status = AIStatus.FAILED
            row.ai_error = reason or STALE_REASON.format(age=_age(last, now))
            row.ai_updated_at = now
            changed = True
    elif isinstance(row, Repository) and row.status == RepositoryStatus.PENDING:
        last = row.updated_at or row.created_at
        if is_stale(last, timeout, now):
            row.status = RepositoryStatus.FAILED
            row.error_message = reason or STALE_REASON.format(age=_age(last, now))
            changed = True
    if changed:
        db.commit()
        log.warning("%s %s marked FAILED by the watchdog: %s", row.__class__.__name__, _row_id(row), getattr(row, "error_message", None) or getattr(row, "ai_error", None))
    return changed


def sweep_stale_jobs(db: Session, settings: Settings | None = None, *, everything: bool = False, reason: str | None = None) -> dict[str, int]:
    """Expire every stale in-progress row. With ``everything`` (startup) every in-progress row is dead."""
    settings = settings or get_settings()
    counts = {"analyses": 0, "validations": 0, "remediations": 0, "findings": 0, "repositories": 0}
    queries = {
        "analyses": select(Analysis).where(Analysis.status.in_([AnalysisStatus.PENDING, AnalysisStatus.RUNNING])),
        "validations": select(Validation).where(Validation.status.in_([ValidationStatus.PENDING, ValidationStatus.RUNNING])),
        "remediations": select(Remediation).where(Remediation.status == RemediationStatus.PENDING),
        "findings": select(Finding).where(Finding.ai_status == AIStatus.RUNNING),
        "repositories": select(Repository).where(Repository.status == RepositoryStatus.PENDING),
    }
    for name, query in queries.items():
        for row in db.scalars(query).all():
            if everything:
                _force_fail(row, reason or RESTART_REASON)
                counts[name] += 1
            elif expire_if_stale(db, row, settings, reason=reason):
                counts[name] += 1
    if everything:
        db.commit()
    return counts


def _force_fail(row: object, reason: str) -> None:
    now = utcnow()
    if isinstance(row, Analysis):
        row.status, row.error_message, row.completed_at = AnalysisStatus.FAILED, reason, now
        row.stages = {k: (StageStatus.FAILED if v == StageStatus.RUNNING else StageStatus.SKIPPED if v == StageStatus.PENDING else v) for k, v in (row.stages or {}).items()}
    elif isinstance(row, Validation):
        row.status, row.error_message = ValidationStatus.FAILED, reason
        if row.remediation is not None and row.remediation.status == RemediationStatus.VALIDATING:
            row.remediation.status = RemediationStatus.VALIDATION_FAILED
    elif isinstance(row, Remediation):
        row.status, row.error_message = RemediationStatus.FAILED, reason
    elif isinstance(row, Finding):
        row.ai_status, row.ai_error, row.ai_updated_at = AIStatus.FAILED, reason, now
    elif isinstance(row, Repository):
        row.status, row.error_message = RepositoryStatus.FAILED, reason


def _row_id(row: object) -> object:
    for attr in ("analysis_id", "validation_id", "remediation_id", "finding_id", "repository_id"):
        if hasattr(row, attr):
            return getattr(row, attr)
    return "?"


__all__ = ["STALE_REASON", "RESTART_REASON", "heartbeat_timeout", "is_stale", "expire_if_stale", "sweep_stale_jobs"]
