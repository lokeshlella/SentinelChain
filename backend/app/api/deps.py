"""FastAPI dependencies and service factories.

Everything that talks to an external system is built here so tests can
replace it through ``app.dependency_overrides``.
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.core.logging import get_stage_logger
from app.db.session import get_db, get_session_factory
from app.services.agents.orchestrator import AIOrchestrator
from app.services.analysis.pipeline import AnalysisPipeline
from app.services.analysis.usage import SourceUsageAnalyzer
from app.services.dependencies.service import DependencyService
from app.services.knowledge_graph.service import KnowledgeGraphService
from app.services.llm.factory import get_default_provider
from app.services.repository.service import RepositoryService
from app.services.vulnerabilities.osv_provider import OSVProvider
from app.services.vulnerabilities.service import VulnerabilityService

log = get_stage_logger("API")

DbDep = Depends(get_db)
SettingsDep = Depends(get_settings)


def get_session_maker() -> sessionmaker[Session]:
    """Session factory used by background jobs (overridden in tests)."""
    return get_session_factory()


def build_orchestrator(settings: Settings) -> AIOrchestrator:
    return AIOrchestrator(get_default_provider(settings), settings)


def build_pipeline(db: Session, settings: Settings | None = None) -> AnalysisPipeline:
    """The real pipeline: OSV, Neo4j and Ollama providers from Settings."""
    settings = settings or get_settings()
    return AnalysisPipeline(
        db,
        settings,
        repository_service=RepositoryService(db, settings),
        dependency_service=DependencyService(),
        vulnerability_service=VulnerabilityService(
            db, provider=OSVProvider(settings.osv_api_url, settings.osv_timeout), settings=settings
        ),
        graph_service=KnowledgeGraphService(),
        usage_analyzer=SourceUsageAnalyzer(),
        orchestrator=build_orchestrator(settings),
    )


PipelineFactory = Callable[[Session], AnalysisPipeline]


def get_pipeline_factory() -> PipelineFactory:
    """Returns a callable building a pipeline for a given session (overridden in tests)."""
    return build_pipeline


def get_repository_service(db: Session = DbDep, settings: Settings = SettingsDep) -> RepositoryService:
    return RepositoryService(db, settings)


def build_repository_service(db: Session, settings: Settings | None = None) -> RepositoryService:
    return RepositoryService(db, settings or get_settings())


def get_repository_service_factory() -> Callable[[Session], RepositoryService]:
    """Factory for background ingestion jobs (overridden in tests)."""
    return build_repository_service


def get_graph_service() -> KnowledgeGraphService:
    return KnowledgeGraphService()


def _run_job(label: str, session_maker: sessionmaker[Session], work) -> None:
    """Run ``work(db)`` in its own session; a crash is logged, never propagated."""
    db = session_maker()
    try:
        work(db)
    except Exception:  # noqa: BLE001 - never let a background job die silently
        log.exception("%s crashed", label)
    finally:
        db.close()


def run_ingest_job(repository_id: int, *, refresh: bool, session_maker: sessionmaker[Session], repository_factory) -> None:
    """Background task: clone/copy + profile a repository (F-05: never on the request thread)."""
    _run_job(f"Ingestion job {repository_id}", session_maker, lambda db: repository_factory(db).ingest_job(repository_id, refresh=refresh))


def run_remediation_job(remediation_id: int, *, session_maker: sessionmaker[Session], remediation_factory) -> None:
    """Background task: candidates → LLM → working-copy change for one PENDING remediation."""
    _run_job(f"Remediation job {remediation_id}", session_maker, lambda db: remediation_factory(db).run(remediation_id))


def run_finding_ai_job(finding_id: int, *, session_maker: sessionmaker[Session], pipeline_factory) -> None:
    """Background task: on-demand agent chain for one finding."""
    _run_job(f"AI job for finding {finding_id}", session_maker, lambda db: pipeline_factory(db).run_ai_for_finding(finding_id))


def run_analysis_job(
    analysis_id: int,
    *,
    run_ai: bool,
    refresh: bool,
    session_maker: sessionmaker[Session],
    pipeline_factory: PipelineFactory,
) -> None:
    """Background task entry point: owns its own session for the whole run."""
    db = session_maker()
    try:
        pipeline_factory(db).run(analysis_id, run_ai=run_ai, refresh=refresh)
    except Exception:  # noqa: BLE001 - never let a background job die silently
        log.exception("Analysis job %d crashed", analysis_id)
    finally:
        db.close()


# ---------------------------------------------------------------- stage 6-7 services


def build_remediation_service(db: Session, settings: Settings | None = None):
    from app.services.remediation.registry import PackageRegistryClient
    from app.services.remediation.service import RemediationService

    settings = settings or get_settings()
    return RemediationService(
        db,
        settings,
        orchestrator=build_orchestrator(settings),
        registry=PackageRegistryClient(settings.registry_timeout),
        vulnerability_service=VulnerabilityService(
            db, provider=OSVProvider(settings.osv_api_url, settings.osv_timeout), settings=settings
        ),
        graph_service=KnowledgeGraphService(),
    )


def build_validation_service(db: Session, settings: Settings | None = None):
    from app.services.sandbox.docker_provider import DockerSandboxProvider
    from app.services.sandbox.security_scan import DependencySecurityScanner
    from app.services.sandbox.service import ValidationService

    settings = settings or get_settings()
    vulnerability_service = VulnerabilityService(
        db, provider=OSVProvider(settings.osv_api_url, settings.osv_timeout), settings=settings
    )
    return ValidationService(
        db,
        settings,
        sandbox=DockerSandboxProvider(settings),
        scanner=DependencySecurityScanner(vulnerability_service),
    )


def build_pull_request_service(db: Session, settings: Settings | None = None):
    from app.services.github.github_provider import GitHubProvider
    from app.services.github.service import PullRequestService
    from app.services.reports.service import ReportService

    settings = settings or get_settings()
    return PullRequestService(db, settings, provider=GitHubProvider(settings.github_token), report_service=ReportService(db))


def build_report_service(db: Session):
    from app.services.reports.service import ReportService

    return ReportService(db)


def get_remediation_factory() -> Callable[[Session], object]:
    return build_remediation_service


def get_validation_factory() -> Callable[[Session], object]:
    return build_validation_service


def get_pull_request_factory() -> Callable[[Session], object]:
    return build_pull_request_service


def get_report_factory() -> Callable[[Session], object]:
    return build_report_service


def run_validation_job(validation_id: int, *, session_maker: sessionmaker[Session], validation_factory) -> None:
    """Background task: execute one sandbox validation with its own session."""
    db = session_maker()
    try:
        validation_factory(db).run(validation_id)
    except Exception:  # noqa: BLE001
        log.exception("Validation job %d crashed", validation_id)
    finally:
        db.close()
