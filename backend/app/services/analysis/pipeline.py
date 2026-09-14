"""The analysis pipeline: Repository → Dependencies → Vulnerability → Usage → KnowledgeGraph → AI.

Each stage records its outcome in ``analysis.stages`` and counters in
``analysis.summary``. Repository / dependency problems fail the analysis;
OSV, Neo4j and Ollama being unavailable only degrade it (the analysis still
completes and says exactly what could not be checked).
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.config import Settings, get_settings
from app.core.exceptions import NotFoundError, SentinelError
from app.core.logging import get_stage_logger
from app.core.paths import resolve_workspace_path
from app.db.base import utcnow
from app.models import Analysis, Dependency, DependencyRelation, Finding, Repository, Vulnerability
from app.models.enums import AIStatus, AnalysisStatus, RiskLevel, StageStatus
from app.services.agents.orchestrator import AIOrchestrator
from app.services.agents.schemas import FindingAIResult, FindingContext
from app.services.analysis.context import build_finding_context
from app.services.analysis.risk import aggregate_overall_risk, sort_findings_by_priority
from app.services.analysis.usage import SourceUsageAnalyzer, UsageEvidence
from app.services.dependencies.service import DependencyService
from app.services.knowledge_graph.service import KnowledgeGraphService
from app.services.repository.analyzer import RepositoryProfile
from app.services.repository.service import RepositoryService
from app.services.vulnerabilities.service import VulnerabilityService

log = get_stage_logger("Analysis")
ai_log = get_stage_logger("AI")

STAGES = ("repository", "dependencies", "vulnerabilities", "usage", "knowledge_graph", "ai")


class AnalysisPipeline:
    """Runs one analysis end to end. All collaborators are injectable for tests."""

    def __init__(
        self,
        db: Session,
        settings: Settings | None = None,
        *,
        repository_service: RepositoryService | None = None,
        dependency_service: DependencyService | None = None,
        vulnerability_service: VulnerabilityService | None = None,
        graph_service: KnowledgeGraphService | None = None,
        usage_analyzer: SourceUsageAnalyzer | None = None,
        orchestrator: AIOrchestrator | None = None,
    ) -> None:
        self.db = db
        self.settings = settings or get_settings()
        self.repositories = repository_service or RepositoryService(db, self.settings)
        self.dependencies = dependency_service or DependencyService()
        self.vulnerabilities = vulnerability_service or VulnerabilityService(db, settings=self.settings)
        self.graph = graph_service or KnowledgeGraphService()
        self.usage = usage_analyzer or SourceUsageAnalyzer()
        self.orchestrator = orchestrator  # None = AI disabled / unavailable

    # ------------------------------------------------------------------ public API

    def run(self, analysis_id: int, *, run_ai: bool = True, refresh: bool = False) -> Analysis:
        analysis = self._get_analysis(analysis_id)
        repository = analysis.repository
        analysis.status = AnalysisStatus.RUNNING
        analysis.started_at = utcnow()
        analysis.stages = {stage: StageStatus.PENDING for stage in STAGES}
        analysis.summary = {"repository": repository.name, "warnings": []}
        analysis.error_message = None
        self._vulnerability_check_status = StageStatus.OK
        self._commit()
        log.info("Analysis %d started for repository %d (%s)", analysis.analysis_id, repository.repository_id, repository.name)
        started = time.monotonic()

        try:
            repo_path = self._stage_repository(analysis, repository, refresh)
            deps = self._stage_dependencies(analysis, repository, repo_path)
            findings = self._stage_vulnerabilities(analysis, deps)
            component_usage = self._stage_usage(analysis, repository, repo_path, findings)
            self._stage_graph(analysis, repository, deps, findings, component_usage)
            self._stage_ai(analysis, repository, findings, run_ai)
            self._finalize(analysis, findings)
        except SentinelError as exc:
            self._fail(analysis, str(exc.message))
        except Exception as exc:  # noqa: BLE001 - the background job must record, not propagate
            log.exception("Analysis %d crashed", analysis.analysis_id)
            self._fail(analysis, f"{exc.__class__.__name__}: {exc}")
        log.info(
            "Analysis %d finished with status %s in %.1fs", analysis.analysis_id, analysis.status, time.monotonic() - started
        )
        return analysis

    def run_ai_for_finding(self, finding_id: int) -> Finding:
        """Run (or re-run) the agent chain for one finding and persist the outcome."""
        finding = self.db.get(Finding, finding_id)
        if finding is None:
            raise NotFoundError(f"Finding {finding_id} not found")
        if self.orchestrator is None:
            self._store_ai_result(finding, None, "AI analysis unavailable: no LLM provider configured")
            self._commit()
            return finding
        finding.ai_status = AIStatus.RUNNING
        finding.ai_error = None
        self._commit()
        context = self.build_finding_context(finding)
        try:
            result = self.orchestrator.analyze_finding(context)
        except Exception as exc:  # noqa: BLE001 - orchestrator bugs must not leave RUNNING rows
            ai_log.exception("Finding %d: orchestrator crashed", finding_id)
            self._store_ai_result(finding, None, f"AI analysis failed: {exc}")
            self._commit()
            return finding
        self._store_ai_result(finding, result, None)
        self._commit()
        return finding

    # ------------------------------------------------------------------ stages

    def _stage_repository(self, analysis: Analysis, repository: Repository, refresh: bool) -> Path:
        self._set_stage(analysis, "repository", StageStatus.RUNNING)
        path = resolve_workspace_path(repository.local_path, self.settings)
        if refresh or path is None or not path.exists():
            log.info("Working copy missing or refresh requested; ingesting %s", repository.source_url)
            repository = self.repositories.ingest(repository, refresh=True)
            path = resolve_workspace_path(repository.local_path, self.settings) or Path("")
        if not path.exists():
            raise SentinelError(f"Working copy of repository {repository.repository_id} is missing at {path}")
        profile = RepositoryProfile.from_dict(repository.profile or {})
        self._merge_summary(
            analysis,
            {
                "language": repository.language,
                "commit_sha": repository.commit_sha,
                "components": len(repository.components),
                "dependency_files": list(profile.dependency_files),
            },
        )
        self._set_stage(analysis, "repository", StageStatus.OK)
        log.info("Repository ready at %s (%d components)", path, len(repository.components))
        return path

    def _stage_dependencies(self, analysis: Analysis, repository: Repository, repo_path: Path) -> list[Dependency]:
        self._set_stage(analysis, "dependencies", StageStatus.RUNNING)
        result = self.dependencies.extract(repo_path)  # raises UnsupportedProjectError when nothing found
        deps = self.dependencies.persist(self.db, repository, analysis, result)
        summary = self.dependencies.summarize(result)
        self._merge_summary(analysis, {"dependencies": summary})
        if result.warnings:
            self._add_warnings(analysis, [f"[Dependencies] {w}" for w in result.warnings[:50]])
        self._set_stage(analysis, "dependencies", StageStatus.OK if not result.warnings else StageStatus.PARTIAL)
        return deps

    def _stage_vulnerabilities(self, analysis: Analysis, deps: list[Dependency]) -> list[Finding]:
        self._set_stage(analysis, "vulnerabilities", StageStatus.RUNNING)
        check = self.vulnerabilities.check_dependencies(deps)
        # Remembered for the graph stage: an unavailable/partial check must not erase known edges.
        self._vulnerability_check_status = StageStatus(check.stage_status)
        findings = self.vulnerabilities.create_findings(analysis, check.dep_vulns)
        self._merge_summary(analysis, {"vulnerabilities": {**check.to_dict(), "findings": len(findings)}})
        if not check.provider_available:
            self._add_warnings(analysis, ["Vulnerability check unavailable: OSV could not be reached; dependencies are UNKNOWN, not safe"])
        self._set_stage(analysis, "vulnerabilities", check.stage_status)
        return findings

    def _stage_usage(
        self, analysis: Analysis, repository: Repository, repo_path: Path, findings: list[Finding]
    ) -> dict[int, list[str]]:
        """Source-usage evidence once per vulnerable dependency; stored on each of its findings."""
        self._set_stage(analysis, "usage", StageStatus.RUNNING)
        component_paths = [c.path for c in repository.components]
        evidence_by_dep: dict[int, UsageEvidence] = {}
        component_usage: dict[int, list[str]] = {}
        for finding in findings:
            dep = finding.dependency
            if dep.dependency_id not in evidence_by_dep:
                evidence_by_dep[dep.dependency_id] = self.usage.find_usage(
                    repo_path, dep.package_name, dep.ecosystem, component_paths
                )
            evidence = evidence_by_dep[dep.dependency_id]
            finding.usage_evidence = evidence.to_dict()
            finding.affected_components = list(evidence.components)
            component_usage[dep.dependency_id] = list(evidence.components)
        used = sum(1 for e in evidence_by_dep.values() if e.is_used)
        self._merge_summary(analysis, {"usage": {"dependencies_scanned": len(evidence_by_dep), "with_source_references": used}})
        self._set_stage(analysis, "usage", StageStatus.OK if findings else StageStatus.SKIPPED)
        self._commit()
        return component_usage

    def _stage_graph(
        self,
        analysis: Analysis,
        repository: Repository,
        deps: list[Dependency],
        findings: list[Finding],
        component_usage: dict[int, list[str]],
    ) -> None:
        self._set_stage(analysis, "knowledge_graph", StageStatus.RUNNING)
        dep_vulns: dict[int, list[Vulnerability]] = {}
        for finding in findings:
            dep_vulns.setdefault(finding.dependency_id, []).append(finding.vulnerability)
        relations = self._relations_for(deps)
        preserve = getattr(self, "_vulnerability_check_status", StageStatus.OK) != StageStatus.OK
        try:
            result = self.graph.sync_analysis(
                repository, repository.components, deps, relations, dep_vulns, component_usage,
                preserve_unknown_vulnerability_edges=preserve,
            )
        except Exception as exc:  # noqa: BLE001 - the graph is optional
            log.warning("Knowledge graph sync raised: %s", exc)
            self._merge_summary(analysis, {"knowledge_graph": {"available": False, "error": str(exc)}})
            self._set_stage(analysis, "knowledge_graph", StageStatus.UNAVAILABLE)
            return
        self._merge_summary(analysis, {"knowledge_graph": result.to_dict()})
        if not result.available:
            self._add_warnings(analysis, ["Knowledge graph unavailable: Neo4j could not be reached"])
            self._set_stage(analysis, "knowledge_graph", StageStatus.UNAVAILABLE)
        elif result.error:
            self._add_warnings(analysis, [f"Knowledge graph sync failed: {result.error}"])
            self._set_stage(analysis, "knowledge_graph", StageStatus.FAILED)
        elif preserve:
            self._add_warnings(analysis, [
                "Knowledge graph: vulnerability data was unavailable for unchecked dependencies; "
                "their previously known vulnerability relationships were kept (not refreshed)"
            ])
            self._set_stage(analysis, "knowledge_graph", StageStatus.PARTIAL)
        else:
            self._set_stage(analysis, "knowledge_graph", StageStatus.OK)

    def _stage_ai(self, analysis: Analysis, repository: Repository, findings: list[Finding], run_ai: bool) -> None:
        self._set_stage(analysis, "ai", StageStatus.RUNNING)
        if not findings:
            self._merge_summary(analysis, {"ai": {"analyzed": 0, "note": "no findings"}})
            self._set_stage(analysis, "ai", StageStatus.SKIPPED)
            return
        if not run_ai or self.orchestrator is None:
            reason = "AI analysis skipped by request" if not run_ai else "AI analysis unavailable: no LLM provider configured"
            for finding in findings:
                finding.ai_status = AIStatus.SKIPPED if not run_ai else AIStatus.UNAVAILABLE
                finding.ai_error = reason
            self._merge_summary(analysis, {"ai": {"analyzed": 0, "note": reason}})
            self._set_stage(analysis, "ai", StageStatus.SKIPPED if not run_ai else StageStatus.UNAVAILABLE)
            self._commit()
            return

        limit = max(0, int(self.settings.ai_max_findings_per_analysis))
        ordered = sort_findings_by_priority(findings)
        selected, skipped = ordered[:limit], ordered[limit:]
        for finding in skipped:
            finding.ai_status = AIStatus.SKIPPED
            finding.ai_error = f"Skipped: analysis limit ({limit}) reached — run on demand"
        counts = {"analyzed": 0, "completed": 0, "failed": 0, "unavailable": 0, "skipped": len(skipped), "limit": limit}
        model = None
        unavailable_reason: str | None = None
        for finding in selected:
            if unavailable_reason is not None:
                self._store_ai_result(finding, None, unavailable_reason)
                counts["unavailable"] += 1
                continue
            finding.ai_status = AIStatus.RUNNING
            self._commit()
            context = self.build_finding_context(finding)
            started = time.monotonic()
            try:
                result = self.orchestrator.analyze_finding(context)
            except Exception as exc:  # noqa: BLE001
                ai_log.exception("Finding %d: orchestrator crashed", finding.finding_id)
                self._store_ai_result(finding, None, f"AI analysis failed: {exc}")
                counts["failed"] += 1
                continue
            counts["analyzed"] += 1
            model = result.model or model
            self._store_ai_result(finding, result, None)
            ai_log.info(
                "Finding %d (%s %s / %s): %s in %.1fs",
                finding.finding_id, context.dependency.package_name, context.dependency.version,
                context.vulnerability.identifier, result.status, time.monotonic() - started,
            )
            if result.status == "UNAVAILABLE":
                counts["unavailable"] += 1
                unavailable_reason = "AI analysis unavailable: " + (result.failures[0].error if result.failures else "LLM unreachable")
            elif result.status == "FAILED":
                counts["failed"] += 1
            else:
                counts["completed"] += 1
            self._commit()

        self._merge_summary(analysis, {"ai": {**counts, "model": model}})
        if counts["completed"] == 0 and counts["unavailable"] > 0:
            self._add_warnings(analysis, [unavailable_reason or "AI analysis unavailable"])
            self._set_stage(analysis, "ai", StageStatus.UNAVAILABLE)
        elif counts["failed"] or counts["unavailable"] or counts["skipped"]:
            self._set_stage(analysis, "ai", StageStatus.PARTIAL)
        else:
            self._set_stage(analysis, "ai", StageStatus.OK)
        self._commit()

    def _finalize(self, analysis: Analysis, findings: list[Finding]) -> None:
        analysis.overall_risk = aggregate_overall_risk(findings)
        analysis.status = AnalysisStatus.COMPLETED
        analysis.completed_at = utcnow()
        self._merge_summary(analysis, {"findings": len(findings), "overall_risk": analysis.overall_risk})
        self._commit()

    def _fail(self, analysis: Analysis, message: str) -> None:
        self.db.rollback()
        analysis = self._get_analysis(analysis.analysis_id)
        stages = dict(analysis.stages or {})
        for stage, status in stages.items():
            if status in (StageStatus.RUNNING, StageStatus.PENDING):
                stages[stage] = StageStatus.FAILED if status == StageStatus.RUNNING else StageStatus.SKIPPED
        analysis.stages = stages
        analysis.status = AnalysisStatus.FAILED
        analysis.error_message = message
        analysis.completed_at = utcnow()
        self._commit()
        log.error("Analysis %d failed: %s", analysis.analysis_id, message)

    # ------------------------------------------------------------------ AI context / persistence

    def build_finding_context(self, finding: Finding) -> FindingContext:
        return build_finding_context(finding, self.graph)

    @staticmethod
    def _store_ai_result(finding: Finding, result: FindingAIResult | None, error: str | None) -> None:
        if result is None:
            finding.ai_status = AIStatus.UNAVAILABLE if error and "unavailable" in error.lower() else AIStatus.FAILED
            finding.ai_error = error
            return
        finding.ai_results = result.model_dump(mode="json")
        finding.ai_status = {"COMPLETED": AIStatus.COMPLETED, "FAILED": AIStatus.FAILED}.get(result.status, AIStatus.UNAVAILABLE)
        finding.ai_error = "; ".join(f"{f.agent}: {f.error}" for f in result.failures) or None
        if result.impact is not None:
            finding.impact_level = result.impact.impact_level
        if result.risk is not None and result.risk.risk_level != RiskLevel.UNKNOWN:
            finding.risk_level = result.risk.risk_level
        finding.reasoning = compose_reasoning(result)

    # ------------------------------------------------------------------ helpers

    def _get_analysis(self, analysis_id: int) -> Analysis:
        analysis = self.db.scalar(
            select(Analysis).options(selectinload(Analysis.repository).selectinload(Repository.components))
            .where(Analysis.analysis_id == analysis_id)
        )
        if analysis is None:
            raise NotFoundError(f"Analysis {analysis_id} not found")
        return analysis

    def _relations_for(self, deps: Iterable[Dependency]) -> list[DependencyRelation]:
        ids = [d.dependency_id for d in deps]
        if not ids:
            return []
        return list(self.db.scalars(select(DependencyRelation).where(DependencyRelation.parent_dependency_id.in_(ids))))

    def _set_stage(self, analysis: Analysis, stage: str, status: StageStatus) -> None:
        analysis.stages = {**(analysis.stages or {}), stage: str(status)}
        self._commit()

    def _merge_summary(self, analysis: Analysis, extra: dict[str, Any]) -> None:
        analysis.summary = {**(analysis.summary or {}), **extra}

    def _add_warnings(self, analysis: Analysis, warnings: list[str]) -> None:
        current = list((analysis.summary or {}).get("warnings", []))
        self._merge_summary(analysis, {"warnings": current + warnings})

    def _commit(self) -> None:
        self.db.commit()


def compose_reasoning(result: FindingAIResult) -> str:
    """Human-readable, clearly labelled summary of the agent chain (INFERENCE, not fact)."""
    parts: list[str] = []
    if result.dependency_analysis:
        parts.append(f"Dependency analysis: {result.dependency_analysis.summary}")
    if result.impact:
        parts.append(f"Impact ({result.impact.impact_level}): {result.impact.reasoning}")
    if result.risk:
        factors = "; ".join(result.risk.factors)
        parts.append(f"Risk ({result.risk.risk_level}): {result.risk.reasoning}" + (f" Factors: {factors}" if factors else ""))
    if result.failures:
        parts.append("Agent failures: " + "; ".join(f"{f.agent} — {f.error}" for f in result.failures))
    return "\n".join(parts)


PipelineFactory = Callable[[Session], AnalysisPipeline]
