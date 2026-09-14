"""Remediation engine: candidate versions → LLM recommendation → deterministic file change.

The LLM only *chooses* among candidate versions that were derived from OSV
fixed-version events and verified against the package registry; it never
executes anything. The actual edit is performed by a modifier in a temporary
working copy of the repository.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.exceptions import NotFoundError, ValidationFailedError
from app.db.base import utcnow
from app.core.logging import get_stage_logger
from app.core.paths import resolve_workspace_path, to_workspace_relative
from app.models import Finding, Remediation, Vulnerability
from app.models.enums import RemediationStatus
from app.services.agents.base import AgentError
from app.services.agents.orchestrator import AIOrchestrator
from app.services.agents.schemas import RemediationResult
from app.services.analysis.context import build_finding_context
from app.services.llm.base import LLMError
from app.services.llm.structured import StructuredOutputError
from app.services.remediation.candidates import CandidateSet, select_candidates
from app.services.remediation.modifiers import get_modifier
from app.services.remediation.workspace import create_working_copy, remove_workspace
from app.services.remediation.registry import PackageRegistryClient
from app.services.vulnerabilities.service import VulnerabilityService

log = get_stage_logger("Remediation")

DETERMINISTIC_CONFIDENCE = 0.5


class RemediationService:
    def __init__(
        self,
        db: Session,
        settings: Settings | None = None,
        *,
        orchestrator: AIOrchestrator | None = None,
        registry: PackageRegistryClient | None = None,
        vulnerability_service: VulnerabilityService | None = None,
        graph_service=None,
    ) -> None:
        self.db = db
        self.settings = settings or get_settings()
        self.orchestrator = orchestrator  # None → deterministic recommendation only
        self.registry = registry or PackageRegistryClient(self.settings.registry_timeout)
        self.vulnerabilities = vulnerability_service or VulnerabilityService(db, settings=self.settings)
        self.graph = graph_service

    # ------------------------------------------------------------------ public API

    def remediate(self, finding_id: int) -> Remediation:
        """Synchronous convenience: ``start`` + ``run``; re-raises a ValidationFailedError from ``run``."""
        remediation = self.start(finding_id)
        return self.run(remediation.remediation_id, raise_validation_errors=True)

    def start(self, finding_id: int) -> Remediation:
        """Validate the request and create the PENDING row (fast; the API answers 202 with it)."""
        finding = self.db.get(Finding, finding_id)
        if finding is None:
            raise NotFoundError(f"Finding {finding_id} not found")
        self._check_remediable(finding)
        dependency = finding.dependency
        remediation = Remediation(
            finding_id=finding.finding_id, current_version=dependency.version,
            status=RemediationStatus.PENDING, heartbeat_at=utcnow(),
        )
        self.db.add(remediation)
        self.db.commit()
        log.info(
            "Remediation %d queued for %s %s (%s) in repository %d",
            remediation.remediation_id, dependency.package_name, dependency.version,
            finding.vulnerability.identifier, finding.analysis.repository.repository_id,
        )
        return remediation

    def run(self, remediation_id: int, *, raise_validation_errors: bool = False) -> Remediation:
        """Candidates → LLM recommendation → working copy → file change. Never leaves the row PENDING."""
        remediation = self.get(remediation_id)
        finding = remediation.finding
        dependency = finding.dependency
        repository = finding.analysis.repository
        rid = remediation.remediation_id
        remediation.heartbeat_at = utcnow()
        self.db.commit()
        workspace: Path | None = None
        try:
            vulnerabilities = self._vulnerabilities_of(finding)
            candidates = select_candidates(
                dependency, vulnerabilities, registry=self.registry, vulnerability_service=self.vulnerabilities
            )
            remediation.candidates = candidates.to_dict()
            remediation.heartbeat_at = utcnow()
            self.db.commit()
            log.info(
                "Candidates for %s: preferred=%s allowed=%s latest=%s (verified_safe=%s)",
                dependency.package_name, candidates.preferred_version, candidates.allowed_versions,
                candidates.latest_version, candidates.verified_safe,
            )

            result, ai_result_json, note = self._recommend(finding, candidates)
            target_version = result.recommended_version or candidates.preferred_version
            if not target_version:
                raise ValidationFailedError(
                    "No fixed version is available for "
                    f"{dependency.package_name} ({', '.join(v.identifier for v in vulnerabilities)}); "
                    + ("; ".join(candidates.notes) or "OSV publishes no fixed version yet"),
                    details={"candidates": candidates.to_dict()},
                )

            workspace = self.settings.workspace_path / "remediations" / str(rid)
            create_working_copy(resolve_workspace_path(repository.local_path, self.settings) or Path(""), workspace)
            change = get_modifier(dependency.source_file).apply(
                workspace, dependency.source_file, dependency.package_name, dependency.version, target_version
            )

            remediation.recommended_version = target_version
            remediation.alternative_package = result.alternative_package
            remediation.recommendation = self._recommendation_text(result, note)
            remediation.confidence_score = result.confidence
            remediation.ai_result = ai_result_json
            remediation.proposed_change = {**change.to_dict(), "workspace_path": to_workspace_relative(workspace, self.settings)}
            remediation.status = RemediationStatus.PROPOSED
            remediation.heartbeat_at = utcnow()
            self.db.commit()
            log.info("Remediation %d proposed: %s %s → %s in %s", rid, dependency.package_name, dependency.version, target_version, change.file)
            return remediation
        except Exception as exc:  # noqa: BLE001 - record the failure, never leave PENDING
            self.db.rollback()
            remediation = self.db.get(Remediation, rid) or remediation
            remediation.status = RemediationStatus.FAILED
            remediation.error_message = getattr(exc, "message", None) or f"{exc.__class__.__name__}: {exc}"
            remediation.heartbeat_at = utcnow()
            self.db.commit()
            remove_workspace(workspace)
            log.error("Remediation %d failed: %s", rid, remediation.error_message)
            if raise_validation_errors and isinstance(exc, ValidationFailedError):
                raise
            return remediation

    def get(self, remediation_id: int) -> Remediation:
        remediation = self.db.get(Remediation, remediation_id)
        if remediation is None:
            raise NotFoundError(f"Remediation {remediation_id} not found")
        return remediation

    def list_for_finding(self, finding_id: int) -> list[Remediation]:
        return list(self.db.scalars(select(Remediation).where(Remediation.finding_id == finding_id).order_by(Remediation.remediation_id)))

    # ------------------------------------------------------------------ steps

    def _check_remediable(self, finding: Finding) -> None:
        dependency = finding.dependency
        if not dependency.version:
            raise ValidationFailedError(
                f"{dependency.package_name} has no concrete version in {dependency.source_file}; pin it before remediating"
            )
        get_modifier(dependency.source_file)  # raises for lock files / unsupported manifests
        repository = finding.analysis.repository
        local = resolve_workspace_path(repository.local_path, self.settings) if repository.local_path else None
        if local is None or not local.is_dir():
            raise ValidationFailedError(
                "The repository working copy is missing; re-run the analysis with refresh=true",
                details={"repository_id": repository.repository_id},
            )

    def _vulnerabilities_of(self, finding: Finding) -> list[Vulnerability]:
        """Every vulnerability of the dependency in this analysis (the fix must cover all of them)."""
        rows = self.db.scalars(
            select(Finding).where(Finding.analysis_id == finding.analysis_id, Finding.dependency_id == finding.dependency_id)
        ).all()
        seen: dict[int, Vulnerability] = {}
        for row in sorted(rows, key=lambda f: (f.finding_id != finding.finding_id, f.finding_id)):
            seen.setdefault(row.vulnerability_id, row.vulnerability)
        return list(seen.values())

    def _recommend(self, finding: Finding, candidates: CandidateSet) -> tuple[RemediationResult, dict | None, str | None]:
        """LLM recommendation with a deterministic fallback; returns (result, ai_json, fallback_note)."""
        if self.orchestrator is None:
            return self._deterministic(candidates, "no LLM provider configured"), None, "LLM unavailable: no LLM provider configured"
        context = build_finding_context(finding, self.graph)
        try:
            result = self.orchestrator.recommend_remediation(context, candidates, prior=finding.ai_results)
        except (LLMError, AgentError, StructuredOutputError) as exc:
            reason = str(exc)
            log.warning("LLM recommendation unavailable (%s); using the deterministic candidate", reason)
            return self._deterministic(candidates, reason), None, f"LLM unavailable: {reason}"
        return result, result.model_dump(mode="json"), None

    @staticmethod
    def _deterministic(candidates: CandidateSet, reason: str) -> RemediationResult:
        version = candidates.preferred_version
        reasoning = (
            f"Deterministic recommendation (LLM unavailable: {reason}). "
            + (
                f"{version} is the lowest version that OSV lists as fixing every known vulnerability of this dependency"
                + (" and that OSV verified as clean" if candidates.verified_safe else "")
                + "."
                if version
                else "No fixed version is available."
            )
        )
        return RemediationResult(
            recommended_version=version,
            alternative_package=None,
            reasoning=reasoning,
            compatibility_notes="; ".join(candidates.notes),
            confidence=DETERMINISTIC_CONFIDENCE if version else 0.0,
        )

    @staticmethod
    def _recommendation_text(result: RemediationResult, note: str | None) -> str:
        parts = [result.reasoning.strip()]
        if result.compatibility_notes:
            parts.append(f"Compatibility: {result.compatibility_notes.strip()}")
        if note:
            parts.append(note)
        return "\n".join(p for p in parts if p)
