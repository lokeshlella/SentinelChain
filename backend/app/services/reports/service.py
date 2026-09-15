"""Evidence report generation (stage logger "Report").

An :class:`EvidenceReport` is rebuilt from PostgreSQL rows alone — the generator
never calls OSV, Neo4j, Ollama, Docker or GitHub — so the same stored state always
yields the same report. Every section keeps four kinds of content in dedicated
keys that are never mixed:

* ``observed_facts``      — what was extracted, queried or executed (repository
                             profile, OSV record, source references, candidates, ...)
* ``ai_reasoning``        — what the LLM agents inferred (clearly labelled inference)
* ``recommendations``     — the proposed remediation and the final decision
* ``validation_results``  — what the Docker sandbox and the security scan observed

The ten sections are exactly the ones named in the V1 specification (§16).
"""

from __future__ import annotations

import json
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from jinja2 import Environment, FileSystemLoader
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError, SentinelError
from app.core.logging import get_stage_logger
from app.core.redaction import redact_secrets
from app.core.versions import normalize_package_name
from app.db.base import utcnow
from app.models import (
    Analysis,
    Dependency,
    DependencyRelation,
    Finding,
    PullRequest,
    Remediation,
    Repository,
    Validation,
    Vulnerability,
)
from app.services.sandbox.service import is_partial_pass
from app.models.enums import AIStatus, CheckResult, ImpactLevel, RemediationStatus, RiskLevel, StageStatus, ValidationStatus
from app.services.analysis.context import fixed_versions_for
from app.services.analysis.risk import provisional_risk_from_severity, risk_rank
from app.services.analysis.usage import UsageEvidence
from app.services.reports.markdown import escape_table_cell, render_value
from app.services.repository.analyzer import RepositoryProfile

log = get_stage_logger("Report")

REPORT_VERSION = "1.0"
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
TEMPLATE_NAME = "evidence_report.md.j2"
REPORT_JSON_FILENAME = "report.json"
REPORT_MARKDOWN_FILENAME = "report.md"

#: The ten section titles of the V1 specification, in order.
SECTION_TITLES: tuple[str, ...] = (
    "Repository",
    "Analysis",
    "Dependency",
    "Vulnerability",
    "Evidence",
    "Application Impact",
    "Risk Assessment",
    "Recommended Remediation",
    "Validation",
    "Final Recommendation",
)

DECISION_APPLY = "Apply"
DECISION_APPLY_WITH_MANUAL_TESTING = "Apply with manual testing"
DECISION_DO_NOT_APPLY = "Do not apply yet"
DECISION_ANALYSIS_ONLY = "Analysis only — not validated"

Decision = Literal["Apply", "Apply with manual testing", "Do not apply yet", "Analysis only — not validated"]

RISK_ORIGIN_AI = "AI"
RISK_ORIGIN_PROVISIONAL = "provisional (severity-based)"
RISK_ORIGIN_FLOOR = "provisional floor (AI judged lower)"

NO_REMEDIATION_NOTE = "No remediation generated yet"
NO_VALIDATION_NOTE = "No validation run yet"


# ---------------------------------------------------------------------- models


class FinalRecommendation(BaseModel):
    decision: Decision
    reason: str


class ReportSection(BaseModel):
    number: int = Field(ge=1, le=len(SECTION_TITLES))
    title: str
    observed_facts: dict[str, Any] = Field(default_factory=dict)
    ai_reasoning: dict[str, Any] | None = None
    recommendations: dict[str, Any] | None = None
    validation_results: dict[str, Any] | None = None
    notes: list[str] = Field(default_factory=list)


class EvidenceReport(BaseModel):
    report_version: str = REPORT_VERSION
    generated_at: datetime
    title: str
    finding_id: int
    analysis_id: int
    repository_id: int
    remediation_id: int | None = None
    validation_id: int | None = None
    pull_request_id: int | None = None
    final_recommendation: FinalRecommendation
    sections: list[ReportSection]

    @model_validator(mode="after")
    def _check_sections(self) -> "EvidenceReport":
        titles = [section.title for section in self.sections]
        if tuple(titles) != SECTION_TITLES:
            raise ValueError(f"report must contain exactly the sections {list(SECTION_TITLES)} in order, got {titles}")
        numbers = [section.number for section in self.sections]
        if numbers != list(range(1, len(SECTION_TITLES) + 1)):
            raise ValueError(f"section numbers must be 1..{len(SECTION_TITLES)} in order, got {numbers}")
        return self

    def section(self, title: str) -> ReportSection:
        """The section called ``title`` (one of :data:`SECTION_TITLES`)."""
        for section in self.sections:
            if section.title == title:
                return section
        raise KeyError(title)


# ---------------------------------------------------------------------- final recommendation


def final_recommendation(remediation: Remediation | None, validation: Validation | None) -> FinalRecommendation:
    """Deterministic decision from the stored remediation / validation state.

    * no remediation or no validation                → "Analysis only — not validated"
    * validation not COMPLETED (FAILED / RUNNING / PENDING) → "Do not apply yet"
    * overall PASS (build, tests and security all passed)          → "Apply"
    * build PASS + security PASS + tests SKIPPED (overall UNKNOWN) → "Apply with manual testing"
    * anything else (FAIL, UNKNOWN for other reasons)              → "Do not apply yet"
    """
    if remediation is None:
        return FinalRecommendation(
            decision=DECISION_ANALYSIS_ONLY,
            reason="No remediation has been generated for this finding, so nothing has been validated.",
        )
    if validation is None:
        if remediation.status == RemediationStatus.FAILED:
            reason = f"Remediation failed ({remediation.error_message or 'no details recorded'}); nothing has been validated."
        else:
            reason = f"Remediation {remediation.remediation_id} has not been validated in the sandbox yet."
        return FinalRecommendation(decision=DECISION_ANALYSIS_ONLY, reason=reason)
    if validation.status != ValidationStatus.COMPLETED:
        detail = f": {validation.error_message}" if validation.error_message else ""
        return FinalRecommendation(
            decision=DECISION_DO_NOT_APPLY,
            reason=f"Validation {validation.validation_id} did not complete (status {validation.status}{detail}).",
        )
    return _decision_from_results(validation)


def _decision_from_results(validation: Validation) -> FinalRecommendation:
    summary = (
        f"build {validation.build_status}, tests {validation.test_status}, "
        f"security scan {validation.security_scan_status}"
    )
    if validation.overall_result == CheckResult.PASS:
        return FinalRecommendation(
            decision=DECISION_APPLY, reason=f"Validation passed with tests executed and passing ({summary})."
        )
    if is_partial_pass(validation.build_status, validation.test_status, validation.security_scan_status):
        return FinalRecommendation(
            decision=DECISION_APPLY_WITH_MANUAL_TESTING,
            reason=f"Partially validated: the change installs and the security scan is clean, but no automated "
            f"tests were run ({summary}); overall result is {validation.overall_result} — test the change manually.",
        )
    return FinalRecommendation(
        decision=DECISION_DO_NOT_APPLY,
        reason=f"Validation overall result is {validation.overall_result} ({summary}).",
    )


# ---------------------------------------------------------------------- service


class ReportService:
    """Builds evidence reports for findings from the database (no external calls)."""

    def __init__(self, db: Session) -> None:
        self.db = db

    # -------------------------------------------------------------- public API

    def build(self, finding_id: int, remediation_id: int | None = None) -> EvidenceReport:
        """Assemble the report for ``finding_id``.

        With ``remediation_id`` the report covers that remediation (which must belong
        to the finding); otherwise the finding's latest remediation, its latest
        validation and its latest pull request are used.
        """
        finding = self._get_finding(finding_id)
        remediation = self._resolve_remediation(finding, remediation_id)
        validation = self._latest_validation(remediation)
        pull_request = self._latest_pull_request(remediation)
        decision = final_recommendation(remediation, validation)
        report = EvidenceReport(
            generated_at=utcnow(),
            title=_title(finding),
            finding_id=finding.finding_id,
            analysis_id=finding.analysis_id,
            repository_id=finding.analysis.repository_id,
            remediation_id=remediation.remediation_id if remediation else None,
            validation_id=validation.validation_id if validation else None,
            pull_request_id=pull_request.pr_id if pull_request else None,
            final_recommendation=decision,
            sections=self._build_sections(finding, remediation, validation, pull_request, decision),
        )
        log.info(
            "Evidence report built for finding %d (remediation=%s, validation=%s, pull_request=%s): %s",
            finding.finding_id, report.remediation_id, report.validation_id, report.pull_request_id, decision.decision,
        )
        return report

    @staticmethod
    def to_json(report: EvidenceReport) -> dict[str, Any]:
        return to_json(report)

    @staticmethod
    def to_markdown(report: EvidenceReport) -> str:
        return to_markdown(report)

    @staticmethod
    def write_report(report: EvidenceReport, directory: str | Path) -> dict[str, str]:
        return write_report(report, directory)

    # -------------------------------------------------------------- loading

    def _get_finding(self, finding_id: int) -> Finding:
        finding = self.db.get(Finding, finding_id)
        if finding is None:
            raise NotFoundError(f"Finding {finding_id} not found")
        return finding

    def _resolve_remediation(self, finding: Finding, remediation_id: int | None) -> Remediation | None:
        if remediation_id is None:
            return self._latest_remediation(finding)
        remediation = self.db.get(Remediation, remediation_id)
        if remediation is None or remediation.finding_id != finding.finding_id:
            raise NotFoundError(f"Remediation {remediation_id} not found for finding {finding.finding_id}")
        return remediation

    def _latest_remediation(self, finding: Finding) -> Remediation | None:
        stmt = (
            select(Remediation)
            .where(Remediation.finding_id == finding.finding_id)
            .order_by(Remediation.created_at.desc(), Remediation.remediation_id.desc())
            .limit(1)
        )
        return self.db.scalars(stmt).first()

    def _latest_validation(self, remediation: Remediation | None) -> Validation | None:
        if remediation is None:
            return None
        stmt = (
            select(Validation)
            .where(Validation.remediation_id == remediation.remediation_id)
            .order_by(Validation.created_at.desc(), Validation.validation_id.desc())
            .limit(1)
        )
        return self.db.scalars(stmt).first()

    def _latest_pull_request(self, remediation: Remediation | None) -> PullRequest | None:
        if remediation is None:
            return None
        stmt = (
            select(PullRequest)
            .where(PullRequest.remediation_id == remediation.remediation_id)
            .order_by(PullRequest.created_at.desc(), PullRequest.pr_id.desc())
            .limit(1)
        )
        return self.db.scalars(stmt).first()

    def _sibling_findings(self, finding: Finding) -> list[Finding]:
        """Other findings of the same dependency in the same analysis."""
        stmt = (
            select(Finding)
            .where(
                Finding.analysis_id == finding.analysis_id,
                Finding.dependency_id == finding.dependency_id,
                Finding.finding_id != finding.finding_id,
            )
            .order_by(Finding.finding_id)
        )
        return list(self.db.scalars(stmt))

    def _dependency_relations(self, dependency: Dependency) -> dict[str, list[str]]:
        """Lock-file relations stored in PostgreSQL for this dependency snapshot."""
        parents = select(DependencyRelation).where(DependencyRelation.child_dependency_id == dependency.dependency_id)
        children = select(DependencyRelation).where(DependencyRelation.parent_dependency_id == dependency.dependency_id)
        depends_on = [self._dependency_label(r.child_dependency_id) for r in self.db.scalars(children)]
        depended_on_by = [self._dependency_label(r.parent_dependency_id) for r in self.db.scalars(parents)]
        return {"depends_on": sorted(depends_on), "depended_on_by": sorted(depended_on_by)}

    def _dependency_label(self, dependency_id: int) -> str:
        dep = self.db.get(Dependency, dependency_id)
        if dep is None:
            return f"dependency #{dependency_id}"
        return f"{dep.package_name}@{dep.version}" if dep.version else dep.package_name

    # -------------------------------------------------------------- sections

    def _build_sections(
        self,
        finding: Finding,
        remediation: Remediation | None,
        validation: Validation | None,
        pull_request: PullRequest | None,
        decision: FinalRecommendation,
    ) -> list[ReportSection]:
        analysis = finding.analysis
        dependency = finding.dependency
        return [
            repository_section(analysis.repository),
            analysis_section(analysis),
            dependency_section(dependency, self._sibling_findings(finding)),
            vulnerability_section(finding.vulnerability, dependency),
            evidence_section(finding, self._dependency_relations(dependency)),
            impact_section(finding),
            risk_section(finding),
            remediation_section(remediation),
            validation_section(remediation, validation),
            final_section(decision, pull_request),
        ]


# ---------------------------------------------------------------------- section builders


def _section(number: int, **content: Any) -> ReportSection:
    return ReportSection(number=number, title=SECTION_TITLES[number - 1], **content)


def repository_section(repository: Repository) -> ReportSection:
    profile = RepositoryProfile.from_dict(repository.profile or {})
    facts = {
        "repository_id": repository.repository_id,
        "name": repository.name,
        "source_url": repository.source_url,
        "source_type": repository.source_type,
        "branch": repository.branch,
        "commit_sha": repository.commit_sha,
        "language": repository.language,
        "languages": dict(profile.languages),
        "total_files": profile.total_files,
        "dependency_files": list(profile.dependency_files),
        "source_dirs": list(profile.source_dirs),
        "test_dirs": list(profile.test_dirs),
        "components": [
            {"path": c.path, "name": c.name, "type": c.component_type, "files": c.file_count}
            for c in sorted(repository.components, key=lambda c: c.path)
        ],
        "ingested_at": _iso(repository.created_at),
    }
    notes = [] if repository.profile else ["No repository profile stored (the repository was not analysed)"]
    return _section(1, observed_facts=facts, notes=notes)


def analysis_section(analysis: Analysis) -> ReportSection:
    facts = {
        "analysis_id": analysis.analysis_id,
        "repository_id": analysis.repository_id,
        "status": analysis.status,
        "triggered_by": analysis.triggered_by,
        "created_at": _iso(analysis.created_at),
        "started_at": _iso(analysis.started_at),
        "completed_at": _iso(analysis.completed_at),
        "stages": dict(analysis.stages or {}),
        "summary": _json_safe(analysis.summary or {}),
        "overall_risk": analysis.overall_risk,
    }
    notes = []
    if analysis.error_message:
        notes.append(f"Analysis error: {analysis.error_message}")
    for stage, status in (analysis.stages or {}).items():
        if status in (StageStatus.UNAVAILABLE, StageStatus.FAILED, StageStatus.PARTIAL):
            notes.append(f"Stage '{stage}' finished with status {status}")
    return _section(2, observed_facts=facts, notes=notes)


def dependency_section(dependency: Dependency, siblings: list[Finding]) -> ReportSection:
    facts = {
        "dependency_id": dependency.dependency_id,
        "package_name": dependency.package_name,
        "ecosystem": dependency.ecosystem,
        "version": dependency.version,
        "version_spec": dependency.version_spec,
        "scope": dependency.direct_or_transitive,
        "source_file": dependency.source_file,
        "vulnerability_status": dependency.vulnerability_status,
        "status_reason": dependency.status_reason,
        "last_checked_at": _iso(dependency.last_checked_at),
        "other_vulnerabilities_in_this_analysis": [
            {
                "finding_id": f.finding_id,
                "identifier": f.vulnerability.identifier,
                "severity": f.vulnerability.severity,
                "cvss_score": f.vulnerability.cvss_score,
                "summary": f.vulnerability.summary,
            }
            for f in siblings
        ],
    }
    notes = []
    if dependency.version is None:
        notes.append("The dependency version is not pinned; the vulnerability match is based on the declared range")
    if dependency.status_reason:
        notes.append(f"Vulnerability status reason: {dependency.status_reason}")
    return _section(3, observed_facts=facts, notes=notes)


def vulnerability_section(vulnerability: Vulnerability, dependency: Dependency) -> ReportSection:
    facts = {
        "vulnerability_id": vulnerability.vulnerability_id,
        "identifier": vulnerability.identifier,
        "source": vulnerability.source,
        "aliases": list(vulnerability.aliases or []),
        "severity": vulnerability.severity,
        "cvss_score": vulnerability.cvss_score,
        "cvss_vector": vulnerability.cvss_vector,
        "summary": vulnerability.summary,
        "description": vulnerability.description,
        "published_at": _iso(vulnerability.published_at),
        "modified_at": _iso(vulnerability.modified_at),
        "fetched_at": _iso(vulnerability.fetched_at),
        "fixed_versions_for_this_package": fixed_versions_for(vulnerability, dependency.ecosystem, dependency.package_name),
        "affected_ranges_for_this_package": _affected_ranges(vulnerability, dependency),
        "reference_url": vulnerability.reference_url,
    }
    notes = []
    if not facts["fixed_versions_for_this_package"]:
        notes.append("No fixed version is recorded for this package in the vulnerability data")
    if vulnerability.severity in (None, "", "UNKNOWN"):
        notes.append("The vulnerability source did not provide a severity label")
    return _section(4, observed_facts=facts, notes=notes)


def evidence_section(finding: Finding, relations: dict[str, list[str]]) -> ReportSection:
    stage = str((finding.analysis.stages or {}).get("knowledge_graph") or "not run")
    graph_facts = {
        "stage_status": stage,
        "stored_in_report": False,
        "api": f"/api/dependencies/{finding.dependency_id}/graph",
    }
    notes: list[str] = []
    if finding.usage_evidence:
        evidence = UsageEvidence.from_dict(finding.usage_evidence)
        facts = _usage_facts(evidence)
        if not evidence.is_used:
            notes.append(
                "No import of the package was observed in the repository's own source files "
                "(it is declared in a dependency file only)"
            )
        if evidence.truncated:
            notes.append("Usage evidence is partial: a scan limit was reached or part of the tree could not be read")
    else:
        facts = {"affected_components": list(finding.affected_components or [])}
        notes.append("No source-usage evidence was recorded for this finding")
    facts["dependency_relations"] = relations
    facts["knowledge_graph"] = graph_facts
    notes.append(_graph_note(stage))
    return _section(5, observed_facts=facts, notes=notes)


def impact_section(finding: Finding) -> ReportSection:
    ai = _ai_results(finding)
    impact = ai.get("impact") if isinstance(ai.get("impact"), dict) else None
    facts = {
        "components_referencing_dependency": list(finding.affected_components or []),
        "files_referencing_dependency": list((finding.usage_evidence or {}).get("files") or []),
        "stored_impact_level": finding.impact_level,
        "ai_status": finding.ai_status,
    }
    notes = _ai_status_notes(finding, "impact assessment", impact is not None)
    if not facts["files_referencing_dependency"]:
        notes.append(
            "No direct import of the package was found; use through other packages, dynamic imports and "
            "notebooks are not analysed, so this is not evidence that the package is unused"
        )
    reasoning = None
    if impact is not None:
        if impact.get("impact_level") == ImpactLevel.NONE and finding.impact_level != ImpactLevel.NONE:
            notes.append(
                f"The AI judged the impact NONE but the stored level is {finding.impact_level}: Sentinel Chain cannot "
                "establish that a vulnerable package has no impact"
            )
        reasoning = {
            "impact_level": impact.get("impact_level"),
            "affected_components": list(impact.get("affected_components") or []),
            "dropped_components": list(ai.get("dropped_components") or []),
            "facts": list(impact.get("facts") or []),
            "inferences": list(impact.get("inferences") or []),
            "reasoning": impact.get("reasoning"),
            "confidence": impact.get("confidence"),
            "model": ai.get("model"),
            "dependency_analysis": _dependency_analysis(ai),
        }
        if reasoning["dropped_components"]:
            notes.append(
                "The model named components that are not in the evidence; they were dropped "
                f"({', '.join(reasoning['dropped_components'])})"
            )
    return _section(6, observed_facts=facts, ai_reasoning=reasoning, notes=notes)


def risk_section(finding: Finding) -> ReportSection:
    ai = _ai_results(finding)
    risk = ai.get("risk") if isinstance(ai.get("risk"), dict) else None
    severity = finding.vulnerability.severity
    provisional = str(provisional_risk_from_severity(severity))
    ai_level = str(risk.get("risk_level")) if risk and risk.get("risk_level") else None
    if ai_level and ai_level != RiskLevel.UNKNOWN and finding.risk_level == ai_level:
        level, origin = ai_level, RISK_ORIGIN_AI
    elif ai_level and ai_level != RiskLevel.UNKNOWN and finding.risk_level and risk_rank(ai_level) < risk_rank(finding.risk_level):
        # audit V2-01: the model judged below the severity-derived level; the floor was kept
        level, origin = finding.risk_level, RISK_ORIGIN_FLOOR
    else:
        level, origin = (finding.risk_level or provisional), RISK_ORIGIN_PROVISIONAL
    facts = {
        "severity": severity,
        "cvss_score": finding.vulnerability.cvss_score,
        "provisional_risk_from_severity": provisional,
        "risk_level": level,
        "risk_origin": origin,
        "impact_level": finding.impact_level,
        "ai_status": finding.ai_status,
    }
    reasoning = None
    if risk is not None:
        reasoning = {
            "risk_level": risk.get("risk_level"),
            "factors": list(risk.get("factors") or []),
            "reasoning": risk.get("reasoning"),
            "confidence": risk.get("confidence"),
            "model": ai.get("model"),
        }
    notes = _ai_status_notes(finding, "risk assessment", risk is not None)
    if origin == RISK_ORIGIN_PROVISIONAL:
        notes.append("The risk level is provisional: it is derived from the vulnerability severity, not from an AI judgement")
    elif origin == RISK_ORIGIN_FLOOR:
        notes.append(
            f"The AI judged the risk {ai_level} but the stored level is {level}: Sentinel Chain never lowers the risk "
            "below the severity-derived level because it cannot prove that the vulnerable code is unreachable "
            "(the usage scan finds direct imports only)"
        )
    return _section(7, observed_facts=facts, ai_reasoning=reasoning, notes=notes)


def remediation_section(remediation: Remediation | None) -> ReportSection:
    if remediation is None:
        return _section(8, notes=[NO_REMEDIATION_NOTE])
    change = remediation.proposed_change if isinstance(remediation.proposed_change, dict) else None
    facts = {
        "remediation_id": remediation.remediation_id,
        "status": remediation.status,
        "created_at": _iso(remediation.created_at),
        "candidates": _json_safe(remediation.candidates or {}),
    }
    recommendations = {
        "current_version": remediation.current_version,
        "recommended_version": remediation.recommended_version,
        "alternative_package": remediation.alternative_package,
        "recommendation": remediation.recommendation,
        "confidence_score": remediation.confidence_score,
        "status": remediation.status,
        "proposed_change": _proposed_change(change),
    }
    reasoning = _json_safe(remediation.ai_result) if isinstance(remediation.ai_result, dict) else None
    notes: list[str] = []
    if not remediation.candidates:
        notes.append("No candidate information was recorded for this remediation")
    if reasoning is None:
        notes.append("No AI remediation reasoning recorded: the recommendation is deterministic (candidate selection only)")
    if change is None:
        notes.append("No proposed file change was produced")
    if remediation.status == RemediationStatus.FAILED:
        notes.append(f"Remediation failed: {remediation.error_message or 'no details recorded'}")
    return _section(8, observed_facts=facts, ai_reasoning=reasoning, recommendations=recommendations, notes=notes)


def validation_section(remediation: Remediation | None, validation: Validation | None) -> ReportSection:
    if remediation is None:
        return _section(9, notes=[NO_REMEDIATION_NOTE, "Nothing to validate without a remediation"])
    if validation is None:
        return _section(9, notes=[f"{NO_VALIDATION_NOTE} for remediation {remediation.remediation_id}"])
    details = dict(validation.details) if isinstance(validation.details, dict) else {}
    results = {
        "validation_id": validation.validation_id,
        "remediation_id": validation.remediation_id,
        "status": validation.status,
        "build_status": validation.build_status,
        "test_status": validation.test_status,
        "security_scan_status": validation.security_scan_status,
        "overall_result": validation.overall_result,
        "created_at": _iso(validation.created_at),
        "validated_at": _iso(validation.validated_at),
        "steps": _json_safe(details.pop("steps", None)),
        "warnings": _json_safe(details.pop("warnings", None)),
        "security_scan": _json_safe(details.pop("security_scan", details.pop("security", None))),
        "logs_path": validation.logs_path,
        "error_message": validation.error_message,
        "other_details": _json_safe(details),
    }
    notes: list[str] = []
    if validation.status != ValidationStatus.COMPLETED:
        notes.append(f"Validation did not complete (status {validation.status}): {validation.error_message or 'no details'}")
    if validation.test_status == CheckResult.SKIPPED:
        notes.append("Tests were skipped inside the sandbox; a skipped test is never reported as PASS")
    if validation.test_status == CheckResult.UNKNOWN or validation.build_status == CheckResult.UNKNOWN:
        notes.append("A check that did not produce a result is reported as UNKNOWN, never as PASS")
    if validation.security_scan_status == CheckResult.UNKNOWN:
        notes.append("The security scan could not verify the proposed dependency state (vulnerability data unavailable)")
    return _section(9, validation_results=results, notes=notes)


def final_section(decision: FinalRecommendation, pull_request: PullRequest | None) -> ReportSection:
    recommendations = {"decision": decision.decision, "reason": decision.reason}
    if pull_request is None:
        return _section(10, recommendations=recommendations, notes=["No pull request has been created"])
    facts = {
        "pull_request": {
            "pull_request_id": pull_request.pr_id,
            "status": pull_request.review_status,
            "url": pull_request.pr_url,
            "number": pull_request.pr_number,
            "branch": pull_request.branch_name,
            "title": pull_request.title,
            "created_at": _iso(pull_request.created_at),
            "error_message": pull_request.error_message,
            "instructions": pull_request.instructions,
        }
    }
    notes: list[str] = []
    if pull_request.review_status in ("UNAVAILABLE", "FAILED"):
        notes.append(f"GitHub PR creation {pull_request.review_status.lower()}: {pull_request.error_message or 'see instructions'}")
    return _section(10, observed_facts=facts, recommendations=recommendations, notes=notes)


# ---------------------------------------------------------------------- section helpers


def _title(finding: Finding) -> str:
    dep = finding.dependency
    version = f" {dep.version}" if dep.version else ""
    return (
        f"Evidence report: {dep.package_name}{version} / {finding.vulnerability.identifier} "
        f"({finding.analysis.repository.name})"
    )


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _json_safe(value: Any) -> Any:
    """Copy of ``value`` with datetimes / enums / tuples turned into JSON-native types."""
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
        return value
    return str(value)


def _affected_ranges(vulnerability: Vulnerability, dependency: Dependency) -> list[dict[str, Any]]:
    wanted = normalize_package_name(dependency.package_name, dependency.ecosystem)
    ranges: list[dict[str, Any]] = []
    for pkg in vulnerability.affected or []:
        if not isinstance(pkg, dict) or pkg.get("ecosystem") != dependency.ecosystem:
            continue
        if normalize_package_name(str(pkg.get("package_name", "")), dependency.ecosystem) != wanted:
            continue
        for rng in pkg.get("ranges") or []:
            if isinstance(rng, dict):
                ranges.append(
                    {
                        "type": rng.get("range_type") or rng.get("type"),
                        "introduced": rng.get("introduced"),
                        "fixed": rng.get("fixed"),
                        "last_affected": rng.get("last_affected"),
                    }
                )
    return ranges


def _usage_facts(evidence: UsageEvidence) -> dict[str, Any]:
    return {
        "package_name": evidence.package_name,
        "ecosystem": evidence.ecosystem,
        "import_names": list(evidence.import_names),
        "files": list(evidence.files),
        "total_files": evidence.total_files,
        "scanned_files": evidence.scanned_files,
        "references": [r.to_dict() for r in evidence.references],
        "affected_components": list(evidence.components),
        "truncated": evidence.truncated,
    }


def _graph_note(stage: str) -> str:
    if stage == StageStatus.OK:
        return (
            "Knowledge graph relationships (components using the dependency, related dependencies, paths) "
            "are not stored on the finding; they are available via the API (GET /api/dependencies/{id}/graph)"
        )
    return f"Knowledge graph relationships are not available: the knowledge graph stage was {stage}"


def _ai_results(finding: Finding) -> dict[str, Any]:
    return dict(finding.ai_results) if isinstance(finding.ai_results, dict) else {}


def _dependency_analysis(ai: dict[str, Any]) -> dict[str, Any] | None:
    analysis = ai.get("dependency_analysis")
    if not isinstance(analysis, dict):
        return None
    return {
        "summary": analysis.get("summary"),
        "usage_evidence": list(analysis.get("usage_evidence") or []),
        "confidence": analysis.get("confidence"),
    }


def _ai_status_notes(finding: Finding, what: str, present: bool) -> list[str]:
    status = str(finding.ai_status)
    error = finding.ai_error or "no details recorded"
    if not present:
        return [f"AI {what} not available ({status}: {error})"]
    if status != AIStatus.COMPLETED:
        return [f"AI analysis finished with status {status}: {error}"]
    return []


def _proposed_change(change: dict[str, Any] | None) -> dict[str, Any] | None:
    if change is None:
        return None
    return {
        "file": change.get("file"),
        "line_number": change.get("line_number"),
        # redacted at source since audit V2-04; applied again for rows stored before that
        "diff": redact_secrets(change.get("diff")),
    }


# ---------------------------------------------------------------------- output formats


def to_json(report: EvidenceReport) -> dict[str, Any]:
    """JSON-native dict (round-trips through ``EvidenceReport.model_validate``)."""
    return report.model_dump(mode="json")


def to_markdown(report: EvidenceReport) -> str:
    """Render the report with ``templates/evidence_report.md.j2`` (plain Markdown, no HTML)."""
    template = _environment().get_template(TEMPLATE_NAME)
    return template.render(report=report, header=_header(report))


def write_report(report: EvidenceReport, directory: str | Path) -> dict[str, str]:
    """Write ``report.json`` and ``report.md`` into ``directory`` and return their paths."""
    target = Path(directory)
    json_path = target / REPORT_JSON_FILENAME
    markdown_path = target / REPORT_MARKDOWN_FILENAME
    try:
        target.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(to_json(report), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        markdown_path.write_text(to_markdown(report), encoding="utf-8")
    except OSError as exc:
        raise SentinelError(f"Could not write the evidence report to {target}: {exc}") from exc
    log.info("Evidence report for finding %d written to %s", report.finding_id, target)
    return {"json": str(json_path), "markdown": str(markdown_path)}


@lru_cache(maxsize=1)
def _environment() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["md_block"] = render_value
    env.filters["cell"] = escape_table_cell
    return env


def _header(report: EvidenceReport) -> dict[str, str]:
    """The short header table: repository, dependency, vulnerability, risk, decision."""
    repo = report.section("Repository").observed_facts
    dep = report.section("Dependency").observed_facts
    vuln = report.section("Vulnerability").observed_facts
    risk = report.section("Risk Assessment").observed_facts
    version = f" {dep.get('version')}" if dep.get("version") else ""
    cvss = f", CVSS {vuln.get('cvss_score')}" if vuln.get("cvss_score") is not None else ""
    return {
        "repository": f"{repo.get('name') or 'n/a'} ({repo.get('source_url') or 'n/a'})",
        "dependency": f"{dep.get('package_name')}{version} ({dep.get('ecosystem')}, {dep.get('source_file')})",
        "vulnerability": f"{vuln.get('identifier')} (severity {vuln.get('severity')}{cvss})",
        "risk": f"{risk.get('risk_level')} ({risk.get('risk_origin')})",
        "decision": report.final_recommendation.decision,
        "generated_at": report.generated_at.isoformat(),
    }
