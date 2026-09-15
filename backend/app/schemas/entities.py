"""Pydantic response / request models for the REST API (one place, shared nested summaries)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.redaction import redact_secrets


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------- repositories


class RepositoryCreate(BaseModel):
    source_url: str = Field(min_length=1, description="GitHub URL (https://github.com/owner/repo) or local directory path")
    source_type: str | None = Field(default=None, description="github | local (auto-detected when omitted)")
    branch: str | None = None


class AnalyzeRequest(BaseModel):
    refresh: bool = Field(default=False, description="Re-clone / re-copy the repository before analysing")
    run_ai: bool = Field(default=True, description="Run the LLM agents on the findings")


class ComponentOut(ORMModel):
    component_id: int
    name: str
    path: str
    component_type: str
    description: str | None = None
    file_count: int


class AnalysisSummary(ORMModel):
    analysis_id: int
    repository_id: int
    status: str
    overall_risk: str | None = None
    triggered_by: str
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    stages: dict[str, Any] | None = None
    error_message: str | None = None
    findings_count: int = 0
    dependencies_count: int = 0


class RepositorySummary(ORMModel):
    repository_id: int
    name: str
    source_url: str
    source_type: str
    status: str = "READY"  # PENDING (ingesting) | READY | FAILED
    error_message: str | None = None
    branch: str | None = None
    language: str | None = None
    commit_sha: str | None = None
    created_at: datetime
    updated_at: datetime
    latest_analysis: AnalysisSummary | None = None
    dependencies_count: int = 0
    vulnerable_count: int = 0


class RepositoryDetail(RepositorySummary):
    local_path: str | None = None
    profile: dict[str, Any] | None = None
    components: list[ComponentOut] = Field(default_factory=list)
    analyses: list[AnalysisSummary] = Field(default_factory=list)


# ---------------------------------------------------------------- dependencies / vulnerabilities


class VulnerabilitySummary(ORMModel):
    vulnerability_id: int
    identifier: str
    source: str
    aliases: list[str] | None = None
    severity: str
    cvss_score: float | None = None
    summary: str | None = None
    reference_url: str | None = None


class VulnerabilityDetail(VulnerabilitySummary):
    cvss_vector: str | None = None
    description: str | None = None
    published_at: datetime | None = None
    modified_at: datetime | None = None
    affected: list[Any] | None = None
    fetched_at: datetime


class DependencySummary(ORMModel):
    dependency_id: int
    repository_id: int
    analysis_id: int
    package_name: str
    version: str | None = None
    version_spec: str | None = None
    ecosystem: str
    direct_or_transitive: str
    source_file: str
    vulnerability_status: str
    status_reason: str | None = None
    last_checked_at: datetime | None = None


class RelationOut(BaseModel):
    relation_id: int
    parent_dependency_id: int
    child_dependency_id: int
    relation_type: str
    parent: str
    child: str


class DependencyDetail(DependencySummary):
    vulnerabilities: list[VulnerabilitySummary] = Field(default_factory=list)
    findings: list["FindingSummary"] = Field(default_factory=list)
    depends_on: list[RelationOut] = Field(default_factory=list)
    depended_on_by: list[RelationOut] = Field(default_factory=list)


# ---------------------------------------------------------------- analyses / findings


class AnalysisDetail(AnalysisSummary):
    summary: dict[str, Any] | None = None
    repository: RepositorySummary | None = None


class FindingSummary(ORMModel):
    finding_id: int
    analysis_id: int
    dependency_id: int
    vulnerability_id: int
    impact_level: str | None = None
    risk_level: str | None = None
    ai_status: str
    ai_updated_at: datetime | None = None
    affected_components: list[str] | None = None
    detected_at: datetime
    dependency: DependencySummary | None = None
    vulnerability: VulnerabilitySummary | None = None


class FindingDetail(FindingSummary):
    usage_evidence: dict[str, Any] | None = None
    reasoning: str | None = None
    ai_results: dict[str, Any] | None = None
    ai_error: str | None = None
    repository: RepositorySummary | None = None
    vulnerability: VulnerabilityDetail | None = None
    remediations: list["RemediationSummary"] = Field(default_factory=list)


# ---------------------------------------------------------------- remediation / validation / PR


class RemediationSummary(ORMModel):
    remediation_id: int
    finding_id: int
    current_version: str | None = None
    recommended_version: str | None = None
    alternative_package: str | None = None
    recommendation: str | None = None
    confidence_score: float | None = None
    status: str
    error_message: str | None = None
    created_at: datetime


class ValidationSummary(ORMModel):
    validation_id: int
    remediation_id: int
    status: str
    build_status: str
    test_status: str
    security_scan_status: str
    overall_result: str
    logs_path: str | None = None
    error_message: str | None = None
    validated_at: datetime | None = None
    created_at: datetime


class ValidationDetail(ValidationSummary):
    details: dict[str, Any] | None = None
    logs: str | None = None


class PullRequestSummary(ORMModel):
    pr_id: int
    remediation_id: int
    pr_url: str | None = None
    pr_number: int | None = None
    branch_name: str | None = None
    title: str
    review_status: str
    error_message: str | None = None
    created_at: datetime
    reviewed_at: datetime | None = None


class PullRequestDetail(PullRequestSummary):
    body: str | None = None
    evidence: dict[str, Any] | None = None
    instructions: str | None = None


class RemediationDetail(RemediationSummary):
    candidates: dict[str, Any] | None = None
    ai_result: dict[str, Any] | None = None
    proposed_change: dict[str, Any] | None = None
    finding: FindingSummary | None = None
    validations: list[ValidationSummary] = Field(default_factory=list)
    pull_requests: list[PullRequestSummary] = Field(default_factory=list)

    @field_validator("proposed_change")
    @classmethod
    def _redact_proposed_change(cls, change: dict[str, Any] | None) -> dict[str, Any] | None:
        """Rows written before audit V2-04 may still hold manifest credentials; never serve them."""
        if not change:
            return change
        return {k: (redact_secrets(v) if isinstance(v, str) else v) for k, v in change.items()}


# ---------------------------------------------------------------- dashboard


class DashboardOut(BaseModel):
    repositories: int
    analyses: int
    dependencies: int
    vulnerable_dependencies: int
    findings: int
    findings_by_risk: dict[str, int]
    remediations: int
    validations: int
    pull_requests: int
    recent_analyses: list[AnalysisSummary]
    high_risk_findings: list[FindingSummary]
    recent_repositories: list[RepositorySummary]


DependencyDetail.model_rebuild()
FindingDetail.model_rebuild()
