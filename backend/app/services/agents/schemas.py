"""Structured inputs / outputs for the AI agents.

Outputs are strict Pydantic models: the LLM must return JSON matching them.
Inputs are plain dataclass-like models built by the orchestrator from stored,
observed data — the agents never see anything that was not extracted from the
repository, OSV or the knowledge graph.
"""

from __future__ import annotations

import math
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from app.models.enums import ImpactLevel, RiskLevel

Confidence = float


def _clamp(value: Any) -> float:
    """Validate a model-supplied confidence: a finite number in ``[0, 1]``.

    Anything else — ``null``, a list, an object, a non-numeric string, or a value
    outside the range (e.g. a percentage such as ``90``) — raises ``ValueError``
    so Pydantic reports it as a regular ``ValidationError`` naming the field and
    the structured-output layer re-prompts the model. Nothing is silently
    normalised (audit F-15): a "90" clamped to 1.0 would look maximally confident.
    """
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        given = "null" if value is None else type(value).__name__
        raise ValueError(f"must be a number between 0 and 1, got {given}") from exc
    if math.isnan(number) or math.isinf(number):
        raise ValueError("must be a finite number between 0 and 1")
    if number < 0.0 or number > 1.0:
        raise ValueError(f"must be between 0 and 1 (a fraction, not a percentage), got {number:g}")
    return number


# ---------------------------------------------------------------- context (input) models


class RepositoryContext(BaseModel):
    name: str
    language: str | None = None
    source_type: str
    components: list[str] = Field(default_factory=list, description="component paths observed in the repository")
    dependency_files: list[str] = Field(default_factory=list)


class DependencyContext(BaseModel):
    package_name: str
    ecosystem: str
    version: str | None = None
    version_spec: str | None = None
    scope: str = "unknown"
    source_file: str


class VulnerabilityContext(BaseModel):
    identifier: str
    aliases: list[str] = Field(default_factory=list)
    severity: str = "UNKNOWN"
    cvss_score: float | None = None
    summary: str | None = None
    description: str | None = None
    fixed_versions: list[str] = Field(default_factory=list)
    reference_url: str | None = None


class UsageReferenceContext(BaseModel):
    file: str
    line: int
    snippet: str


class UsageContext(BaseModel):
    """FACTS: where the dependency is referenced in the repository's own source."""

    import_names: list[str] = Field(default_factory=list)
    references: list[UsageReferenceContext] = Field(default_factory=list)
    files: list[str] = Field(default_factory=list)
    components: list[str] = Field(default_factory=list)
    truncated: bool = False


class GraphContext(BaseModel):
    """FACTS: relationships stored in the knowledge graph."""

    available: bool = False
    components_using: list[str] = Field(default_factory=list)
    depends_on: list[str] = Field(default_factory=list)
    depended_on_by: list[str] = Field(default_factory=list)
    vulnerabilities: list[str] = Field(default_factory=list)
    paths: list[list[str]] = Field(default_factory=list)


class FindingContext(BaseModel):
    repository: RepositoryContext
    dependency: DependencyContext
    vulnerability: VulnerabilityContext
    usage: UsageContext
    graph: GraphContext


# ---------------------------------------------------------------- agent output models


class DependencyAnalysisResult(BaseModel):
    summary: str = Field(description="What the dependency is and how this application uses it")
    usage_evidence: list[str] = Field(
        default_factory=list,
        description="Factual statements derived ONLY from the provided evidence (file references, graph relations)",
    )
    confidence: Confidence = Field(ge=0, le=1)

    @field_validator("confidence", mode="before")
    @classmethod
    def _clamp_conf(cls, v):
        return _clamp(v)


class ImpactAssessmentResult(BaseModel):
    affected_components: list[str] = Field(
        default_factory=list, description="Component paths from the provided evidence that are affected"
    )
    impact_level: ImpactLevel
    facts: list[str] = Field(default_factory=list, description="Statements backed by provided evidence")
    inferences: list[str] = Field(default_factory=list, description="Reasoned conclusions, clearly labelled")
    reasoning: str
    confidence: Confidence = Field(ge=0, le=1)

    @field_validator("confidence", mode="before")
    @classmethod
    def _clamp_conf(cls, v):
        return _clamp(v)

    @field_validator("impact_level", mode="before")
    @classmethod
    def _norm_level(cls, v):
        return str(v).strip().upper() if isinstance(v, str) else v


class RiskAssessmentResult(BaseModel):
    risk_level: RiskLevel
    factors: list[str] = Field(default_factory=list)
    reasoning: str
    confidence: Confidence = Field(ge=0, le=1)

    @field_validator("confidence", mode="before")
    @classmethod
    def _clamp_conf(cls, v):
        return _clamp(v)

    @field_validator("risk_level", mode="before")
    @classmethod
    def _norm_level(cls, v):
        return str(v).strip().upper() if isinstance(v, str) else v


class RemediationResult(BaseModel):
    recommended_version: str | None = Field(
        default=None, description="Must be one of the candidate versions offered in the prompt"
    )
    alternative_package: str | None = None
    reasoning: str
    compatibility_notes: str = ""
    confidence: Confidence = Field(ge=0, le=1)

    @field_validator("confidence", mode="before")
    @classmethod
    def _clamp_conf(cls, v):
        return _clamp(v)

    @field_validator("recommended_version", "alternative_package", mode="before")
    @classmethod
    def _empty_to_none(cls, v):
        if isinstance(v, str) and v.strip().lower() in {"", "none", "null", "n/a"}:
            return None
        return v


class AgentFailure(BaseModel):
    agent: str
    error: str
    raw_output: str | None = None


class FindingAIResult(BaseModel):
    """Everything the orchestrator produced for one finding."""

    status: Literal["COMPLETED", "FAILED", "UNAVAILABLE"]
    dependency_analysis: DependencyAnalysisResult | None = None
    impact: ImpactAssessmentResult | None = None
    risk: RiskAssessmentResult | None = None
    failures: list[AgentFailure] = Field(default_factory=list)
    model: str | None = None
    # Component names the LLM listed that were NOT in the evidence and were therefore dropped.
    dropped_components: list[str] = Field(default_factory=list)
