"""Agent 4: which candidate version should be applied, and what to watch out for."""

from __future__ import annotations

from typing import Any

from app.services.agents.base import BaseAgent
from app.services.agents.prompts import build_remediation_prompt
from app.services.agents.schemas import (
    DependencyAnalysisResult,
    FindingContext,
    ImpactAssessmentResult,
    RemediationResult,
    RiskAssessmentResult,
)


class RemediationAgent(BaseAgent[RemediationResult]):
    """Chooses among the deterministic candidate versions and explains the choice.

    ``candidates`` is the plain-dict view of a ``CandidateSet`` (keys
    ``allowed_versions``, ``preferred_version``, ``latest_version``,
    ``minimum_fixed_version``, ``same_major``, ``notes``, ...). The version
    guardrail is enforced by the orchestrator, not here.
    """

    name = "RemediationAgent"
    output_model = RemediationResult
    field_order = ("reasoning", "recommended_version", "alternative_package", "compatibility_notes", "confidence")

    def build_prompt(
        self,
        context: FindingContext,
        candidates: dict[str, Any],
        dependency_analysis: DependencyAnalysisResult | None = None,
        impact: ImpactAssessmentResult | None = None,
        risk: RiskAssessmentResult | None = None,
    ) -> str:
        return build_remediation_prompt(context, candidates, dependency_analysis, impact, risk)

    def run(
        self,
        context: FindingContext,
        candidates: dict[str, Any],
        dependency_analysis: DependencyAnalysisResult | None = None,
        impact: ImpactAssessmentResult | None = None,
        risk: RiskAssessmentResult | None = None,
    ) -> RemediationResult:
        return super().run(context, candidates, dependency_analysis, impact, risk)
