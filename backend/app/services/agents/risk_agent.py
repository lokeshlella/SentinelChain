"""Agent 3: overall risk of the finding for this application."""

from __future__ import annotations

from app.services.agents.base import BaseAgent
from app.services.agents.prompts import build_risk_prompt
from app.services.agents.schemas import (
    DependencyAnalysisResult,
    FindingContext,
    ImpactAssessmentResult,
    RiskAssessmentResult,
)


class RiskEvaluationAgent(BaseAgent[RiskAssessmentResult]):
    """Combines severity, usage evidence and the impact assessment into a risk level."""

    name = "RiskEvaluationAgent"
    output_model = RiskAssessmentResult
    field_order = ("factors", "reasoning", "risk_level", "confidence")

    def build_prompt(
        self,
        context: FindingContext,
        dependency_analysis: DependencyAnalysisResult | None = None,
        impact: ImpactAssessmentResult | None = None,
    ) -> str:
        return build_risk_prompt(context, dependency_analysis, impact)

    def run(
        self,
        context: FindingContext,
        dependency_analysis: DependencyAnalysisResult | None = None,
        impact: ImpactAssessmentResult | None = None,
    ) -> RiskAssessmentResult:
        return super().run(context, dependency_analysis, impact)
