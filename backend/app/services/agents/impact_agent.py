"""Agent 2: which application components are affected and how badly?"""

from __future__ import annotations

from app.services.agents.base import BaseAgent
from app.services.agents.prompts import build_impact_prompt
from app.services.agents.schemas import DependencyAnalysisResult, FindingContext, ImpactAssessmentResult


class ImpactAssessmentAgent(BaseAgent[ImpactAssessmentResult]):
    """Assesses application impact from usage + graph evidence.

    The raw result may still name components outside the evidence; the
    orchestrator applies the component guardrail after this agent returns.
    """

    name = "ImpactAssessmentAgent"
    output_model = ImpactAssessmentResult
    field_order = ("facts", "inferences", "reasoning", "affected_components", "impact_level", "confidence")

    def build_prompt(
        self, context: FindingContext, dependency_analysis: DependencyAnalysisResult | None = None
    ) -> str:
        return build_impact_prompt(context, dependency_analysis)

    def run(
        self, context: FindingContext, dependency_analysis: DependencyAnalysisResult | None = None
    ) -> ImpactAssessmentResult:
        return super().run(context, dependency_analysis)
