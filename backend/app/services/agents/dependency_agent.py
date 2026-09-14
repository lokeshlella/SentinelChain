"""Agent 1: what is this dependency and how does the application use it?"""

from __future__ import annotations

from app.services.agents.base import BaseAgent
from app.services.agents.prompts import build_dependency_analysis_prompt
from app.services.agents.schemas import DependencyAnalysisResult, FindingContext


class DependencyAnalysisAgent(BaseAgent[DependencyAnalysisResult]):
    """Summarises the dependency and lists FACT-level usage evidence."""

    name = "DependencyAnalysisAgent"
    output_model = DependencyAnalysisResult
    field_order = ("summary", "usage_evidence", "confidence")

    def build_prompt(self, context: FindingContext) -> str:
        return build_dependency_analysis_prompt(context)

    def run(self, context: FindingContext) -> DependencyAnalysisResult:  # noqa: D102 (documented on BaseAgent)
        return super().run(context)
