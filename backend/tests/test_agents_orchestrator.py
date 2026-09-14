"""Unit tests for AIOrchestrator, BaseAgent and the evidence guardrails (fake provider only)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

import pytest

from app.core.config import Settings
from app.services.agents.base import AgentError
from app.services.agents.dependency_agent import DependencyAnalysisAgent
from app.services.agents.impact_agent import ImpactAssessmentAgent
from app.services.agents.orchestrator import AIOrchestrator, candidate_view, filter_components
from app.services.agents.prompts import SYSTEM_PROMPT
from app.services.agents.remediation_agent import RemediationAgent
from app.services.agents.risk_agent import RiskEvaluationAgent
from app.services.agents.schemas import (
    DependencyAnalysisResult,
    FindingAIResult,
    ImpactAssessmentResult,
    RemediationResult,
    RiskAssessmentResult,
)
from app.services.llm.base import LLMError
from tests.fixtures.agents.contexts import (
    make_context,
    prior_results,
    valid_dependency_output,
    valid_impact_output,
    valid_remediation_output,
    valid_risk_output,
)
from tests.fixtures.llm.fake_provider import FakeLLMProvider


@pytest.fixture
def settings() -> Settings:
    return Settings(llm_max_retries=1, ollama_model="fake-model:1b")


def make_orchestrator(responses: list, settings: Settings) -> tuple[AIOrchestrator, FakeLLMProvider]:
    provider = FakeLLMProvider(list(responses), model="fake-model:1b")
    return AIOrchestrator(provider, settings), provider


@dataclass
class FakeCandidateSet:
    """Duck-typed stand-in for app.services.remediation.candidates.CandidateSet."""

    current_version: str = "2.25.1"
    minimum_fixed_version: str | None = "2.31.0"
    preferred_version: str | None = "2.31.0"
    allowed_versions: list[str] = field(default_factory=lambda: ["2.31.0", "2.32.4"])
    latest_version: str | None = "2.32.4"
    same_major: bool | None = True
    verified_safe: bool | None = True
    remaining_vulnerabilities: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=lambda: ["2.31.0 verified safe against OSV"])
    registry_available: bool = True


# ------------------------------------------------------------------ analyze_finding


def test_completed_path_runs_three_agents_in_order_and_chains_results(settings):
    orchestrator, provider = make_orchestrator(
        [valid_dependency_output(), valid_impact_output(), valid_risk_output()], settings
    )
    result = orchestrator.analyze_finding(make_context())

    assert result.status == "COMPLETED"
    assert result.model == "fake-model:1b"
    assert result.failures == [] and result.dropped_components == []
    assert isinstance(result.dependency_analysis, DependencyAnalysisResult)
    assert isinstance(result.impact, ImpactAssessmentResult)
    assert isinstance(result.risk, RiskAssessmentResult)
    assert result.impact.impact_level == "MEDIUM" and result.risk.risk_level == "MEDIUM"
    assert result.impact.affected_components == ["src/app"]

    assert len(provider.calls) == 3
    dep_call, impact_call, risk_call = provider.calls
    assert all(call.system == SYSTEM_PROMPT for call in provider.calls)
    assert "TASK: Explain what the package 'requests' is" in dep_call.prompt
    assert "TASK: Assess the impact" in impact_call.prompt
    assert result.dependency_analysis.summary in impact_call.prompt  # step 1 feeds step 2
    assert "TASK: Evaluate the overall risk" in risk_call.prompt
    assert result.impact.reasoning in risk_call.prompt  # step 2 feeds step 3
    # every call asks for the strict schema: all keys required, reasoning before verdict
    assert set(impact_call.json_schema["required"]) == set(ImpactAssessmentResult.model_fields)
    assert list(risk_call.json_schema["properties"]) == ["factors", "reasoning", "risk_level", "confidence"]


def test_unavailable_when_first_call_raises_llm_error(settings):
    orchestrator, provider = make_orchestrator(
        [LLMError("Ollama unreachable at http://localhost:11434; start it with `ollama serve`")], settings
    )
    result = orchestrator.analyze_finding(make_context())

    assert result.status == "UNAVAILABLE"
    assert result.dependency_analysis is None and result.impact is None and result.risk is None
    assert len(result.failures) == 1
    assert result.failures[0].agent == "DependencyAnalysisAgent"
    assert "ollama serve" in result.failures[0].error
    assert result.failures[0].raw_output is None
    assert len(provider.calls) == 1  # no further LLM calls
    assert result.model == "fake-model:1b"


def test_partial_failure_records_agent_error_and_later_agents_still_run(settings):
    # dependency ok; impact invalid twice (max_retries=1 → 2 attempts); risk ok
    orchestrator, provider = make_orchestrator(
        [
            valid_dependency_output(),
            {**valid_impact_output(), "impact_level": "SEVERE"},
            "I cannot produce JSON for this.",
            valid_risk_output(),
        ],
        settings,
    )
    result = orchestrator.analyze_finding(make_context())

    assert result.status == "FAILED"
    assert result.dependency_analysis is not None
    assert result.impact is None
    assert result.risk is not None and result.risk.risk_level == "MEDIUM"
    assert [f.agent for f in result.failures] == ["ImpactAssessmentAgent"]
    failure = result.failures[0]
    assert failure.raw_output == "I cannot produce JSON for this."
    assert "after 2 attempt(s)" in failure.error
    assert len(provider.calls) == 4
    # the correction prompt carried the validation error back to the model
    assert "impact_level" in provider.calls[2].prompt and "SEVERE" in provider.calls[2].prompt
    # the risk agent ran without an impact section
    assert "PREVIOUS STEP: IMPACT ASSESSMENT" not in provider.calls[3].prompt
    assert "PREVIOUS STEP: DEPENDENCY ANALYSIS" in provider.calls[3].prompt


def test_llm_error_after_first_call_is_recorded_not_unavailable(settings):
    orchestrator, provider = make_orchestrator(
        [valid_dependency_output(), LLMError("Ollama did not answer within 180s"), valid_risk_output()], settings
    )
    result = orchestrator.analyze_finding(make_context())
    assert result.status == "FAILED"
    assert [f.agent for f in result.failures] == ["ImpactAssessmentAgent"]
    assert "180s" in result.failures[0].error
    assert result.risk is not None
    assert len(provider.calls) == 3


def test_all_agents_failing_yields_failed_with_three_failures(settings):
    orchestrator, _ = make_orchestrator(
        [valid_dependency_output(), "bad", "bad", "bad", "bad"],
        settings,
    )
    result = orchestrator.analyze_finding(make_context())
    assert result.status == "FAILED"
    assert [f.agent for f in result.failures] == ["ImpactAssessmentAgent", "RiskEvaluationAgent"]
    assert result.dependency_analysis is not None and result.impact is None and result.risk is None


def test_component_guardrail_drops_invented_components(settings):
    ctx = make_context(usage_components=["src/app"], repo_components=["src/app", "tests"])
    invented = ["src/app", "src/auth/", "./tests", "lib/payments", "TESTS", "src/app"]
    orchestrator, _ = make_orchestrator(
        [valid_dependency_output(), valid_impact_output(invented), valid_risk_output()], settings
    )
    result = orchestrator.analyze_finding(ctx)

    assert result.status == "COMPLETED"
    assert result.impact.affected_components == ["src/app", "tests"]  # evidence spelling, de-duplicated
    assert result.dropped_components == ["src/auth/", "lib/payments"]
    # the risk prompt saw the filtered list only
    assert "src/auth" not in orchestrator.provider.calls[2].prompt  # type: ignore[attr-defined]


def test_component_guardrail_allows_repository_components_without_usage(settings):
    ctx = make_context(usage_components=[], references=[], repo_components=["src/app", "docs"])
    orchestrator, _ = make_orchestrator(
        [valid_dependency_output(), valid_impact_output(["docs", "src/lib"]), valid_risk_output()], settings
    )
    result = orchestrator.analyze_finding(ctx)
    assert result.impact.affected_components == ["docs"]
    assert result.dropped_components == ["src/lib"]


def test_filter_components_helper():
    kept, dropped = filter_components(["a/", "./b", "C", "x"], ["a", "b", "c"])
    assert kept == ["a", "b", "c"] and dropped == ["x"]
    assert filter_components([], ["a"]) == ([], [])
    assert filter_components(["a"], []) == ([], ["a"])


def test_result_serialises_for_storage(settings):
    orchestrator, _ = make_orchestrator(
        [valid_dependency_output(), valid_impact_output(), valid_risk_output()], settings
    )
    result = orchestrator.analyze_finding(make_context())
    stored = json.loads(result.model_dump_json())
    assert stored["status"] == "COMPLETED" and stored["impact"]["impact_level"] == "MEDIUM"
    assert FindingAIResult.model_validate(stored) == result


# ------------------------------------------------------------------ recommend_remediation


def test_remediation_accepts_model_choice_when_allowed(settings):
    orchestrator, provider = make_orchestrator([valid_remediation_output("2.32.4")], settings)
    result = orchestrator.recommend_remediation(make_context(), FakeCandidateSet())
    assert isinstance(result, RemediationResult)
    assert result.recommended_version == "2.32.4"
    assert "adjusted" not in result.reasoning
    prompt = provider.calls[0].prompt
    assert "CANDIDATE VERSIONS (only these may be recommended)" in prompt
    assert "- allowed versions: 2.31.0, 2.32.4" in prompt
    assert list(provider.calls[0].json_schema["properties"])[0] == "reasoning"


def test_remediation_guardrail_substitutes_disallowed_version(settings):
    orchestrator, _ = make_orchestrator([valid_remediation_output("2.99.0")], settings)
    result = orchestrator.recommend_remediation(make_context(), FakeCandidateSet())
    assert result.recommended_version == "2.31.0"
    assert result.reasoning.endswith("(adjusted: model proposed 2.99.0 which is not an allowed candidate)")
    assert result.reasoning.startswith("2.31.0 is the lowest verified-safe version")


def test_remediation_guardrail_uses_preferred_when_model_gives_none(settings):
    orchestrator, _ = make_orchestrator([valid_remediation_output(None)], settings)
    result = orchestrator.recommend_remediation(make_context(), FakeCandidateSet(preferred_version="2.31.0"))
    assert result.recommended_version == "2.31.0"
    assert "(no version proposed by the model; using the preferred candidate 2.31.0)" in result.reasoning


def test_remediation_guardrail_normalises_prefixed_spelling(settings):
    orchestrator, _ = make_orchestrator([valid_remediation_output("v2.32.4")], settings)
    result = orchestrator.recommend_remediation(make_context(), FakeCandidateSet())
    assert result.recommended_version == "2.32.4"
    assert "adjusted" not in result.reasoning


def test_remediation_guardrail_with_no_candidates_never_invents_a_version(settings):
    orchestrator, _ = make_orchestrator([valid_remediation_output("2.31.0")], settings)
    empty = FakeCandidateSet(preferred_version=None, allowed_versions=[], latest_version=None)
    result = orchestrator.recommend_remediation(make_context(), empty)
    assert result.recommended_version is None
    assert "not an allowed candidate" in result.reasoning
    assert "no safe candidate version is known" in result.reasoning


def test_remediation_accepts_dict_candidates_and_prior_results(settings):
    orchestrator, provider = make_orchestrator([valid_remediation_output("2.31.0")], settings)
    dep, impact, risk = prior_results()
    prior = FindingAIResult(status="COMPLETED", dependency_analysis=dep, impact=impact, risk=risk)
    candidates = {"allowed_versions": ["2.31.0"], "preferred_version": "2.31.0", "notes": ["from OSV"]}
    result = orchestrator.recommend_remediation(make_context(), candidates, prior=prior)
    assert result.recommended_version == "2.31.0"
    prompt = provider.calls[0].prompt
    assert "PREVIOUS STEP: RISK EVALUATION" in prompt and "PREVIOUS STEP: IMPACT ASSESSMENT" in prompt
    assert "- notes:" in prompt and "from OSV" in prompt


def test_remediation_prior_results_as_stored_dict(settings):
    orchestrator, provider = make_orchestrator([valid_remediation_output("2.31.0")], settings)
    stored = {"dependency_analysis": valid_dependency_output(), "impact": valid_impact_output(), "risk": None}
    orchestrator.recommend_remediation(make_context(), FakeCandidateSet(), prior=stored)
    prompt = provider.calls[0].prompt
    assert "PREVIOUS STEP: IMPACT ASSESSMENT" in prompt and "PREVIOUS STEP: RISK EVALUATION" not in prompt


def test_remediation_propagates_llm_error_and_agent_error(settings):
    orchestrator, _ = make_orchestrator([LLMError("Ollama unreachable")], settings)
    with pytest.raises(LLMError):
        orchestrator.recommend_remediation(make_context(), FakeCandidateSet())

    orchestrator, _ = make_orchestrator(["nope", "still nope"], settings)
    with pytest.raises(AgentError) as info:
        orchestrator.recommend_remediation(make_context(), FakeCandidateSet())
    assert info.value.agent == "RemediationAgent" and info.value.raw_output == "still nope"


def test_candidate_view_handles_objects_dicts_and_missing_fields():
    view = candidate_view(FakeCandidateSet(allowed_versions=["1.0.0"], preferred_version="1.0.0"))
    assert view["allowed_versions"] == ["1.0.0"] and view["preferred_version"] == "1.0.0"
    assert view["same_major"] is True
    view = candidate_view({"allowed_versions": None})
    assert view["allowed_versions"] == [] and view["preferred_version"] is None and view["notes"] == []
    view = candidate_view(None)
    assert view["allowed_versions"] == []

    class Minimal:
        allowed_versions = ("3.0.0",)
        preferred_version = "3.0.0"

    view = candidate_view(Minimal())
    assert view["allowed_versions"] == ["3.0.0"] and view["latest_version"] is None


# ------------------------------------------------------------------ available() / BaseAgent


def test_available_delegates_to_provider_health(settings):
    provider = FakeLLMProvider([], healthy=False, health_detail="model 'x' not pulled")
    assert AIOrchestrator(provider, settings).available() == (False, "model 'x' not pulled")

    class Exploding(FakeLLMProvider):
        def health(self):
            raise RuntimeError("boom")

    ok, detail = AIOrchestrator(Exploding([]), settings).available()
    assert ok is False and "boom" in detail


def test_base_agent_wraps_structured_errors_but_not_llm_errors(settings):
    agent = DependencyAnalysisAgent(FakeLLMProvider(["bad", "bad"]), settings)
    with pytest.raises(AgentError) as info:
        agent.run(make_context())
    assert info.value.agent == "DependencyAnalysisAgent"
    assert info.value.raw_output == "bad"
    assert str(info.value).startswith("DependencyAnalysisAgent: ")

    agent = DependencyAnalysisAgent(FakeLLMProvider([LLMError("down")]), settings)
    with pytest.raises(LLMError):
        agent.run(make_context())


def test_agents_expose_names_and_output_models():
    assert DependencyAnalysisAgent.output_model is DependencyAnalysisResult
    assert ImpactAssessmentAgent.output_model is ImpactAssessmentResult
    assert RiskEvaluationAgent.output_model is RiskAssessmentResult
    assert RemediationAgent.output_model is RemediationResult
    assert {a.name for a in (DependencyAnalysisAgent, ImpactAssessmentAgent, RiskEvaluationAgent, RemediationAgent)} == {
        "DependencyAnalysisAgent", "ImpactAssessmentAgent", "RiskEvaluationAgent", "RemediationAgent",
    }


def test_max_retries_comes_from_settings():
    agent = RiskEvaluationAgent(FakeLLMProvider(["bad"] * 4), Settings(llm_max_retries=3))
    with pytest.raises(AgentError) as info:
        agent.run(make_context())
    assert "after 4 attempt(s)" in info.value.error


# ------------------------------------------------------------------ regression: invalid confidence types


@pytest.mark.parametrize("bad_confidence", [None, [0.5], {"value": 0.5}, "high"])
def test_non_numeric_confidence_triggers_correction_round_instead_of_crash(settings, bad_confidence):
    """Field validators raise TypeError/ValueError (not ValidationError) for non-numeric
    confidence values; that must be treated as invalid output and re-prompted."""
    provider = FakeLLMProvider(
        [
            {**valid_dependency_output(), "confidence": bad_confidence},
            valid_dependency_output(),
            valid_impact_output(),
            valid_risk_output(),
        ]
    )
    result = AIOrchestrator(provider, settings).analyze_finding(make_context())
    assert result.status == "COMPLETED"
    assert len(provider.calls) == 4  # one correction round for the dependency agent


def test_unexpected_agent_exception_is_recorded_as_failure(settings):
    provider = FakeLLMProvider([valid_dependency_output(), valid_impact_output(), valid_risk_output()])
    orchestrator = AIOrchestrator(provider, settings)

    def boom(*_args, **_kwargs):
        raise RuntimeError("agent bug")

    orchestrator.impact_agent.run = boom  # type: ignore[method-assign]
    result = orchestrator.analyze_finding(make_context())
    assert result.status == "FAILED"
    assert any("agent bug" in f.error for f in result.failures)
    assert result.risk is not None  # later agents still ran
