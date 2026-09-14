"""Integration tests against a real local Ollama (SENTINEL_INTEGRATION=1 to run)."""

from __future__ import annotations

import pytest

from app.core.config import get_settings
from app.services.agents.orchestrator import AIOrchestrator
from app.services.agents.schemas import DependencyAnalysisResult
from app.services.llm.factory import get_default_provider
from app.services.llm.structured import generate_structured, strict_schema
from tests.fixtures.agents.contexts import make_context

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def provider():
    provider = get_default_provider(get_settings())
    ok, detail = provider.health()
    if not ok:
        pytest.skip(f"Ollama not usable: {detail}")
    return provider


def test_real_ollama_returns_schema_conforming_json(provider):
    result = generate_structured(
        provider,
        "The package 'requests' is imported in src/app/services/weather.py line 3. Summarise its use as JSON "
        "with keys summary, usage_evidence (list of FACT strings) and confidence (0-1).",
        "Return only JSON.",
        DependencyAnalysisResult,
        max_retries=1,
        json_schema=strict_schema(DependencyAnalysisResult),
    )
    assert result.summary
    assert 0 <= result.confidence <= 1


def test_real_orchestrator_completes_and_respects_component_evidence(provider):
    orchestrator = AIOrchestrator(provider, get_settings())
    result = orchestrator.analyze_finding(make_context())
    assert result.status == "COMPLETED", result.failures
    assert set(result.impact.affected_components) <= {"src/app", "tests"}
    assert result.model == provider.model_name


def test_real_remediation_only_recommends_allowed_versions(provider):
    orchestrator = AIOrchestrator(provider, get_settings())
    candidates = {"allowed_versions": ["2.31.0", "2.32.4"], "preferred_version": "2.31.0", "latest_version": "2.32.4"}
    result = orchestrator.recommend_remediation(make_context(), candidates)
    assert result.recommended_version in {"2.31.0", "2.32.4"}
