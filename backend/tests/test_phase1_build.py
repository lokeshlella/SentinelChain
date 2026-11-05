"""Phase-1 build (SENTINEL_PHASE=1): only the deterministic analysis is exposed.

Sentinel Chain is reviewed in two phases. A Phase-1 build must run an analysis end to end without
an AI stage, answer 404 for every Phase-2 route (even for rows that exist), and never call Ollama,
Docker or GitHub — while the default build keeps every feature.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app.api import deps
from app.core.config import Settings, get_settings
from app.core.features import ALL_FEATURES, PHASE_1_FEATURES, PHASE_2_FEATURES, current_phase, describe, enabled_features
from app.main import app
from app.services.agents.orchestrator import AIOrchestrator
from app.services.analysis.pipeline import AnalysisPipeline
from app.services.analysis.usage import SourceUsageAnalyzer
from app.services.dependencies.service import DependencyService
from app.services.repository.service import RepositoryService
from app.services.vulnerabilities.service import VulnerabilityService
from tests.fixtures.api_fakes import FakeGraphService, FakeVulnerabilityProvider, make_demo_repo
from tests.fixtures.llm.fake_provider import FakeLLMProvider

PHASE_1_STAGES = ["repository", "dependencies", "vulnerabilities", "usage", "knowledge_graph"]

# Every route of a Phase-2 feature, as the dashboard would call it.
PHASE_2_ROUTES = [
    ("post", "/api/findings/1/analyze"),
    ("post", "/api/findings/1/remediate"),
    ("get", "/api/findings/1/report"),
    ("get", "/api/remediations/1"),
    ("get", "/api/remediations/1/validations"),
    ("post", "/api/remediations/1/validate"),
    ("get", "/api/remediations/1/report"),
    ("post", "/api/remediations/1/pull-request"),
    ("get", "/api/validations/1"),
    ("get", "/api/validations/1/logs"),
    ("get", "/api/pull-requests"),
    ("get", "/api/pull-requests/1"),
]


def settings_for(tmp_path: Path, **overrides) -> Settings:
    return Settings(_env_file=None, repository_workspace=str(tmp_path / "ws"), **overrides)


# ----------------------------------------------------------------- which features a build has


def test_default_build_is_the_complete_product(tmp_path):
    settings = settings_for(tmp_path)
    assert current_phase(settings) == 2
    assert enabled_features(settings) == {name: True for name in ALL_FEATURES}


def test_phase_1_build_keeps_only_the_deterministic_analysis(tmp_path):
    features = enabled_features(settings_for(tmp_path, sentinel_phase=1))
    assert [name for name, on in features.items() if on] == list(PHASE_1_FEATURES)
    assert not any(features[name] for name in PHASE_2_FEATURES)


def test_extra_features_come_with_their_prerequisites(tmp_path):
    ai_only = enabled_features(settings_for(tmp_path, sentinel_phase=1, sentinel_features="ai"))
    assert ai_only["ai"] and not ai_only["remediation"] and not ai_only["pull_requests"]
    prs = enabled_features(settings_for(tmp_path, sentinel_phase=1, sentinel_features=" Pull_Requests "))
    assert prs["pull_requests"] and prs["validation"] and prs["remediation"]
    assert not prs["ai"] and not prs["reports"]


def test_unknown_or_out_of_range_values_never_break_startup(tmp_path):
    settings = settings_for(tmp_path, sentinel_phase=1, sentinel_features="ai,graphs,,")
    assert enabled_features(settings)["ai"]
    assert "ignored unknown SENTINEL_FEATURES: graphs" in describe(settings)
    assert current_phase(settings_for(tmp_path, sentinel_phase=0)) == 1
    assert current_phase(settings_for(tmp_path, sentinel_phase=7)) == 2
    assert all(enabled_features(settings_for(tmp_path, sentinel_features="nonsense")).values())


def test_features_endpoint_defaults_to_the_complete_product():
    body = TestClient(app).get("/api/features").json()
    assert body == {"phase": 2, "features": {name: True for name in ALL_FEATURES}}


# ----------------------------------------------------------------- a Phase-1 build over the API


@pytest.fixture
def phase1(engine, tmp_path: Path):
    settings = settings_for(tmp_path, sentinel_phase=1, ai_max_findings_per_analysis=5, llm_max_retries=1)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)
    graph = FakeGraphService()
    llm = FakeLLMProvider([])  # any call fails loudly: a Phase-1 build must never reach the model

    def override_db():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    def pipeline_factory(db) -> AnalysisPipeline:
        return AnalysisPipeline(
            db,
            settings,
            repository_service=RepositoryService(db, settings),
            dependency_service=DependencyService(),
            vulnerability_service=VulnerabilityService(db, provider=FakeVulnerabilityProvider(), settings=settings),
            graph_service=graph,
            usage_analyzer=SourceUsageAnalyzer(),
            orchestrator=AIOrchestrator(llm, settings),  # handed over, and still never used
        )

    def override_repo_service():
        session = factory()
        try:
            yield RepositoryService(session, settings)
        finally:
            session.close()

    app.dependency_overrides[deps.get_db] = override_db
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[deps.get_session_maker] = lambda: factory
    app.dependency_overrides[deps.get_pipeline_factory] = lambda: pipeline_factory
    app.dependency_overrides[deps.get_graph_service] = lambda: graph
    app.dependency_overrides[deps.get_repository_service] = override_repo_service
    app.dependency_overrides[deps.get_repository_service_factory] = lambda: (lambda db: RepositoryService(db, settings))
    with TestClient(app) as client:
        client.demo_path = str(make_demo_repo(tmp_path / "demo"))
        client.llm = llm
        client.graph = graph
        yield client
    app.dependency_overrides.clear()


def analyse(client) -> dict:
    """Register the demo repository and run one analysis (TestClient runs the background jobs)."""
    repo = client.post("/api/repositories", json={"source_url": client.demo_path, "source_type": "local"})
    assert repo.status_code == 202, repo.text
    started = client.post(f"/api/repositories/{repo.json()['repository_id']}/analyze", json={"run_ai": True})
    assert started.status_code == 202, started.text
    return client.get(f"/api/analyses/{started.json()['analysis_id']}").json()


def test_phase_1_analysis_completes_without_an_ai_stage(phase1):
    analysis = analyse(phase1)  # run_ai=True is requested and must simply not apply
    assert analysis["status"] == "COMPLETED" and analysis["error_message"] is None
    assert list(analysis["stages"]) == PHASE_1_STAGES
    assert set(analysis["stages"].values()) == {"OK"}
    assert "ai" not in analysis["summary"]
    assert phase1.graph.synced, "the knowledge graph is part of Phase 1"

    findings = phase1.get(f"/api/analyses/{analysis['analysis_id']}/findings").json()
    assert findings, "the demo repository has a vulnerable dependency"
    # Risk stays the severity-derived value; nothing claims an AI result, and nothing waits for one
    # (PENDING would read as "agents running" once a build with the AI feature shows these findings).
    assert all(f["ai_status"] == "SKIPPED" and f["impact_level"] is None for f in findings)
    assert all(f["risk_level"] == f["vulnerability"]["severity"] for f in findings)
    assert phase1.llm.calls == []


def test_phase_2_routes_answer_404_even_for_rows_that_exist(phase1):
    analysis = analyse(phase1)
    finding_id = phase1.get(f"/api/analyses/{analysis['analysis_id']}/findings").json()[0]["finding_id"]
    for method, path in PHASE_2_ROUTES:
        response = getattr(phase1, method)(path.replace("/findings/1/", f"/findings/{finding_id}/"))
        assert response.status_code == 404, path
        assert response.json()["error"] == "FeatureNotEnabledError", path
        assert response.json()["details"]["phase"] == 1, path
    finding = phase1.get(f"/api/findings/{finding_id}").json()
    assert finding["ai_status"] == "SKIPPED" and finding["remediations"] == []
    assert phase1.llm.calls == []


def test_phase_1_build_keeps_every_phase_1_route(phase1):
    analysis = analyse(phase1)
    repository_id = analysis["repository_id"]
    finding = phase1.get(f"/api/analyses/{analysis['analysis_id']}/findings").json()[0]
    for path in (
        "/api/dashboard",
        "/api/repositories",
        f"/api/repositories/{repository_id}",
        f"/api/repositories/{repository_id}/dependencies",
        f"/api/repositories/{repository_id}/findings",
        f"/api/repositories/{repository_id}/graph",
        f"/api/analyses/{analysis['analysis_id']}",
        f"/api/findings/{finding['finding_id']}",
        f"/api/dependencies/{finding['dependency']['dependency_id']}",
        f"/api/vulnerabilities/{finding['vulnerability']['vulnerability_id']}",
    ):
        assert phase1.get(path).status_code == 200, path


def test_phase_1_health_checks_only_the_services_it_uses(phase1):
    with (
        patch("app.api.routes.health.check_database", return_value=(True, "pg")),
        patch("app.api.routes.health.check_neo4j", return_value=(True, "neo4j")),
        patch("app.api.routes.health._check_osv", return_value=(True, "osv")),
        patch("app.api.routes.health._check_ollama") as ollama,
        patch("app.api.routes.health._check_docker") as docker,
        patch("app.api.routes.health._check_github") as github,
    ):
        body = phase1.get("/api/health").json()
    assert [s["name"] for s in body["services"]] == ["postgresql", "neo4j", "osv"]
    assert body["status"] == "ok"
    ollama.assert_not_called()
    docker.assert_not_called()
    github.assert_not_called()


def test_features_endpoint_reports_a_phase_1_build(phase1):
    body = phase1.get("/api/features").json()
    assert body == {"phase": 1, "features": {name: True for name in PHASE_1_FEATURES}}  # disabled ones are not named
