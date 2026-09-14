"""REST API tests with the SQLite session and fake providers injected via dependency_overrides."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app.api import deps
from app.core.config import Settings, get_settings
from app.main import app
from app.services.agents.orchestrator import AIOrchestrator
from app.services.analysis.pipeline import AnalysisPipeline
from app.services.analysis.usage import SourceUsageAnalyzer
from app.services.dependencies.service import DependencyService
from app.services.repository.service import RepositoryService
from app.services.vulnerabilities.service import VulnerabilityService
from tests.fixtures.agents.contexts import valid_dependency_output, valid_impact_output, valid_risk_output
from tests.fixtures.api_fakes import FakeGraphService, FakeVulnerabilityProvider, make_demo_repo
from tests.fixtures.llm.fake_provider import FakeLLMProvider


@pytest.fixture
def client(engine, tmp_path: Path):
    settings = Settings(_env_file=None, repository_workspace=str(tmp_path / "ws"), ai_max_findings_per_analysis=5, llm_max_retries=1)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)
    graph = FakeGraphService()
    llm = FakeLLMProvider([valid_dependency_output(), valid_impact_output(components=["src"]), valid_risk_output()] * 3)

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
            orchestrator=AIOrchestrator(llm, settings),
        )

    app.dependency_overrides[deps.get_db] = override_db
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[deps.get_session_maker] = lambda: factory
    app.dependency_overrides[deps.get_pipeline_factory] = lambda: pipeline_factory
    app.dependency_overrides[deps.get_graph_service] = lambda: graph

    def override_repo_service():
        session = factory()
        try:
            yield RepositoryService(session, settings)
        finally:
            session.close()

    app.dependency_overrides[deps.get_repository_service] = override_repo_service
    with TestClient(app) as test_client:
        test_client.demo_path = str(make_demo_repo(tmp_path / "demo"))
        yield test_client
    app.dependency_overrides.clear()


def register(client) -> dict:
    response = client.post("/api/repositories", json={"source_url": client.demo_path, "source_type": "local"})
    assert response.status_code == 201, response.text
    return response.json()


def test_register_local_repository(client):
    body = register(client)
    assert body["name"] == "demo" and body["language"] == "Python" and body["source_type"] == "local"
    assert {c["path"] for c in body["components"]} == {"src", "tests"}
    assert sorted(body["profile"]["dependency_files"]) == ["package.json", "requirements.txt"]
    assert body["latest_analysis"] is None and body["dependencies_count"] == 0


def test_register_invalid_url_is_400(client):
    response = client.post("/api/repositories", json={"source_url": "not a repository"})
    assert response.status_code == 400
    assert response.json()["error"] == "ValidationFailedError"
    assert "github.com" in response.json()["message"]


def test_duplicate_registration_is_409(client):
    register(client)
    response = client.post("/api/repositories", json={"source_url": client.demo_path})
    assert response.status_code == 409 and response.json()["details"]["repository_id"] == 1


def test_not_found_paths(client):
    for path in ("/api/repositories/99", "/api/analyses/99", "/api/dependencies/99", "/api/vulnerabilities/99", "/api/findings/99"):
        response = client.get(path)
        assert response.status_code == 404, path
        assert response.json()["error"] == "NotFoundError"


def test_analyze_runs_in_background_and_produces_findings(client):
    repo = register(client)
    response = client.post(f"/api/repositories/{repo['repository_id']}/analyze", json={"run_ai": True})
    assert response.status_code == 202
    analysis_id = response.json()["analysis_id"]
    # TestClient executes background tasks before returning, so the analysis is done here.
    analysis = client.get(f"/api/analyses/{analysis_id}").json()
    assert analysis["status"] == "COMPLETED", analysis
    assert analysis["stages"]["vulnerabilities"] == "OK" and analysis["stages"]["ai"] == "OK"
    assert analysis["dependencies_count"] == 3 and analysis["findings_count"] == 1

    findings = client.get(f"/api/analyses/{analysis_id}/findings").json()
    assert findings[0]["vulnerability"]["identifier"] == "GHSA-j8r2-6x86-q33q"
    assert findings[0]["dependency"]["package_name"] == "requests"
    assert findings[0]["affected_components"] == ["src"]

    detail = client.get(f"/api/findings/{findings[0]['finding_id']}").json()
    assert detail["ai_status"] == "COMPLETED" and detail["ai_results"]["impact"]["affected_components"] == ["src"]
    assert detail["usage_evidence"]["files"] == ["src/app/client.py"]
    assert detail["repository"]["repository_id"] == repo["repository_id"]

    vulnerable = client.get(f"/api/repositories/{repo['repository_id']}/dependencies?status=VULNERABLE").json()
    assert [d["package_name"] for d in vulnerable] == ["requests"]
    dep = client.get(f"/api/dependencies/{vulnerable[0]['dependency_id']}").json()
    assert dep["vulnerabilities"][0]["identifier"] == "GHSA-j8r2-6x86-q33q" and len(dep["findings"]) == 1
    vuln = client.get(f"/api/vulnerabilities/by-identifier/GHSA-j8r2-6x86-q33q").json()
    assert vuln["cvss_score"] == 6.1 and vuln["affected"][0]["fixed_versions"] == ["2.31.0"]

    repo_detail = client.get(f"/api/repositories/{repo['repository_id']}").json()
    assert repo_detail["latest_analysis"]["status"] == "COMPLETED"
    assert repo_detail["dependencies_count"] == 3 and repo_detail["vulnerable_count"] == 1

    dashboard = client.get("/api/dashboard").json()
    assert dashboard["repositories"] == 1 and dashboard["findings"] == 1 and dashboard["vulnerable_dependencies"] == 1
    assert dashboard["recent_analyses"][0]["analysis_id"] == analysis_id
    assert "MEDIUM" in dashboard["findings_by_risk"] or "HIGH" in dashboard["findings_by_risk"] or "CRITICAL" in dashboard["findings_by_risk"]


def test_second_analyze_while_running_is_409(client, engine):
    repo = register(client)
    from app.models import Analysis
    from sqlalchemy.orm import Session

    with Session(engine) as session:
        session.add(Analysis(repository_id=repo["repository_id"], status="RUNNING"))
        session.commit()
    response = client.post(f"/api/repositories/{repo['repository_id']}/analyze", json={})
    assert response.status_code == 409


def test_finding_analyze_endpoint_reruns_ai(client):
    repo = register(client)
    analysis_id = client.post(f"/api/repositories/{repo['repository_id']}/analyze", json={"run_ai": False}).json()["analysis_id"]
    finding = client.get(f"/api/analyses/{analysis_id}/findings").json()[0]
    assert finding["ai_status"] == "SKIPPED"
    response = client.post(f"/api/findings/{finding['finding_id']}/analyze")
    assert response.status_code == 200
    assert response.json()["ai_status"] == "COMPLETED"


def test_delete_repository_removes_everything(client):
    repo = register(client)
    client.post(f"/api/repositories/{repo['repository_id']}/analyze", json={"run_ai": False})
    assert client.delete(f"/api/repositories/{repo['repository_id']}").status_code == 204
    assert client.get(f"/api/repositories/{repo['repository_id']}").status_code == 404
    assert client.get("/api/dashboard").json()["repositories"] == 0
