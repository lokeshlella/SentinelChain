"""Full workflow through the REST API with fake providers: analyze → remediate → validate → report → PR."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app.api import deps
from app.core.config import Settings, get_settings
from app.main import app
from app.models.enums import PullRequestStatus
from app.services.agents.orchestrator import AIOrchestrator
from app.services.analysis.pipeline import AnalysisPipeline
from app.services.analysis.usage import SourceUsageAnalyzer
from app.services.dependencies.service import DependencyService
from app.services.github.base import PullRequestResult
from app.services.github.service import PullRequestService
from app.services.remediation.service import RemediationService
from app.services.reports.service import ReportService
from app.services.repository.service import RepositoryService
from app.services.sandbox.service import ValidationService
from app.services.vulnerabilities.service import VulnerabilityService
from tests.fixtures.agents.contexts import valid_dependency_output, valid_impact_output, valid_remediation_output, valid_risk_output
from tests.fixtures.api_fakes import FakeGraphService, FakeVulnerabilityProvider, make_demo_repo
from tests.fixtures.llm.fake_provider import FakeLLMProvider
from tests.test_remediation_modules import FakeChecker, FakeRegistry
from tests.test_sandbox_modules import FakeSandbox, FakeScanner


class FakeGitProvider:
    def __init__(self, configured=True):
        self.configured = configured

    def is_configured(self):
        return self.configured

    def create_pull_request(self, spec):
        return PullRequestResult(status=PullRequestStatus.DRAFT, branch=spec.head_branch, url="https://github.com/example/demo/pull/1", number=1)


@pytest.fixture
def client(engine, tmp_path: Path):
    settings = Settings(_env_file=None, repository_workspace=str(tmp_path / "ws"), llm_max_retries=1)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)
    graph = FakeGraphService()
    llm = FakeLLMProvider([valid_dependency_output(), valid_impact_output(components=["src"]), valid_risk_output(), valid_remediation_output("2.31.0")])
    checker = FakeChecker({"GHSA-j8r2-6x86-q33q": "2.31.0"})

    def override_db():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    def override_repo_service():
        session = factory()
        try:
            yield RepositoryService(session, settings)
        finally:
            session.close()

    pipeline_factory = lambda db: AnalysisPipeline(  # noqa: E731
        db, settings, repository_service=RepositoryService(db, settings), dependency_service=DependencyService(),
        vulnerability_service=VulnerabilityService(db, provider=FakeVulnerabilityProvider(), settings=settings),
        graph_service=graph, usage_analyzer=SourceUsageAnalyzer(), orchestrator=AIOrchestrator(llm, settings),
    )
    remediation_factory = lambda db: RemediationService(  # noqa: E731
        db, settings, orchestrator=AIOrchestrator(llm, settings), registry=FakeRegistry(["2.25.1", "2.31.0", "2.32.4"]), vulnerability_service=checker, graph_service=graph,
    )
    validation_factory = lambda db: ValidationService(db, settings, sandbox=FakeSandbox(), scanner=FakeScanner())  # noqa: E731
    pr_factory = lambda db: PullRequestService(db, settings, provider=FakeGitProvider(), report_service=ReportService(db))  # noqa: E731

    app.dependency_overrides.update({
        deps.get_db: override_db,
        get_settings: lambda: settings,
        deps.get_session_maker: lambda: factory,
        deps.get_pipeline_factory: lambda: pipeline_factory,
        deps.get_graph_service: lambda: graph,
        deps.get_repository_service: override_repo_service,
        deps.get_repository_service_factory: lambda: (lambda db: RepositoryService(db, settings)),
        deps.get_remediation_factory: lambda: remediation_factory,
        deps.get_validation_factory: lambda: validation_factory,
        deps.get_pull_request_factory: lambda: pr_factory,
        deps.get_report_factory: lambda: ReportService,
    })
    with TestClient(app) as test_client:
        test_client.demo_path = str(make_demo_repo(tmp_path / "demo"))
        yield test_client
    app.dependency_overrides.clear()


def test_end_to_end_workflow_via_api(client):
    repo = client.post("/api/repositories", json={"source_url": client.demo_path}).json()
    analysis = client.post(f"/api/repositories/{repo['repository_id']}/analyze", json={"run_ai": True}).json()
    finding = client.get(f"/api/analyses/{analysis['analysis_id']}/findings").json()[0]
    fid = finding["finding_id"]

    # remediation
    response = client.post(f"/api/findings/{fid}/remediate")
    assert response.status_code == 202, response.text
    assert response.json()["status"] == "PENDING"  # the LLM/registry work runs in the background
    remediation = client.get(f"/api/remediations/{response.json()['remediation_id']}").json()
    assert remediation["status"] == "PROPOSED" and remediation["recommended_version"] == "2.31.0"
    assert remediation["proposed_change"]["file"] == "requirements.txt" and "+requests==2.31.0" in remediation["proposed_change"]["diff"]
    assert remediation["candidates"]["preferred_version"] == "2.31.0"
    rid = remediation["remediation_id"]
    assert client.get(f"/api/remediations/{rid}").json()["finding"]["finding_id"] == fid

    # validation (background task runs inside TestClient)
    response = client.post(f"/api/remediations/{rid}/validate")
    assert response.status_code == 202
    vid = response.json()["validation_id"]
    validation = client.get(f"/api/validations/{vid}").json()
    assert validation["status"] == "COMPLETED" and validation["overall_result"] == "PASS"
    assert "### step build" in validation["logs"] and "### step build" in client.get(f"/api/validations/{vid}/logs").text
    assert client.get(f"/api/remediations/{rid}/validations").json()[0]["validation_id"] == vid
    assert client.get(f"/api/remediations/{rid}").json()["status"] == "VALIDATED"

    # evidence report
    report = client.get(f"/api/findings/{fid}/report").json()
    assert [s["title"] for s in report["sections"]][-1] == "Final Recommendation"
    assert report["final_recommendation"]["decision"] == "Apply"
    markdown = client.get(f"/api/remediations/{rid}/report?format=markdown")
    assert markdown.headers["content-type"].startswith("text/markdown") and "## 9. Validation" in markdown.text

    # pull request
    response = client.post(f"/api/remediations/{rid}/pull-request", json={})
    assert response.status_code == 201, response.text
    pr = response.json()
    assert pr["review_status"] == "DRAFT" and pr["pr_url"].endswith("/pull/1")
    assert "GHSA-j8r2-6x86-q33q" in pr["body"] and pr["evidence"]["remediation_id"] == rid
    assert client.get(f"/api/pull-requests/{pr['pr_id']}").json()["title"].startswith("Sentinel Chain: bump requests")
    assert client.get("/api/pull-requests").json()[0]["pr_id"] == pr["pr_id"]
    assert client.get(f"/api/remediations/{rid}").json()["status"] == "PR_CREATED"

    dashboard = client.get("/api/dashboard").json()
    assert dashboard["remediations"] == 1 and dashboard["validations"] == 1 and dashboard["pull_requests"] == 1


def test_pull_request_requires_validation(client):
    repo = client.post("/api/repositories", json={"source_url": client.demo_path}).json()
    analysis = client.post(f"/api/repositories/{repo['repository_id']}/analyze", json={"run_ai": False}).json()
    fid = client.get(f"/api/analyses/{analysis['analysis_id']}/findings").json()[0]["finding_id"]
    rid = client.post(f"/api/findings/{fid}/remediate").json()["remediation_id"]
    assert client.get(f"/api/remediations/{rid}").json()["status"] == "PROPOSED"
    response = client.post(f"/api/remediations/{rid}/pull-request")
    assert response.status_code == 400 and "validate" in response.json()["message"]
    assert client.get("/api/remediations/999").status_code == 404
    assert client.get("/api/validations/999").status_code == 404
    assert client.get("/api/pull-requests/999").status_code == 404
