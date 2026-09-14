"""Regression tests for the LOW findings of AUDIT_V1.md (F-11 … F-19), one section each."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.exceptions import ConflictError
from app.models import Repository
from app.models.enums import CheckResult, PullRequestStatus, RemediationStatus

ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------- F-11: no security PASS when the sandbox never ran


def test_f11_security_scan_is_unknown_when_sandbox_could_not_start(db, tmp_path):
    from app.models import Analysis, Dependency, Finding, Remediation, Vulnerability
    from app.services.sandbox.service import ValidationService
    from tests.test_sandbox_modules import FakeSandbox, FakeScanner, python_workspace, settings

    ws = python_workspace(tmp_path)
    repo = Repository(name="demo", source_url=str(ws), source_type="local", local_path=str(ws), profile={"hints": {"has_pytest": True}})
    db.add(repo)
    db.flush()
    analysis = Analysis(repository_id=repo.repository_id, status="COMPLETED")
    db.add(analysis)
    db.flush()
    dep = Dependency(repository_id=repo.repository_id, analysis_id=analysis.analysis_id, package_name="requests", version="2.30.0", ecosystem="PyPI", direct_or_transitive="unknown", source_file="requirements.txt", vulnerability_status="VULNERABLE")
    vuln = Vulnerability(identifier="GHSA-j8r2-6x86-q33q", source="osv", severity="MEDIUM")
    db.add_all([dep, vuln])
    db.flush()
    finding = Finding(analysis_id=analysis.analysis_id, dependency_id=dep.dependency_id, vulnerability_id=vuln.vulnerability_id, ai_status="SKIPPED")
    db.add(finding)
    db.flush()
    rem = Remediation(finding_id=finding.finding_id, current_version="2.30.0", recommended_version="2.33.0", status=RemediationStatus.PROPOSED,
                      proposed_change={"file": "requirements.txt", "workspace_path": str(ws), "diff": "x"})
    db.add(rem)
    db.commit()
    scanner = FakeScanner("PASS")  # would say PASS if asked — it must not be asked
    validation = ValidationService(db, settings(tmp_path), sandbox=FakeSandbox(error="Docker daemon unreachable"), scanner=scanner).validate(rem.remediation_id)
    assert validation.build_status == "UNKNOWN" and validation.test_status == "UNKNOWN"
    assert validation.security_scan_status == "UNKNOWN"
    assert validation.overall_result == "UNKNOWN"
    assert any("sandbox could not be started" in n for n in validation.details["security_scan"]["notes"])


# ---------------------------------------------------------------- F-12: never a non-draft pull request


def test_f12_draft_unsupported_fails_instead_of_opening_a_regular_pr(tmp_path):
    import git
    from github import GithubException

    from app.services.github.base import PullRequestSpec
    from app.services.github.github_provider import GitHubProvider, run_git

    ws = tmp_path / "ws"
    git.Repo.init(ws, initial_branch="main")
    (ws / "requirements.txt").write_text("requests==2.30.0\n")
    repo = git.Repo(ws)
    repo.index.add(["requirements.txt"])
    repo.index.commit("init", author=git.Actor("d", "d@x"), committer=git.Actor("d", "d@x"))
    repo.create_remote("origin", "https://github.com/example/demo.git")
    (ws / "requirements.txt").write_text("requests==2.33.0\n")

    class GhRepo:
        def __init__(self):
            self.calls = []

        def get_pulls(self, **kwargs):
            return []

        def create_pull(self, **kwargs):
            self.calls.append(kwargs)
            raise GithubException(422, {"message": "Draft pull requests are not supported in this repository."}, None)

    gh = GhRepo()

    class Gh:
        def get_repo(self, name):
            return gh

    def runner(args, *, cwd, env=None, timeout=None):
        if "push" in args or "ls-remote" in args:
            return ""
        return run_git(args, cwd=cwd, env=env, timeout=timeout)

    result = GitHubProvider("ghp_x", github_client=Gh(), git_runner=runner).create_pull_request(
        PullRequestSpec(workspace_path=ws, base_branch="main", head_branch="sentinel-chain/x", title="t", body="b", commit_message="c", changed_files=["requirements.txt"], repo_full_name="example/demo")
    )
    assert result.status == PullRequestStatus.FAILED
    assert "never opens non-draft" in (result.error or "")
    assert len(gh.calls) == 1 and gh.calls[0]["draft"] is True  # no second, non-draft attempt


# ---------------------------------------------------------------- F-13: HTTP status follows the outcome


@pytest.mark.parametrize("outcome,expected", [(PullRequestStatus.DRAFT, 201), (PullRequestStatus.UNAVAILABLE, 200), (PullRequestStatus.FAILED, 502)])
def test_f13_pull_request_status_code_reflects_the_outcome(engine, tmp_path, outcome, expected):
    from sqlalchemy.orm import sessionmaker

    from app.api import deps
    from app.main import app
    from app.models import PullRequest

    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)

    class FakePrService:
        def __init__(self, db):
            self.db = db

        def create(self, remediation_id, *, force=False):
            pr = PullRequest(remediation_id=remediation_id, title="t", review_status=outcome, error_message="boom" if outcome == PullRequestStatus.FAILED else None)
            # a real row needs a remediation; satisfy the FK chain minimally
            from app.models import Analysis, Dependency, Finding, Remediation, Vulnerability

            repo = Repository(name="r", source_url=f"/tmp/{outcome}", source_type="local")
            self.db.add(repo)
            self.db.flush()
            analysis = Analysis(repository_id=repo.repository_id, status="COMPLETED")
            self.db.add(analysis)
            self.db.flush()
            dep = Dependency(repository_id=repo.repository_id, analysis_id=analysis.analysis_id, package_name="p", version="1", ecosystem="PyPI", direct_or_transitive="unknown", source_file="requirements.txt", vulnerability_status="VULNERABLE")
            vuln = Vulnerability(identifier=f"GHSA-{outcome}", source="osv", severity="LOW")
            self.db.add_all([dep, vuln])
            self.db.flush()
            finding = Finding(analysis_id=analysis.analysis_id, dependency_id=dep.dependency_id, vulnerability_id=vuln.vulnerability_id, ai_status="SKIPPED")
            self.db.add(finding)
            self.db.flush()
            rem = Remediation(finding_id=finding.finding_id, status=RemediationStatus.VALIDATED)
            self.db.add(rem)
            self.db.flush()
            pr.remediation_id = rem.remediation_id
            self.db.add(pr)
            self.db.commit()
            return pr

    def override_db():
        session = factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[deps.get_db] = override_db
    app.dependency_overrides[deps.get_pull_request_factory] = lambda: FakePrService
    try:
        with TestClient(app) as client:
            response = client.post("/api/remediations/1/pull-request", json={})
            assert response.status_code == expected, response.text
            assert response.json()["review_status"] == outcome and "pr_id" in response.json()
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------- F-14: database-level uniqueness


def test_f14_duplicate_source_is_rejected_by_the_database_and_mapped_to_conflict(db, tmp_path):
    from sqlalchemy.exc import IntegrityError

    db.add(Repository(name="a", source_url="https://github.com/Owner/Repo", source_type="github", branch="main"))
    db.commit()
    db.add(Repository(name="b", source_url="https://github.com/owner/repo", source_type="github", branch="main"))  # case-insensitive
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()
    db.add(Repository(name="c", source_url="https://github.com/owner/repo", source_type="github", branch="dev"))  # other branch is fine
    db.commit()
    db.add(Repository(name="d", source_url="/tmp/local-x", source_type="local"))
    db.commit()
    db.add(Repository(name="e", source_url="/tmp/local-x", source_type="local"))  # NULL branch counts as ''
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()

    # the service turns the race into a ConflictError instead of a 500
    from app.services.repository.service import RepositoryService

    project = tmp_path / "proj"
    project.mkdir()
    (project / "requirements.txt").write_text("requests==2.30.0\n")
    service = RepositoryService(db, Settings(_env_file=None, repository_workspace=str(tmp_path / "ws")))
    with patch.object(service, "_ensure_not_registered", return_value=None):  # bypass the code-side check → DB must catch it
        service.register(str(project), ingest=False)
        with pytest.raises(ConflictError):
            service.register(str(project), ingest=False)


# ---------------------------------------------------------------- F-15: confidence must be a fraction


@pytest.mark.parametrize("value", [1.7, 90, -0.1, "150"])
def test_f15_out_of_range_confidence_is_rejected_not_clamped(value):
    from pydantic import ValidationError

    from app.services.agents.schemas import RiskAssessmentResult

    with pytest.raises(ValidationError) as exc:
        RiskAssessmentResult(risk_level="HIGH", reasoning="r", confidence=value)
    assert "between 0 and 1" in str(exc.value)
    assert RiskAssessmentResult(risk_level="HIGH", reasoning="r", confidence=0.9).confidence == 0.9


# ---------------------------------------------------------------- F-16: token validity in /health


def test_f16_health_verifies_the_github_token(monkeypatch):
    from app.api.routes import health

    monkeypatch.setattr(health, "get_settings", lambda: Settings(_env_file=None, github_token="ghp_test"))
    for status_code, body, expected_ok, fragment in [
        (200, {"login": "octocat"}, True, "valid for GitHub user 'octocat'"),
        (401, {"message": "Bad credentials"}, False, "rejected by GitHub"),
    ]:
        with patch.object(health.httpx, "get", return_value=httpx.Response(status_code, json=body, request=httpx.Request("GET", "https://api.github.com/user"))):
            ok, detail = health._check_github()
        assert ok is expected_ok and fragment in detail
    with patch.object(health.httpx, "get", side_effect=httpx.ConnectError("offline")):
        ok, detail = health._check_github()
    assert ok is True and "not reachable to verify" in detail


# ---------------------------------------------------------------- F-17: optional API key


def test_f17_api_key_guard_protects_api_routes_but_not_health(monkeypatch):
    from app import main

    monkeypatch.setattr(main.settings, "api_key", "s3cret")
    with TestClient(main.app) as client:
        with patch("app.api.routes.health.check_database", return_value=(True, "pg")), \
             patch("app.api.routes.health.check_neo4j", return_value=(True, "ok")), \
             patch("app.api.routes.health._check_ollama", return_value=(True, "ok")), \
             patch("app.api.routes.health._check_docker", return_value=(True, "ok")), \
             patch("app.api.routes.health._check_github", return_value=(False, "no token")):
            assert client.get("/api/health").status_code == 200  # health stays open
        denied = client.get("/api/repositories")
        assert denied.status_code == 401 and denied.json()["error"] == "Unauthorized"
        assert client.get("/api/repositories", headers={"X-API-Key": "wrong"}).status_code == 401
        # a correct key gets through the guard (the request then hits the real DB dependency → not 401)
        assert client.get("/api/repositories", headers={"X-API-Key": "s3cret"}).status_code != 401
        assert client.get("/api/repositories?api_key=s3cret").status_code != 401


def test_f17_cors_does_not_allow_credentials():
    from app import main

    cors = next(m for m in main.app.user_middleware if m.cls.__name__ == "CORSMiddleware")
    assert cors.kwargs["allow_credentials"] is False


# ---------------------------------------------------------------- F-18: compose healthchecks


def test_f18_compose_defines_healthchecks_and_ordered_startup():
    compose = (ROOT / "docker-compose.yml").read_text()
    backend = compose.split("  backend:", 1)[1].split("  frontend:", 1)[0]
    frontend = compose.split("  frontend:", 1)[1].split("volumes:", 1)[0]
    assert "healthcheck:" in backend and "/api/health/live" in backend
    assert "healthcheck:" in frontend and "condition: service_healthy" in frontend


# ---------------------------------------------------------------- F-19 is covered in tests/test_pipeline.py::test_ai_limit_skips_remaining_findings_and_on_demand_run_fills_them
