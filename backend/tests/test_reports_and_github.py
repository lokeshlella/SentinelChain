"""Evidence report generation and pull-request creation (fake git provider / real temp git repo)."""

from __future__ import annotations

import logging
from pathlib import Path

import git
import pytest

from app.core.config import Settings
from app.core.exceptions import ConflictError, ValidationFailedError
from app.models import Analysis, Dependency, Finding, PullRequest, Remediation, Repository, Validation, Vulnerability
from app.models.enums import CheckResult, PullRequestStatus, RemediationStatus, ValidationStatus
from app.services.github.base import PullRequestResult, PullRequestSpec
from app.services.github.github_provider import GitHubProvider
from app.services.github.service import PullRequestService, build_branch_name, build_pr_title
from app.services.reports.service import EvidenceReport, ReportService

SECTION_TITLES = ["Repository", "Analysis", "Dependency", "Vulnerability", "Evidence", "Application Impact",
                  "Risk Assessment", "Recommended Remediation", "Validation", "Final Recommendation"]


@pytest.fixture
def graph(db, tmp_path):
    """Repository → Analysis → Dependency/Vulnerability → Finding (+ optional remediation/validation)."""
    ws = tmp_path / "repo"
    ws.mkdir()
    (ws / "requirements.txt").write_text("requests==2.33.0\n")
    repo = Repository(name="demo-project", source_url="https://github.com/example/demo-project", source_type="github", branch="main",
                      language="Python", local_path=str(ws), commit_sha="abc123", profile={"dependency_files": ["requirements.txt"], "hints": {}})
    db.add(repo)
    db.flush()
    analysis = Analysis(repository_id=repo.repository_id, status="COMPLETED", overall_risk="MEDIUM", stages={"ai": "OK"}, summary={"findings": 1})
    db.add(analysis)
    db.flush()
    dep = Dependency(repository_id=repo.repository_id, analysis_id=analysis.analysis_id, package_name="requests", version="2.30.0", ecosystem="PyPI",
                     direct_or_transitive="unknown", source_file="requirements.txt", vulnerability_status="VULNERABLE")
    vuln = Vulnerability(identifier="GHSA-j8r2-6x86-q33q", source="osv", aliases=["CVE-2023-32681"], severity="MEDIUM", cvss_score=6.1,
                         summary="Proxy-Authorization leak", affected=[{"ecosystem": "PyPI", "package_name": "requests", "ranges": [], "versions": [], "fixed_versions": ["2.31.0"]}])
    db.add_all([dep, vuln])
    db.flush()
    finding = Finding(
        analysis_id=analysis.analysis_id, dependency_id=dep.dependency_id, vulnerability_id=vuln.vulnerability_id,
        impact_level="MEDIUM", risk_level="MEDIUM", affected_components=["src"], ai_status="COMPLETED",
        usage_evidence={"package_name": "requests", "ecosystem": "PyPI", "import_names": ["requests"], "files": ["src/app.py"], "components": ["src"],
                        "references": [{"file": "src/app.py", "line": 3, "snippet": "import requests", "kind": "import"}], "truncated": False, "scanned_files": 4},
        ai_results={"status": "COMPLETED", "model": "llama3.2:3b", "impact": {"impact_level": "MEDIUM", "affected_components": ["src"], "facts": ["FACT: src/app.py line 3 imports requests"],
                    "inferences": ["INFERENCE: HTTP calls may leak proxy credentials"], "reasoning": "used for outbound HTTP", "confidence": 0.8},
                    "risk": {"risk_level": "MEDIUM", "factors": ["network exposure"], "reasoning": "medium", "confidence": 0.7}, "failures": [], "dropped_components": []},
        reasoning="Impact (MEDIUM): used for outbound HTTP",
    )
    db.add(finding)
    db.commit()
    return {"repo": repo, "analysis": analysis, "finding": finding, "workspace": ws}


def add_remediation(db, graph, tmp_path, *, validated=True, overall="PASS", tests="PASS"):
    ws = tmp_path / "remediation-ws"
    if not ws.exists():
        git.Repo.init(ws, initial_branch="main")
        (ws / "requirements.txt").write_text("requests==2.30.0\n")
        r = git.Repo(ws)
        r.index.add(["requirements.txt"])
        r.index.commit("initial", author=git.Actor("dev", "dev@example.com"), committer=git.Actor("dev", "dev@example.com"))
        r.create_remote("origin", "https://github.com/example/demo-project.git")
        (ws / "requirements.txt").write_text("requests==2.33.0\n")
    rem = Remediation(finding_id=graph["finding"].finding_id, current_version="2.30.0", recommended_version="2.33.0", confidence_score=0.9,
                      recommendation="upgrade", status=RemediationStatus.VALIDATED if validated else RemediationStatus.PROPOSED,
                      proposed_change={"file": "requirements.txt", "workspace_path": str(ws), "diff": "--- a/requirements.txt\n+++ b/requirements.txt\n-requests==2.30.0\n+requests==2.33.0", "line_number": 1})
    db.add(rem)
    db.flush()
    if validated:
        db.add(Validation(remediation_id=rem.remediation_id, status=ValidationStatus.COMPLETED, build_status="PASS", test_status=tests,
                          security_scan_status="PASS", overall_result=overall, details={"steps": [], "warnings": []}))
    db.commit()
    return rem


# ---------------------------------------------------------------- reports


def test_report_has_ten_sections_and_separates_facts_from_reasoning(db, graph, tmp_path):
    add_remediation(db, graph, tmp_path)
    report = ReportService(db).build(graph["finding"].finding_id)
    assert [s.title for s in report.sections] == SECTION_TITLES
    assert [s.number for s in report.sections] == list(range(1, 11))
    evidence = report.section("Evidence")
    assert "src/app.py" in str(evidence.observed_facts) and evidence.ai_reasoning is None
    impact = report.section("Application Impact")
    assert "INFERENCE" in str(impact.ai_reasoning) and "INFERENCE" not in str(impact.observed_facts)
    assert report.section("Validation").validation_results["overall_result"] == "PASS"
    assert report.final_recommendation.decision == "Apply"
    md = ReportService.to_markdown(report)
    assert "## 6. Application Impact" in md and "```diff" in md and "Apply" in md
    assert EvidenceReport.model_validate(ReportService.to_json(report)).finding_id == graph["finding"].finding_id


def test_report_without_remediation_says_so(db, graph):
    report = ReportService(db).build(graph["finding"].finding_id)
    assert report.remediation_id is None
    assert report.final_recommendation.decision == "Analysis only — not validated"
    assert any("No remediation" in n for n in report.section("Recommended Remediation").notes)


@pytest.mark.parametrize("overall,tests,decision", [("PASS", "SKIPPED", "Apply with manual testing"), ("FAIL", "FAIL", "Do not apply yet"), ("UNKNOWN", "PASS", "Do not apply yet")])
def test_final_recommendation_rules(db, graph, tmp_path, overall, tests, decision):
    add_remediation(db, graph, tmp_path, overall=overall, tests=tests)
    assert ReportService(db).build(graph["finding"].finding_id).final_recommendation.decision == decision


# ---------------------------------------------------------------- GitHub provider on a real temp repository


class FakePull:
    def __init__(self, number=7, draft=True):
        self.number, self.draft, self.html_url = number, draft, f"https://github.com/example/demo-project/pull/{number}"


class FakeGitHubRepo:
    def __init__(self, existing=None, error=None):
        self.existing, self.error, self.create_calls = existing or [], error, []

    def get_pulls(self, state="open", head=None):
        return list(self.existing)

    def create_pull(self, **kwargs):
        self.create_calls.append(kwargs)
        if self.error:
            raise self.error
        return FakePull(draft=kwargs.get("draft", False))


class FakeGitHub:
    def __init__(self, repo):
        self.repo = repo

    def get_repo(self, full_name):
        self.full_name = full_name
        return self.repo


def recording_runner(pushed: list):
    from app.services.github.github_provider import run_git

    def runner(args, *, cwd, env=None, timeout=None):
        if "push" in args or "ls-remote" in args:
            pushed.append(list(args))
            return ""  # pretend the remote accepted it
        return run_git(args, cwd=cwd, env=env, timeout=timeout)

    return runner


def test_provider_creates_branch_commit_and_draft_pr_without_leaking_token(db, graph, tmp_path, caplog):
    rem = add_remediation(db, graph, tmp_path)
    ws = Path(rem.proposed_change["workspace_path"])
    pushed: list = []
    gh_repo = FakeGitHubRepo()
    provider = GitHubProvider("ghp_SECRET123", github_client=FakeGitHub(gh_repo), git_runner=recording_runner(pushed))
    spec = PullRequestSpec(workspace_path=ws, base_branch="main", head_branch="sentinel-chain/pypi-requests-2.33.0", title="bump", body="body",
                           commit_message="bump", changed_files=["requirements.txt"], repo_full_name="example/demo-project", draft=True)
    with caplog.at_level(logging.DEBUG):
        result = provider.create_pull_request(spec)
    assert result.status == PullRequestStatus.DRAFT and result.number == 7 and result.url.endswith("/pull/7")
    repo = git.Repo(ws)
    assert repo.active_branch.name == "sentinel-chain/pypi-requests-2.33.0"
    assert repo.head.commit.author.name == "Sentinel Chain" and "requirements.txt" in repo.head.commit.stats.files
    push = next(a for a in pushed if "push" in a)
    assert any("x-access-token:ghp_SECRET123@github.com/example/demo-project" in a for a in push)
    assert gh_repo.create_calls[0]["draft"] is True and gh_repo.create_calls[0]["base"] == "main"
    assert "ghp_SECRET123" not in caplog.text and "ghp_SECRET123" not in str(result)
    config = (ws / ".git" / "config").read_text()
    assert "ghp_SECRET123" not in config


def test_provider_unconfigured_returns_instructions_without_touching_repo(db, graph, tmp_path):
    rem = add_remediation(db, graph, tmp_path)
    ws = Path(rem.proposed_change["workspace_path"])
    result = GitHubProvider(None).create_pull_request(PullRequestSpec(workspace_path=ws, base_branch="main", head_branch="b", title="t", body="b", commit_message="c", changed_files=["requirements.txt"]))
    assert result.status == PullRequestStatus.UNAVAILABLE and "gh pr create --draft" in result.instructions
    assert git.Repo(ws).active_branch.name == "main"


def test_provider_reports_auth_failure_clearly(db, graph, tmp_path):
    from github import GithubException

    rem = add_remediation(db, graph, tmp_path)
    ws = Path(rem.proposed_change["workspace_path"])
    gh_repo = FakeGitHubRepo(error=GithubException(401, {"message": "Bad credentials"}, None))
    provider = GitHubProvider("bad-token", github_client=FakeGitHub(gh_repo), git_runner=recording_runner([]))
    result = provider.create_pull_request(PullRequestSpec(workspace_path=ws, base_branch="main", head_branch="b2", title="t", body="b", commit_message="c", changed_files=["requirements.txt"], repo_full_name="example/demo-project"))
    assert result.status == PullRequestStatus.FAILED and "authentication" in result.error.lower()


# ---------------------------------------------------------------- PullRequestService


class FakeProvider:
    def __init__(self, status=PullRequestStatus.DRAFT, configured=True):
        self.status, self.configured, self.specs = status, configured, []

    def is_configured(self):
        return self.configured

    def create_pull_request(self, spec):
        self.specs.append(spec)
        return PullRequestResult(status=self.status, branch=spec.head_branch, url="https://github.com/example/demo-project/pull/9", number=9)


def test_service_creates_pr_with_evidence_and_marks_remediation(db, graph, tmp_path):
    rem = add_remediation(db, graph, tmp_path)
    provider = FakeProvider()
    settings = Settings(_env_file=None, repository_workspace=str(tmp_path / "ws"))
    pr = PullRequestService(db, settings, provider=provider).create(rem.remediation_id)
    assert pr.review_status == PullRequestStatus.DRAFT and pr.pr_url.endswith("/pull/9")
    assert pr.title == "Sentinel Chain: bump requests 2.30.0 → 2.33.0 (GHSA-j8r2-6x86-q33q)"
    assert pr.branch_name == "sentinel-chain/pypi-requests-2.33.0"
    assert "GHSA-j8r2-6x86-q33q" in pr.body and "+requests==2.33.0" in pr.body and "Overall:** PASS" in pr.body
    assert pr.evidence["finding_id"] == graph["finding"].finding_id
    assert rem.status == RemediationStatus.PR_CREATED
    assert provider.specs[0].repo_full_name == "example/demo-project" and provider.specs[0].draft is True
    assert (tmp_path / "ws" / "reports" / str(rem.remediation_id) / "report.md").is_file()


def test_service_requires_validation_and_refuses_failed_unless_forced(db, graph, tmp_path):
    rem = add_remediation(db, graph, tmp_path, validated=False)
    service = PullRequestService(db, Settings(_env_file=None, repository_workspace=str(tmp_path / "ws")), provider=FakeProvider())
    with pytest.raises(ValidationFailedError):
        service.create(rem.remediation_id)
    db.add(Validation(remediation_id=rem.remediation_id, status=ValidationStatus.COMPLETED, build_status="FAIL", test_status="SKIPPED", security_scan_status="PASS", overall_result="FAIL"))
    db.commit()
    with pytest.raises(ConflictError):
        service.create(rem.remediation_id)
    pr = service.create(rem.remediation_id, force=True)
    assert pr.review_status == PullRequestStatus.DRAFT


def test_service_unavailable_without_token_keeps_instructions(db, graph, tmp_path):
    rem = add_remediation(db, graph, tmp_path)
    pr = PullRequestService(db, Settings(_env_file=None, repository_workspace=str(tmp_path / "ws")), provider=FakeProvider(configured=False)).create(rem.remediation_id)
    assert pr.review_status == PullRequestStatus.UNAVAILABLE and "GITHUB_TOKEN" in pr.instructions
    assert rem.status == RemediationStatus.VALIDATED
    assert db.get(PullRequest, pr.pr_id).body.startswith("## Summary")


def test_pure_builders():
    assert build_pr_title("lodash", "4.17.15", "4.18.1", "GHSA-x") == "Sentinel Chain: bump lodash 4.17.15 → 4.18.1 (GHSA-x)"
    assert build_branch_name("npm", "@scope/pkg", "1.2.3") == "sentinel-chain/npm-scope-pkg-1.2.3"
