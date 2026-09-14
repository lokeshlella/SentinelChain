"""AnalysisPipeline behaviour with fake collaborators (SQLite, no external services)."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.config import Settings
from app.models import Analysis, Finding
from app.models.enums import AIStatus, AnalysisStatus, StageStatus, VulnerabilityStatus
from app.services.agents.orchestrator import AIOrchestrator
from app.services.analysis.pipeline import AnalysisPipeline
from app.services.analysis.usage import SourceUsageAnalyzer
from app.services.dependencies.service import DependencyService
from app.services.llm.base import LLMError
from app.services.repository.service import RepositoryService
from app.services.vulnerabilities.service import VulnerabilityService
from tests.fixtures.agents.contexts import valid_dependency_output, valid_impact_output, valid_risk_output
from tests.fixtures.api_fakes import FakeGraphService, FakeVulnerabilityProvider, make_demo_repo
from tests.fixtures.llm.fake_provider import FakeLLMProvider


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(_env_file=None, repository_workspace=str(tmp_path / "ws"), ai_max_findings_per_analysis=5, llm_max_retries=1)


@pytest.fixture
def repository(db, settings, tmp_path):
    return RepositoryService(db, settings).register(str(make_demo_repo(tmp_path / "demo")))


def new_analysis(db, repository) -> Analysis:
    analysis = Analysis(repository_id=repository.repository_id, status=AnalysisStatus.PENDING)
    db.add(analysis)
    db.commit()
    return analysis


def make_pipeline(db, settings, *, provider=None, graph=None, llm=None, orchestrator="auto") -> AnalysisPipeline:
    if orchestrator == "auto":
        orchestrator = AIOrchestrator(llm, settings) if llm is not None else None
    return AnalysisPipeline(
        db,
        settings,
        repository_service=RepositoryService(db, settings),
        dependency_service=DependencyService(),
        vulnerability_service=VulnerabilityService(db, provider=provider or FakeVulnerabilityProvider(), settings=settings),
        graph_service=graph or FakeGraphService(),
        usage_analyzer=SourceUsageAnalyzer(),
        orchestrator=orchestrator,
    )


def ai_outputs(n: int) -> list:
    out = []
    for _ in range(n):
        out += [valid_dependency_output(), valid_impact_output(components=["src"]), valid_risk_output()]
    return out


def test_full_run_completes_with_findings_and_ai(db, settings, repository):
    llm = FakeLLMProvider(ai_outputs(1))
    graph = FakeGraphService()
    analysis = new_analysis(db, repository)
    make_pipeline(db, settings, llm=llm, graph=graph).run(analysis.analysis_id)
    db.refresh(analysis)
    assert analysis.status == AnalysisStatus.COMPLETED
    assert analysis.stages == {s: "OK" for s in ("repository", "dependencies", "vulnerabilities", "usage", "knowledge_graph", "ai")}
    deps = {(d.package_name, d.vulnerability_status) for d in analysis.dependencies}
    assert ("requests", VulnerabilityStatus.VULNERABLE) in deps
    assert ("flask", VulnerabilityStatus.UNKNOWN) in deps  # unpinned
    assert ("lodash", VulnerabilityStatus.SAFE) in deps
    finding = analysis.findings[0]
    assert finding.vulnerability.identifier == "GHSA-j8r2-6x86-q33q"
    assert finding.usage_evidence["files"] == ["src/app/client.py"]
    assert finding.affected_components == ["src"]
    assert finding.ai_status == AIStatus.COMPLETED
    assert finding.impact_level == "MEDIUM" and finding.risk_level in ("MEDIUM", "HIGH", "CRITICAL", "LOW")
    assert finding.ai_results["status"] == "COMPLETED"
    assert "Dependency analysis:" in finding.reasoning
    assert graph.synced[0]["usage"] == {finding.dependency_id: ["src"]}
    assert analysis.summary["vulnerabilities"]["vulnerable"] == 1
    assert analysis.overall_risk == finding.risk_level


def test_osv_unavailable_degrades_to_unknown_never_safe(db, settings, repository):
    analysis = new_analysis(db, repository)
    make_pipeline(db, settings, provider=FakeVulnerabilityProvider(available=False), llm=FakeLLMProvider([])).run(analysis.analysis_id)
    db.refresh(analysis)
    assert analysis.status == AnalysisStatus.COMPLETED
    assert analysis.stages["vulnerabilities"] == StageStatus.UNAVAILABLE
    assert {d.vulnerability_status for d in analysis.dependencies} == {VulnerabilityStatus.UNKNOWN}
    assert all("unavailable" in (d.status_reason or "").lower() or "pinned" in (d.status_reason or "") for d in analysis.dependencies)
    assert analysis.findings == []
    assert analysis.stages["ai"] == StageStatus.SKIPPED
    assert any("Vulnerability check unavailable" in w for w in analysis.summary["warnings"])


def test_llm_unavailable_marks_ai_stage_unavailable(db, settings, repository):
    llm = FakeLLMProvider([LLMError("Ollama unreachable at http://localhost:11434; start it with `ollama serve`")])
    analysis = new_analysis(db, repository)
    make_pipeline(db, settings, llm=llm).run(analysis.analysis_id)
    db.refresh(analysis)
    assert analysis.status == AnalysisStatus.COMPLETED
    assert analysis.stages["ai"] == StageStatus.UNAVAILABLE
    finding = analysis.findings[0]
    assert finding.ai_status == AIStatus.UNAVAILABLE
    assert "unreachable" in finding.ai_error
    assert finding.risk_level == "MEDIUM"  # provisional from severity, still present
    assert len(llm.calls) == 1  # no further LLM calls after the first failure


def test_run_ai_false_skips_agents(db, settings, repository):
    llm = FakeLLMProvider([])
    analysis = new_analysis(db, repository)
    make_pipeline(db, settings, llm=llm).run(analysis.analysis_id, run_ai=False)
    db.refresh(analysis)
    assert analysis.stages["ai"] == StageStatus.SKIPPED
    assert analysis.findings[0].ai_status == AIStatus.SKIPPED
    assert llm.calls == []


def test_ai_limit_skips_remaining_findings_and_on_demand_run_fills_them(db, settings, repository):
    from tests.fixtures.api_fakes import requests_record

    second = requests_record()
    second.identifier, second.aliases = "GHSA-second-0000-0000", ["CVE-2024-0001"]
    provider = FakeVulnerabilityProvider(vulnerable={("PyPI", "requests"): [requests_record(), second]})
    settings.ai_max_findings_per_analysis = 1
    llm = FakeLLMProvider(ai_outputs(2))
    analysis = new_analysis(db, repository)
    pipeline = make_pipeline(db, settings, provider=provider, llm=llm)
    pipeline.run(analysis.analysis_id)
    db.refresh(analysis)
    statuses = sorted(f.ai_status for f in analysis.findings)
    assert statuses == [AIStatus.COMPLETED, AIStatus.SKIPPED]
    assert analysis.stages["ai"] == StageStatus.PARTIAL
    skipped = next(f for f in analysis.findings if f.ai_status == AIStatus.SKIPPED)
    assert "limit (1)" in skipped.ai_error
    pipeline.run_ai_for_finding(skipped.finding_id)
    db.refresh(skipped)
    assert skipped.ai_status == AIStatus.COMPLETED and skipped.ai_error is None


def test_graph_unavailable_is_reported_not_fatal(db, settings, repository):
    analysis = new_analysis(db, repository)
    make_pipeline(db, settings, graph=FakeGraphService(available=False), llm=FakeLLMProvider(ai_outputs(1))).run(analysis.analysis_id)
    db.refresh(analysis)
    assert analysis.status == AnalysisStatus.COMPLETED
    assert analysis.stages["knowledge_graph"] == StageStatus.UNAVAILABLE
    assert analysis.findings[0].ai_status == AIStatus.COMPLETED  # AI still ran with graph.available=False


def test_missing_dependency_files_fails_analysis_clearly(db, settings, tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "README.md").write_text("nothing here\n")
    repository = RepositoryService(db, settings).register(str(empty))
    analysis = new_analysis(db, repository)
    make_pipeline(db, settings, llm=FakeLLMProvider([])).run(analysis.analysis_id)
    db.refresh(analysis)
    assert analysis.status == AnalysisStatus.FAILED
    assert "No supported dependency files" in analysis.error_message
    assert analysis.stages["dependencies"] == StageStatus.FAILED
    assert analysis.stages["vulnerabilities"] == StageStatus.SKIPPED


def test_invented_component_is_dropped_by_guardrail(db, settings, repository):
    llm = FakeLLMProvider([valid_dependency_output(), valid_impact_output(components=["src", "billing/core"]), valid_risk_output()])
    analysis = new_analysis(db, repository)
    make_pipeline(db, settings, llm=llm).run(analysis.analysis_id)
    db.refresh(analysis)
    finding: Finding = analysis.findings[0]
    assert finding.ai_results["impact"]["affected_components"] == ["src"]
    assert finding.ai_results["dropped_components"] == ["billing/core"]
