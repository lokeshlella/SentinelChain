"""Regression tests for AUDIT-V2 findings V2-02 and V2-03.

* V2-03 — eligible files the scan cannot read (larger than the 1 MB cap, unreadable)
  are listed and make the evidence ``truncated``; they were silently dropped before.
* V2-02 — "beyond analysis depth" (transitive), "scan incomplete", "unknown scope" and
  "no direct import" are distinct verdicts in the prompt, the API, the evidence report
  and the UI; the bare "not referenced by application code" no longer exists.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.api.routes.findings import finding_detail
from app.models import Analysis, Dependency, Finding, Repository, Vulnerability
from app.models.enums import AIStatus
from app.services.agents.prompts import build_dependency_analysis_prompt, build_impact_prompt
from app.services.agents.schemas import GraphContext
from app.services.analysis import usage as usage_module
from app.services.analysis.context import build_finding_context
from app.services.analysis.usage import (
    MAX_FILE_SIZE_BYTES,
    MAX_SKIPPED_FILES_REPORTED,
    USAGE_BEYOND_DEPTH,
    USAGE_NO_DIRECT_IMPORT,
    USAGE_NOT_ANALYSED,
    USAGE_SCAN_INCOMPLETE,
    USAGE_UNKNOWN_SCOPE,
    USAGE_USED,
    SourceUsageAnalyzer,
    UsageEvidence,
    usage_verdict,
)
from app.services.reports.service import evidence_section, impact_section


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


# ---------------------------------------------------------------- V2-03: skipped files are partial evidence


def test_oversized_file_is_listed_and_marks_the_evidence_truncated(tmp_path, caplog):
    _write(tmp_path, "src/big.py", "import requests\n" + "x = 1\n" * (MAX_FILE_SIZE_BYTES // 6 + 1))
    _write(tmp_path, "src/small.py", "print(1)\n")

    with caplog.at_level("WARNING"):
        evidence = SourceUsageAnalyzer().find_usage(tmp_path, "requests", "PyPI", ["src"])

    assert evidence.files == [] and evidence.is_used is False
    assert evidence.truncated is True
    assert evidence.skipped_files == ["src/big.py"] and evidence.skipped_files_total == 1
    assert evidence.scanned_files == 1
    assert "Skipping src/big.py while scanning for requests: larger than" in caplog.text
    assert evidence.to_dict()["skipped_files"] == ["src/big.py"]


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="needs a non-root POSIX user for an unreadable file")
def test_unreadable_file_is_listed_as_skipped(tmp_path):
    hidden = _write(tmp_path, "src/hidden.py", "import requests\n")
    hidden.chmod(0)
    try:
        evidence = SourceUsageAnalyzer().find_usage(tmp_path, "requests", "PyPI", ["src"])
    finally:
        hidden.chmod(0o644)

    assert evidence.truncated is True
    assert evidence.skipped_files == ["src/hidden.py"]


def test_symlinks_are_skipped_by_design_not_as_missing_evidence(tmp_path):
    _write(tmp_path, "src/app.py", "print(1)\n")
    (tmp_path / "src" / "link.py").symlink_to(tmp_path / "src" / "app.py")

    evidence = SourceUsageAnalyzer().find_usage(tmp_path, "requests", "PyPI", ["src"])

    assert evidence.truncated is False and evidence.skipped_files == [] and evidence.skipped_files_total == 0


def test_skipped_file_list_is_capped_but_the_total_is_exact(tmp_path, monkeypatch):
    monkeypatch.setattr(usage_module, "MAX_FILE_SIZE_BYTES", 8)  # every file below is "oversized"
    for i in range(MAX_SKIPPED_FILES_REPORTED + 5):
        _write(tmp_path, f"src/mod{i:02d}.py", "import requests\n")

    evidence = SourceUsageAnalyzer().find_usage(tmp_path, "requests", "PyPI", ["src"])

    assert evidence.skipped_files_total == MAX_SKIPPED_FILES_REPORTED + 5
    assert len(evidence.skipped_files) == MAX_SKIPPED_FILES_REPORTED
    assert evidence.skipped_files == sorted(evidence.skipped_files)
    assert evidence.truncated is True and evidence.scanned_files == 0


def test_skipped_total_forces_truncated_and_legacy_rows_still_load():
    evidence = UsageEvidence(package_name="x", ecosystem="PyPI", skipped_files=["a.py"])
    assert evidence.truncated is True and evidence.skipped_files_total == 1

    legacy = UsageEvidence.from_dict({"package_name": "x", "ecosystem": "PyPI", "files": [], "truncated": False})
    assert legacy.skipped_files == [] and legacy.skipped_files_total == 0 and legacy.truncated is False
    assert legacy.analysis_depth == "direct-import-scan"


# ---------------------------------------------------------------- V2-02: what "no usage" means


def _evidence(**kwargs) -> UsageEvidence:
    return UsageEvidence(package_name="urllib3", ecosystem="PyPI", **kwargs)


@pytest.mark.parametrize(
    ("evidence", "scope", "kind", "fragment"),
    [
        (_evidence(files=["src/a.py"]), "direct", USAGE_USED, "Direct import found in 1 source file(s)."),
        (_evidence(files=["src/a.py"], truncated=True), "direct", USAGE_USED, "scan incomplete: more files may import it"),
        (_evidence(), "transitive", USAGE_BEYOND_DEPTH, "Beyond analysis depth"),
        (_evidence(truncated=True), "transitive", USAGE_BEYOND_DEPTH, "Beyond analysis depth"),  # depth wins over incompleteness
        (_evidence(skipped_files=["src/big.py"]), "direct", USAGE_SCAN_INCOMPLETE, "1 eligible file(s) were not scanned"),
        (_evidence(truncated=True), "direct", USAGE_SCAN_INCOMPLETE, "a scan limit was reached"),
        (_evidence(), "unknown", USAGE_UNKNOWN_SCOPE, "cannot tell whether the dependency is direct or transitive"),
        (_evidence(), None, USAGE_UNKNOWN_SCOPE, "cannot tell"),
        (_evidence(), "direct", USAGE_NO_DIRECT_IMPORT, "complete scan of a direct dependency"),
        (None, "direct", USAGE_NOT_ANALYSED, "No source-usage evidence was recorded"),
        ({"files": [], "truncated": False}, "TRANSITIVE", USAGE_BEYOND_DEPTH, "Beyond analysis depth"),  # stored dict, any case
    ],
)
def test_usage_verdict_kinds(evidence, scope, kind, fragment):
    verdict = usage_verdict(evidence, scope)
    assert verdict.kind == kind
    assert fragment in verdict.message
    assert verdict.to_dict()["analysis_depth"] == "direct-import-scan"
    assert "not referenced by application code" not in verdict.message


_repo_counter = 0


def _finding(db, *, scope: str, usage_evidence: dict | None) -> Finding:
    global _repo_counter
    _repo_counter += 1  # uq_repositories_source_branch: one repository row per call
    repo = Repository(name="demo", source_url=f"/tmp/demo-{_repo_counter}", source_type="local", language="Python",
                      profile={"dependency_files": ["requirements.txt"]})
    db.add(repo)
    db.flush()
    analysis = Analysis(repository_id=repo.repository_id, status="COMPLETED", stages={"knowledge_graph": "OK"})
    db.add(analysis)
    db.flush()
    dep = Dependency(repository_id=repo.repository_id, analysis_id=analysis.analysis_id, package_name="urllib3", version="2.0.7",
                     ecosystem="PyPI", direct_or_transitive=scope, source_file="requirements.txt", vulnerability_status="VULNERABLE")
    vuln = Vulnerability(identifier=f"GHSA-qccp-gfcp-{_repo_counter:04d}", source="osv", severity="HIGH", cvss_score=8.1, summary="header leak")
    db.add_all([dep, vuln])
    db.flush()
    finding = Finding(analysis_id=analysis.analysis_id, dependency_id=dep.dependency_id, vulnerability_id=vuln.vulnerability_id,
                      risk_level="HIGH", ai_status=AIStatus.PENDING, usage_evidence=usage_evidence, affected_components=[])
    db.add(finding)
    db.commit()
    return finding


class _NoGraph:
    def dependency_context(self, dep):
        return GraphContext(available=False)


def test_agent_context_and_prompt_say_beyond_depth_for_a_transitive_dependency(db):
    finding = _finding(db, scope="transitive", usage_evidence=_evidence().to_dict())
    ctx = build_finding_context(finding, _NoGraph())

    assert ctx.usage.verdict_kind == USAGE_BEYOND_DEPTH
    prompt = build_dependency_analysis_prompt(ctx)
    assert "- what this means: Beyond analysis depth: the dependency is transitive" in prompt
    assert "use UNKNOWN unless the evidence shows otherwise" in build_impact_prompt(ctx, None)


def test_prompt_lists_files_that_were_not_scanned(db):
    evidence = _evidence(skipped_files=["src/big.py"], files=["src/a.py"], components=["src"], total_files=1)
    finding = _finding(db, scope="direct", usage_evidence=evidence.to_dict())
    ctx = build_finding_context(finding, _NoGraph())

    assert ctx.usage.skipped_files == ["src/big.py"] and ctx.usage.truncated is True
    prompt = build_dependency_analysis_prompt(ctx)
    assert "- not scanned (1 eligible file(s) larger than 1 MB or unreadable): src/big.py" in prompt
    assert "more references may exist" in prompt


def test_api_detail_carries_the_usage_verdict(db):
    finding = _finding(db, scope="transitive", usage_evidence=_evidence().to_dict())
    detail = finding_detail(db, finding)

    assert detail.usage_verdict == {
        "kind": USAGE_BEYOND_DEPTH,
        "message": usage_verdict(finding.usage_evidence, "transitive").message,
        "analysis_depth": "direct-import-scan",
    }
    assert detail.usage_evidence["skipped_files"] == []

    none_recorded = finding_detail(db, _finding(db, scope="direct", usage_evidence=None))
    assert none_recorded.usage_verdict["kind"] == USAGE_NOT_ANALYSED


def test_report_distinguishes_beyond_depth_from_no_direct_import(db):
    transitive = _finding(db, scope="transitive", usage_evidence=_evidence().to_dict())
    section = evidence_section(transitive, {})
    assert section.observed_facts["usage_verdict"]["kind"] == USAGE_BEYOND_DEPTH
    assert any(n.startswith("Beyond analysis depth") for n in section.notes)
    assert not any("declared in a dependency file only" in n for n in section.notes)
    assert any("Beyond analysis depth" in n for n in impact_section(transitive).notes)

    direct = _finding(db, scope="direct", usage_evidence=_evidence().to_dict())
    section = evidence_section(direct, {})
    assert section.observed_facts["usage_verdict"]["kind"] == USAGE_NO_DIRECT_IMPORT
    assert any("complete scan of a direct dependency" in n for n in section.notes)

    partial = _finding(db, scope="direct", usage_evidence=_evidence(skipped_files=["src/big.py"]).to_dict())
    section = evidence_section(partial, {})
    assert section.observed_facts["skipped_files"] == ["src/big.py"]
    assert any("1 eligible file(s) larger than 1 MB or unreadable were not scanned (src/big.py)" in n for n in section.notes)
    assert section.observed_facts["usage_verdict"]["kind"] == USAGE_SCAN_INCOMPLETE
