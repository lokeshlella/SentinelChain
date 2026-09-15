"""Regression tests for the AUDIT-V2 fixes.

* V2-01 — the agents may raise a finding's risk/impact but never lower them below what
  the advisory severity warrants; "no direct import found" is never presented as proof
  of non-use.
* V2-04 — credentials carried by dependency manifests are redacted from everything that
  is stored, served or pushed (proposed change, evidence report, PR body, API rows,
  extraction warnings) while the working copy keeps the real content.
"""

from __future__ import annotations

import json

import pytest

from app.core.redaction import contains_secret, redact_secrets
from app.models import Analysis, Dependency, Finding, Repository, Vulnerability
from app.models.enums import AIStatus, ImpactLevel, RiskLevel
from app.schemas.entities import RemediationDetail
from app.services.agents.schemas import FindingAIResult, ImpactAssessmentResult, RiskAssessmentResult
from app.services.analysis.pipeline import AnalysisPipeline, compose_reasoning
from app.services.dependencies.python_extractor import PythonDependencyExtractor
from app.services.dependencies.service import DependencyService
from app.services.remediation.modifiers import REDACTION_NOTE, PackageJsonModifier, RequirementsTxtModifier
from app.services.reports.service import RISK_ORIGIN_FLOOR, _proposed_change, risk_section
from tests.fixtures.agents.contexts import valid_impact_output, valid_risk_output

TOKEN = "s3cr3tT0k3n"
INDEX_LINE = f"--extra-index-url https://deploy:{TOKEN}@pypi.internal.example/simple\n"


# ---------------------------------------------------------------- V2-01: storage guard


def _finding(db, *, severity: str, risk_level: str | None) -> Finding:
    repo = Repository(name="demo", source_url="/tmp/demo", source_type="local", language="Python")
    db.add(repo)
    db.flush()
    analysis = Analysis(repository_id=repo.repository_id, status="RUNNING")
    db.add(analysis)
    db.flush()
    dep = Dependency(repository_id=repo.repository_id, analysis_id=analysis.analysis_id, package_name="urllib3", version="2.0.7",
                     ecosystem="PyPI", source_file="requirements.txt", vulnerability_status="VULNERABLE")
    vuln = Vulnerability(identifier="GHSA-qccp-gfcp-xxvc", source="osv", severity=severity, cvss_score=8.1)
    db.add_all([dep, vuln])
    db.flush()
    finding = Finding(analysis_id=analysis.analysis_id, dependency_id=dep.dependency_id, vulnerability_id=vuln.vulnerability_id,
                      risk_level=risk_level, ai_status=AIStatus.PENDING)
    db.add(finding)
    db.commit()
    return finding


def _ai_result(*, impact: str, risk: str) -> FindingAIResult:
    return FindingAIResult(
        status="COMPLETED",
        impact=ImpactAssessmentResult(**{**valid_impact_output(components=[]), "impact_level": impact}),
        risk=RiskAssessmentResult(**{**valid_risk_output(), "risk_level": risk}),
        model="llama3.2:3b",
    )


def test_model_cannot_lower_a_high_advisory_below_high(db):
    # The AUDIT-V2 experiment: HIGH advisory, zero usage references, model says NONE / MEDIUM.
    finding = _finding(db, severity="HIGH", risk_level="HIGH")
    AnalysisPipeline._store_ai_result(finding, _ai_result(impact="NONE", risk="MEDIUM"), None)

    assert finding.risk_level == RiskLevel.HIGH
    assert finding.impact_level == ImpactLevel.UNKNOWN
    assert finding.ai_results["risk"]["risk_level"] == "MEDIUM"  # the raw verdict is preserved
    assert finding.ai_results["impact"]["impact_level"] == "NONE"
    assert "Risk floor: the model judged MEDIUM, stored as HIGH" in finding.reasoning
    assert "Impact guard: the model judged NONE, stored as UNKNOWN" in finding.reasoning


def test_model_may_raise_the_risk_above_the_severity_level(db):
    finding = _finding(db, severity="MEDIUM", risk_level="MEDIUM")
    AnalysisPipeline._store_ai_result(finding, _ai_result(impact="HIGH", risk="CRITICAL"), None)

    assert finding.risk_level == RiskLevel.CRITICAL and finding.impact_level == ImpactLevel.HIGH
    assert "Risk floor" not in finding.reasoning and "Impact guard" not in finding.reasoning


def test_unknown_verdict_keeps_the_provisional_level(db):
    finding = _finding(db, severity="HIGH", risk_level="HIGH")
    AnalysisPipeline._store_ai_result(finding, _ai_result(impact="UNKNOWN", risk="UNKNOWN"), None)

    assert finding.risk_level == RiskLevel.HIGH and finding.impact_level == ImpactLevel.UNKNOWN
    assert "Risk floor" not in finding.reasoning


def test_unrated_advisory_has_no_floor(db):
    finding = _finding(db, severity="UNKNOWN", risk_level="UNKNOWN")
    AnalysisPipeline._store_ai_result(finding, _ai_result(impact="LOW", risk="LOW"), None)

    assert finding.risk_level == RiskLevel.LOW and finding.impact_level == ImpactLevel.LOW


def test_report_risk_section_names_the_floor(db):
    finding = _finding(db, severity="HIGH", risk_level="HIGH")
    AnalysisPipeline._store_ai_result(finding, _ai_result(impact="NONE", risk="LOW"), None)
    db.commit()

    section = risk_section(finding)
    assert section.observed_facts["risk_level"] == "HIGH"
    assert section.observed_facts["risk_origin"] == RISK_ORIGIN_FLOOR
    assert section.ai_reasoning["risk_level"] == "LOW"
    assert any("never lowers the risk below the severity-derived level" in n for n in section.notes)


def test_compose_reasoning_appends_guard_notes():
    text = compose_reasoning(_ai_result(impact="LOW", risk="LOW"), ["Risk floor: note"])
    assert text.endswith("Risk floor: note")


# ---------------------------------------------------------------- V2-04: redaction


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (INDEX_LINE, "--extra-index-url https://***@pypi.internal.example/simple\n"),
        ("git+https://ghp_abcdefghijklmnopqrstuvwxyz0123456789@github.com/o/r.git#egg=x", "git+https://***@github.com/o/r.git#egg=x"),
        ("//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789", "//registry.npmjs.org/:_authToken=***"),
        ("https://${PIP_TOKEN}@pypi.internal/simple", "https://${PIP_TOKEN}@pypi.internal/simple"),  # placeholders stay
        ("token==1.0.0\ntokenizers==0.15.0\nsecret>=1.2", "token==1.0.0\ntokenizers==0.15.0\nsecret>=1.2"),  # specifiers are not credentials
        ("requests==2.31.0 --hash=sha256:abc", "requests==2.31.0 --hash=sha256:abc"),
        ("AKIAIOSFODNN7EXAMPLE", "***"),
        ("", ""),
        (None, None),
    ],
)
def test_redact_secrets(text, expected):
    assert redact_secrets(text) == expected
    assert contains_secret(text) is (text != expected)


def test_redaction_never_changes_the_line_count():
    text = "a\n" + INDEX_LINE + "requests==2.30.0\n"
    assert redact_secrets(text).count("\n") == text.count("\n")


def test_requirements_change_is_redacted_but_the_working_copy_is_not(tmp_path):
    (tmp_path / "requirements.txt").write_text(INDEX_LINE + "requests==2.30.0\n")

    change = RequirementsTxtModifier().apply(tmp_path, "requirements.txt", "requests", "2.30.0", "2.33.0")

    on_disk = (tmp_path / "requirements.txt").read_text()
    assert on_disk == INDEX_LINE + "requests==2.33.0\n"  # installed content keeps the real index URL
    for text in (change.before, change.after, change.diff):
        assert TOKEN not in text and "https://***@pypi.internal.example/simple" in text
    assert "+requests==2.33.0" in change.diff and change.line_number == 2
    assert change.redacted and REDACTION_NOTE in change.notes
    assert TOKEN not in json.dumps(change.to_dict())


def test_package_json_change_is_redacted(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "demo",
        "publishConfig": {"registry": f"https://ci:{TOKEN}@npm.internal.example/"},
        "dependencies": {"lodash": "^4.17.15"},
    }, indent=2) + "\n")

    change = PackageJsonModifier().apply(tmp_path, "package.json", "lodash", "4.17.15", "4.17.21")

    assert TOKEN in (tmp_path / "package.json").read_text()
    assert TOKEN not in change.before and TOKEN not in change.after and TOKEN not in change.diff
    assert '"lodash": "^4.17.21"' in change.after and change.redacted


def test_clean_change_carries_no_redaction_note(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.30.0\n")
    change = RequirementsTxtModifier().apply(tmp_path, "requirements.txt", "requests", "2.30.0", "2.33.0")
    assert not change.redacted and change.notes == []


def test_extraction_warnings_and_specs_are_redacted(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        INDEX_LINE
        + f"-e git+https://{TOKEN}@github.com/org/tool.git#egg=tool\n"
        + f"git+https://deploy:{TOKEN}@github.com/org/lib.git#egg=lib\n"
        + "requests==2.30.0\n"
    )
    result = DependencyService(extractors=[PythonDependencyExtractor()]).extract(tmp_path)

    assert result.warnings, "the editable and URL requirements are reported"
    assert all(TOKEN not in w for w in result.warnings)
    assert any("https://***@github.com/org/tool.git" in w for w in result.warnings)
    lib = next(d for d in result.dependencies if d.package_name == "lib")
    assert lib.version_spec == "git+https://***@github.com/org/lib.git#egg=lib"


def test_legacy_proposed_change_rows_are_redacted_when_served():
    detail = RemediationDetail.model_validate({
        "remediation_id": 1, "finding_id": 1, "status": "PROPOSED", "created_at": "2026-01-01T00:00:00Z",
        "proposed_change": {"file": "requirements.txt", "diff": f"-{INDEX_LINE}", "before": INDEX_LINE, "after": INDEX_LINE, "line_number": 1},
    })
    assert TOKEN not in json.dumps(detail.proposed_change)
    assert detail.proposed_change["line_number"] == 1


def test_report_proposed_change_is_redacted():
    assert TOKEN not in _proposed_change({"file": "requirements.txt", "diff": INDEX_LINE, "line_number": 1})["diff"]


def test_pr_body_never_carries_manifest_credentials(db, tmp_path):
    from app.models import Remediation, Validation
    from app.models.enums import RemediationStatus, ValidationStatus
    from app.services.github.service import build_pr_body

    finding = _finding(db, severity="HIGH", risk_level="HIGH")
    rem = Remediation(finding_id=finding.finding_id, current_version="2.0.7", recommended_version="2.2.2", confidence_score=0.9,
                      recommendation="upgrade", status=RemediationStatus.VALIDATED,
                      proposed_change={"file": "requirements.txt", "workspace_path": str(tmp_path), "line_number": 2,
                                       "diff": f"--- a/requirements.txt\n+++ b/requirements.txt\n {INDEX_LINE}-urllib3==2.0.7\n+urllib3==2.2.2\n"})
    db.add(rem)
    db.flush()
    validation = Validation(remediation_id=rem.remediation_id, status=ValidationStatus.COMPLETED, build_status="PASS", test_status="PASS",
                            security_scan_status="PASS", overall_result="PASS", details={"steps": [], "warnings": []})
    db.add(validation)
    db.commit()

    body = build_pr_body(rem, validation, None)
    assert TOKEN not in body and "https://***@pypi.internal.example/simple" in body
