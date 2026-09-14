"""Remediation engine: registry parsing, candidate selection, file modifiers, service."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from app.core.config import Settings
from app.core.exceptions import ValidationFailedError
from app.models import Analysis, Dependency, Finding, Repository, Vulnerability
from app.models.enums import RemediationStatus, VulnerabilityStatus
from app.services.agents.orchestrator import AIOrchestrator
from app.services.llm.base import LLMError
from app.services.remediation.candidates import select_candidates
from app.services.remediation.modifiers import PackageJsonModifier, RequirementsTxtModifier, get_modifier
from app.services.remediation.registry import PackageRegistryClient, RegistryInfo, parse_npm, parse_pypi
from app.services.remediation.service import RemediationService
from app.services.vulnerabilities.base import PackageQuery, PackageVulnerabilityResult
from tests.fixtures.agents.contexts import valid_remediation_output
from tests.fixtures.llm.fake_provider import FakeLLMProvider

FIXTURES = Path(__file__).parent / "fixtures" / "remediation"


# ---------------------------------------------------------------- registry


def test_parse_pypi_excludes_yanked_and_picks_latest_stable():
    info = parse_pypi("requests", json.loads((FIXTURES / "pypi_requests.json").read_text()))
    assert info.available and "2.33.0" in info.versions and info.latest
    assert all(v not in info.versions for v in info.yanked)


def test_parse_npm_excludes_deprecated_versions():
    info = parse_npm("lodash", json.loads((FIXTURES / "npm_lodash.json").read_text()))
    assert "4.18.0" not in info.versions and "4.18.0" in info.yanked
    assert "Bad release" in info.deprecations["4.18.0"]
    assert info.latest == "4.18.1"


def test_registry_client_handles_404_and_transport_errors():
    def handler(request: httpx.Request) -> httpx.Response:
        if "missing" in request.url.path:
            return httpx.Response(404)
        raise httpx.ConnectError("boom", request=request)

    client = PackageRegistryClient(5, httpx.Client(transport=httpx.MockTransport(handler)))
    missing = client.versions("PyPI", "missing-pkg")
    assert missing.available is True and missing.versions == [] and "not found" in (missing.error or "")
    down = client.versions("npm", "lodash")
    assert down.available is False and down.error


# ---------------------------------------------------------------- candidates


class FakeRegistry:
    def __init__(self, versions: list[str], deprecated: dict[str, str] | None = None, available: bool = True):
        self._versions, self._deprecated, self._available = versions, deprecated or {}, available

    def versions(self, ecosystem: str, name: str) -> RegistryInfo:
        if not self._available:
            return RegistryInfo(ecosystem=ecosystem, package_name=name, available=False, error="down")
        usable = [v for v in self._versions if v not in self._deprecated]
        return RegistryInfo(ecosystem=ecosystem, package_name=name, versions=usable, latest=usable[-1], yanked=list(self._deprecated), deprecations=dict(self._deprecated))


class FakeChecker:
    """OSV stand-in: ``vulnerable_below`` maps identifier -> first fixed version."""

    def __init__(self, vulnerable_below: dict[str, str], available: bool = True):
        self.vulnerable_below, self.available, self.calls = vulnerable_below, available, []

    def check_package(self, ecosystem, name, version):
        from app.core.versions import compare_versions
        from tests.fixtures.api_fakes import requests_record

        self.calls.append(version)
        query = PackageQuery(ecosystem, name, version)
        if not self.available:
            return PackageVulnerabilityResult(query=query, status=VulnerabilityStatus.UNKNOWN, reason="Vulnerability check unavailable")
        records = []
        for ident, fixed in self.vulnerable_below.items():
            if compare_versions(version, fixed, ecosystem) < 0:
                rec = requests_record()
                rec.identifier = ident
                rec.affected[0].ranges[0].fixed = fixed
                rec.affected[0].fixed_versions = [fixed]
                records.append(rec)
        status = VulnerabilityStatus.VULNERABLE if records else VulnerabilityStatus.SAFE
        return PackageVulnerabilityResult(query=query, status=status, vulnerabilities=records)


def vuln_row(db, identifier: str, fixed: str, name="requests", ecosystem="PyPI") -> Vulnerability:
    row = Vulnerability(
        identifier=identifier, source="osv", severity="MEDIUM",
        affected=[{"ecosystem": ecosystem, "package_name": name, "ranges": [{"range_type": "ECOSYSTEM", "introduced": "0", "fixed": fixed, "last_affected": None}], "versions": [], "fixed_versions": [fixed]}],
    )
    db.add(row)
    db.flush()
    return row


class Dep:
    def __init__(self, name, version, ecosystem="PyPI"):
        self.package_name, self.version, self.ecosystem = name, version, ecosystem


def test_candidates_cover_all_vulnerabilities_and_verify_with_osv(db):
    vulns = [vuln_row(db, "GHSA-a", "2.31.0"), vuln_row(db, "GHSA-b", "2.32.4")]
    registry = FakeRegistry(["2.30.0", "2.31.0", "2.32.0", "2.32.4", "2.33.0", "3.0.0"])
    checker = FakeChecker({"GHSA-a": "2.31.0", "GHSA-b": "2.32.4"})
    cs = select_candidates(Dep("requests", "2.30.0"), vulns, registry=registry, vulnerability_service=checker)
    assert cs.minimum_fixed_version == "2.32.4" and cs.preferred_version == "2.32.4"
    assert cs.verified_safe is True and cs.same_major is True
    assert cs.latest_version == "3.0.0" and cs.latest_in_same_major == "2.33.0"
    assert set(cs.allowed_versions) == {"2.32.4", "2.33.0", "3.0.0"}


def test_candidate_still_vulnerable_is_bumped_to_next_fix(db):
    vulns = [vuln_row(db, "GHSA-a", "2.31.0")]
    registry = FakeRegistry(["2.30.0", "2.31.0", "2.32.0", "2.33.0"])
    # OSV knows about a second advisory the stored rows do not: 2.31.0 is still vulnerable.
    checker = FakeChecker({"GHSA-a": "2.31.0", "GHSA-new": "2.33.0"})
    cs = select_candidates(Dep("requests", "2.30.0"), vulns, registry=registry, vulnerability_service=checker)
    assert cs.preferred_version == "2.33.0" and cs.verified_safe is True
    assert "2.31.0" in cs.verification and cs.verification["2.31.0"] == "VULNERABLE"


def test_deprecated_registry_version_is_skipped(db):
    vulns = [vuln_row(db, "GHSA-x", "4.18.0", name="lodash", ecosystem="npm")]
    registry = FakeRegistry(["4.17.21", "4.18.0", "4.18.1"], deprecated={"4.18.0": "Bad release"})
    checker = FakeChecker({"GHSA-x": "4.18.0"})
    cs = select_candidates(Dep("lodash", "4.17.15", "npm"), vulns, registry=registry, vulnerability_service=checker)
    assert cs.preferred_version == "4.18.1"
    assert any("deprecated" in n for n in cs.notes)


def test_osv_unavailable_yields_unverified_candidate_with_note(db):
    vulns = [vuln_row(db, "GHSA-a", "2.31.0")]
    cs = select_candidates(Dep("requests", "2.30.0"), vulns, registry=FakeRegistry(["2.31.0", "2.33.0"]), vulnerability_service=FakeChecker({}, available=False))
    assert cs.preferred_version == "2.31.0" and cs.verified_safe is None and cs.osv_available is False


def test_no_fixed_version_gives_no_candidate(db):
    row = Vulnerability(identifier="GHSA-nofix", source="osv", severity="HIGH", affected=[{"ecosystem": "PyPI", "package_name": "requests", "ranges": [], "versions": [], "fixed_versions": []}])
    db.add(row)
    db.flush()
    cs = select_candidates(Dep("requests", "2.30.0"), [row], registry=FakeRegistry(["2.30.0"]), vulnerability_service=FakeChecker({}))
    assert cs.preferred_version is None and cs.has_candidate is False
    assert any("no fixed version" in n.lower() for n in cs.notes)


# ---------------------------------------------------------------- modifiers


def test_requirements_modifier_preserves_extras_markers_comments_and_crlf(tmp_path):
    (tmp_path / "requirements.txt").write_bytes(b"flask==2.0.0\r\nRequests[security]==2.30.0 ; python_version>'3.8'  # http client\r\n")
    change = RequirementsTxtModifier().apply(tmp_path, "requirements.txt", "requests", "2.30.0", "2.33.0")
    assert change.line_number == 2
    assert "Requests[security]==2.33.0 ; python_version>'3.8'  # http client" in change.after
    assert (tmp_path / "requirements.txt").read_bytes().count(b"\r\n") == 2
    assert "-Requests[security]==2.30.0" in change.diff and "+Requests[security]==2.33.0" in change.diff


def test_requirements_modifier_rejects_missing_or_unpinned(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests>=2.0\n")
    with pytest.raises(ValidationFailedError):
        RequirementsTxtModifier().apply(tmp_path, "requirements.txt", "requests", None, "2.33.0")
    with pytest.raises(ValidationFailedError):
        RequirementsTxtModifier().apply(tmp_path, "requirements.txt", "django", "3.0", "4.0")


def test_package_json_modifier_keeps_operator_and_indentation(tmp_path):
    (tmp_path / "package.json").write_text('{\n    "name": "x",\n    "dependencies": {\n        "lodash": "^4.17.15"\n    },\n    "devDependencies": {\n        "jest": "~29.0.0"\n    }\n}\n')
    (tmp_path / "package-lock.json").write_text("{}")
    change = PackageJsonModifier().apply(tmp_path, "package.json", "lodash", "4.17.15", "4.18.1")
    data = json.loads(change.after)
    assert data["dependencies"]["lodash"] == "^4.18.1" and data["devDependencies"]["jest"] == "~29.0.0"
    assert change.after.startswith('{\n    "name"') and change.after.endswith("}\n")
    assert change.lock_note is not None


def test_get_modifier_refuses_lock_files():
    with pytest.raises(ValidationFailedError):
        get_modifier("package-lock.json")
    assert isinstance(get_modifier("requirements/base.txt"), RequirementsTxtModifier)
    assert isinstance(get_modifier("frontend/package.json"), PackageJsonModifier)


# ---------------------------------------------------------------- service


@pytest.fixture
def finding(db, tmp_path):
    source = tmp_path / "repo"
    source.mkdir()
    (source / "requirements.txt").write_text("requests==2.30.0\nflask==3.0.0\n")
    repo = Repository(name="demo", source_url=str(source), source_type="local", local_path=str(source), profile={"dependency_files": ["requirements.txt"]})
    db.add(repo)
    db.flush()
    analysis = Analysis(repository_id=repo.repository_id, status="COMPLETED")
    db.add(analysis)
    db.flush()
    dep = Dependency(repository_id=repo.repository_id, analysis_id=analysis.analysis_id, package_name="requests", version="2.30.0", ecosystem="PyPI", direct_or_transitive="unknown", source_file="requirements.txt", vulnerability_status="VULNERABLE")
    db.add(dep)
    db.flush()
    vuln = vuln_row(db, "GHSA-j8r2-6x86-q33q", "2.31.0")
    row = Finding(analysis_id=analysis.analysis_id, dependency_id=dep.dependency_id, vulnerability_id=vuln.vulnerability_id, ai_status="COMPLETED", usage_evidence={"package_name": "requests", "ecosystem": "PyPI", "import_names": ["requests"], "references": [], "files": ["src/app.py"], "components": ["src"], "truncated": False, "scanned_files": 3})
    db.add(row)
    db.commit()
    return row


def service(db, tmp_path, llm_responses, checker=None) -> RemediationService:
    settings = Settings(_env_file=None, repository_workspace=str(tmp_path / "ws"), llm_max_retries=1)
    orchestrator = AIOrchestrator(FakeLLMProvider(llm_responses), settings) if llm_responses is not None else None
    return RemediationService(
        db, settings, orchestrator=orchestrator,
        registry=FakeRegistry(["2.30.0", "2.31.0", "2.32.4", "2.33.0"]),
        vulnerability_service=checker or FakeChecker({"GHSA-j8r2-6x86-q33q": "2.31.0"}),
    )


def test_remediate_produces_a_proposed_change_in_a_new_workspace(db, tmp_path, finding):
    remediation = service(db, tmp_path, [valid_remediation_output("2.31.0")]).remediate(finding.finding_id)
    assert remediation.status == RemediationStatus.PROPOSED
    assert remediation.recommended_version == "2.31.0" and remediation.confidence_score > 0.5
    change = remediation.proposed_change
    workspace = Path(change["workspace_path"])
    assert workspace.exists() and workspace != Path(finding.analysis.repository.local_path)
    assert (workspace / "requirements.txt").read_text() == "requests==2.31.0\nflask==3.0.0\n"
    assert Path(finding.analysis.repository.local_path, "requirements.txt").read_text().startswith("requests==2.30.0")
    assert "+requests==2.31.0" in change["diff"] and remediation.ai_result["recommended_version"] == "2.31.0"


def test_llm_unavailable_falls_back_to_deterministic_candidate(db, tmp_path, finding):
    remediation = service(db, tmp_path, [LLMError("Ollama unreachable")]).remediate(finding.finding_id)
    assert remediation.status == RemediationStatus.PROPOSED
    assert remediation.recommended_version == "2.31.0" and remediation.ai_result is None
    assert remediation.confidence_score == 0.5 and "LLM unavailable" in remediation.recommendation


def test_llm_choosing_non_candidate_version_is_overridden(db, tmp_path, finding):
    remediation = service(db, tmp_path, [valid_remediation_output("9.9.9")]).remediate(finding.finding_id)
    assert remediation.recommended_version == "2.31.0"
    assert "adjusted" in remediation.recommendation


def test_no_fixed_version_fails_without_inventing_one(db, tmp_path, finding):
    finding.vulnerability.affected = [{"ecosystem": "PyPI", "package_name": "requests", "ranges": [], "versions": [], "fixed_versions": []}]
    db.commit()
    svc = service(db, tmp_path, None, checker=FakeChecker({"GHSA-j8r2-6x86-q33q": "2.31.0"}))
    with pytest.raises(ValidationFailedError):
        svc.remediate(finding.finding_id)
    remediation = svc.list_for_finding(finding.finding_id)[-1]
    assert remediation.status == RemediationStatus.FAILED and "No fixed version" in remediation.error_message


def test_lock_file_dependencies_are_refused(db, tmp_path, finding):
    finding.dependency.source_file = "package-lock.json"
    db.commit()
    with pytest.raises(ValidationFailedError):
        service(db, tmp_path, None).remediate(finding.finding_id)
