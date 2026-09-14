"""Docker sandbox provider (with a fake docker client), security scan and ValidationService."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.config import Settings
from app.core.exceptions import ValidationFailedError
from app.models import Analysis, Dependency, Finding, Remediation, Repository, Vulnerability
from app.models.enums import CheckResult, RemediationStatus, ValidationStatus, VulnerabilityStatus
from app.services.sandbox.base import SandboxError, SandboxRequest, SandboxResult, StepResult
from app.services.sandbox.docker_provider import DockerSandboxProvider, build_script, parse_step_markers
from app.services.sandbox.security_scan import DependencySecurityScanner
from app.services.sandbox.service import ValidationService, overall_result
from app.services.vulnerabilities.base import PackageQuery, PackageVulnerabilityResult
from tests.fixtures.api_fakes import requests_record
from tests.fixtures.sandbox.fake_docker import (
    FAILING_BUILD_LOGS,
    FAILING_TESTS_LOGS,
    PASSING_PYTHON_LOGS,
    SKIPPED_TESTS_LOGS,
    TIMEOUT_DURING_TESTS_LOGS,
    FakeDockerClient,
)


def settings(tmp_path: Path) -> Settings:
    return Settings(_env_file=None, repository_workspace=str(tmp_path / "ws"), docker_timeout=30)


def python_workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws-py"
    if ws.exists():
        return ws
    (ws / "tests").mkdir(parents=True)
    (ws / "requirements.txt").write_text("requests==2.33.0\n")
    (ws / "tests" / "test_x.py").write_text("def test_ok():\n    assert True\n")
    (ws / "node_modules").mkdir()
    (ws / "node_modules" / "junk.js").write_text("x")
    return ws


# ---------------------------------------------------------------- pure helpers


def test_parse_step_markers_covers_pass_fail_skip_and_timeout():
    assert parse_step_markers(PASSING_PYTHON_LOGS)["build"] == 0 and parse_step_markers(PASSING_PYTHON_LOGS)["tests"] == 0
    failing = parse_step_markers(FAILING_BUILD_LOGS)
    assert failing["build"] == 1 and failing["tests"] is None and "build failed" in failing["tests_skipped_reason"]
    assert parse_step_markers(FAILING_TESTS_LOGS)["tests"] == 1
    skipped = parse_step_markers(SKIPPED_TESTS_LOGS)
    assert skipped["tests"] is None and "no test script" in skipped["tests_skipped_reason"]
    timeout = parse_step_markers(TIMEOUT_DURING_TESTS_LOGS)
    assert timeout["build"] == 0 and timeout["tests"] is None and timeout["tests_skipped_reason"] is None


def test_script_builders_detect_tests(tmp_path):
    ws = python_workspace(tmp_path)
    script = build_script(SandboxRequest(workspace_path=ws, ecosystem="PyPI", dependency_file="requirements.txt"))
    assert "pip install" in script.text and "pytest" in script.text and script.test_command
    empty = tmp_path / "ws-empty"
    empty.mkdir()
    (empty / "requirements.txt").write_text("requests==2.33.0\n")
    script2 = build_script(SandboxRequest(workspace_path=empty, ecosystem="PyPI", dependency_file="requirements.txt"))
    assert script2.test_command is None and script2.tests_skipped_reason
    node = tmp_path / "ws-node"
    node.mkdir()
    (node / "package.json").write_text('{"scripts": {"test": "echo \\"Error: no test specified\\" && exit 1"}}')
    script3 = build_script(SandboxRequest(workspace_path=node, ecosystem="npm", dependency_file="package.json"))
    assert "npm install" in script3.text and script3.test_command is None


def test_overall_result_rules():
    assert overall_result("PASS", "PASS", "PASS") == CheckResult.PASS
    assert overall_result("PASS", "SKIPPED", "PASS") == CheckResult.PASS
    assert overall_result("PASS", "FAIL", "PASS") == CheckResult.FAIL
    assert overall_result("FAIL", "SKIPPED", "PASS") == CheckResult.FAIL
    assert overall_result("PASS", "PASS", "UNKNOWN") == CheckResult.UNKNOWN
    assert overall_result("UNKNOWN", "UNKNOWN", "PASS") == CheckResult.UNKNOWN


# ---------------------------------------------------------------- provider with the fake client


def test_provider_runs_isolated_container_and_cleans_up(tmp_path):
    client = FakeDockerClient(logs=PASSING_PYTHON_LOGS)
    provider = DockerSandboxProvider(settings(tmp_path), client=client)
    result = provider.run(SandboxRequest(workspace_path=python_workspace(tmp_path), ecosystem="PyPI", dependency_file="requirements.txt", timeout_seconds=30))
    assert result.build.status == CheckResult.PASS and result.tests.status == CheckResult.PASS
    assert result.image == "python:3.12-slim" and not result.timed_out
    container = client.containers.created[0]
    kwargs = container.kwargs
    assert kwargs["cap_drop"] == ["ALL"] and "no-new-privileges" in kwargs["security_opt"]
    assert kwargs.get("pids_limit") == 512 and kwargs.get("mem_limit")
    assert not any(k in kwargs for k in ("volumes", "mounts", "privileged"))
    assert container.removed == {"force": True}
    from tests.fixtures.sandbox.fake_docker import tar_names

    names = [n for _, data in container.archives for n in tar_names(data)]
    assert any(n.endswith("requirements.txt") for n in names) and not any("node_modules" in n for n in names)


def test_provider_reports_build_failure_and_skipped_tests(tmp_path):
    provider = DockerSandboxProvider(settings(tmp_path), client=FakeDockerClient(logs=FAILING_BUILD_LOGS))
    result = provider.run(SandboxRequest(workspace_path=python_workspace(tmp_path), ecosystem="PyPI", dependency_file="requirements.txt"))
    assert result.build.status == CheckResult.FAIL and result.build.exit_code == 1
    assert result.tests.status == CheckResult.SKIPPED and "build failed" in (result.tests.note or "")


def test_provider_timeout_kills_container_and_marks_unknown(tmp_path):
    client = FakeDockerClient(logs=TIMEOUT_DURING_TESTS_LOGS, wait_timeout=True)
    provider = DockerSandboxProvider(settings(tmp_path), client=client)
    result = provider.run(SandboxRequest(workspace_path=python_workspace(tmp_path), ecosystem="PyPI", dependency_file="requirements.txt", timeout_seconds=1))
    assert result.timed_out and result.tests.status == CheckResult.UNKNOWN
    assert client.containers.created[0].killed and client.containers.created[0].removed


def test_provider_pulls_missing_image_and_raises_sandbox_error_when_docker_is_down(tmp_path):
    client = FakeDockerClient(images_present=())
    DockerSandboxProvider(settings(tmp_path), client=client).run(SandboxRequest(workspace_path=python_workspace(tmp_path), ecosystem="PyPI", dependency_file="requirements.txt"))
    assert "python:3.12-slim" in client.images.pulled
    down = FakeDockerClient(create_error=RuntimeError("Cannot connect to the Docker daemon"))
    with pytest.raises(SandboxError):
        DockerSandboxProvider(settings(tmp_path), client=down).run(SandboxRequest(workspace_path=python_workspace(tmp_path), ecosystem="PyPI", dependency_file="requirements.txt"))


# ---------------------------------------------------------------- security scan


class Checker:
    def __init__(self, status, records=None, available=True):
        self.status, self.records, self.available = status, records or [], available

    def check_package(self, ecosystem, name, version):
        q = PackageQuery(ecosystem, name, version)
        if not self.available:
            return PackageVulnerabilityResult(query=q, status=VulnerabilityStatus.UNKNOWN, reason="Vulnerability check unavailable")
        return PackageVulnerabilityResult(query=q, status=self.status, vulnerabilities=self.records)


def test_security_scan_pass_fail_unknown_and_mismatch(tmp_path):
    ws = python_workspace(tmp_path)
    assert DependencySecurityScanner(Checker(VulnerabilityStatus.SAFE)).scan(ws, "PyPI", "requests", "2.33.0").status == CheckResult.PASS
    failed = DependencySecurityScanner(Checker(VulnerabilityStatus.VULNERABLE, [requests_record()])).scan(ws, "PyPI", "requests", "2.33.0")
    assert failed.status == CheckResult.FAIL and failed.target_vulnerabilities == ["GHSA-j8r2-6x86-q33q"]
    unknown = DependencySecurityScanner(Checker(VulnerabilityStatus.SAFE, available=False)).scan(ws, "PyPI", "requests", "2.33.0")
    assert unknown.status == CheckResult.UNKNOWN and unknown.provider_available is False
    mismatch = DependencySecurityScanner(Checker(VulnerabilityStatus.SAFE)).scan(ws, "PyPI", "requests", "2.99.0")
    assert mismatch.status == CheckResult.FAIL and any("expected" in n for n in mismatch.notes)


# ---------------------------------------------------------------- ValidationService


class FakeSandbox:
    name = "fake"

    def __init__(self, build="PASS", tests="PASS", error=None, artifacts=None):
        self.build, self.tests, self.error, self.artifacts = build, tests, error, artifacts or {}

    def run(self, request):
        if self.error:
            raise SandboxError(self.error)
        return SandboxResult(
            build=StepResult("build", CheckResult(self.build), command="pip install", exit_code=0 if self.build == "PASS" else 1),
            tests=StepResult("tests", CheckResult(self.tests), command="pytest", note="no test suite" if self.tests == "SKIPPED" else None),
            image="python:3.12-slim", logs="::step build start 1\n...", artifacts=self.artifacts,
        )

    def health(self):
        return True, "fake"


class FakeScanner:
    def __init__(self, status="PASS"):
        self.status = status

    def scan(self, workspace_path, ecosystem, package_name, new_version, *, dependency_file=None):
        from app.services.sandbox.security_scan import SecurityScanResult

        return SecurityScanResult(status=CheckResult(self.status), target_version_found=new_version, provider_available=self.status != "UNKNOWN")


@pytest.fixture
def remediation(db, tmp_path):
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
                      proposed_change={"file": "requirements.txt", "workspace_path": str(ws), "diff": "-requests==2.30.0\n+requests==2.33.0"})
    db.add(rem)
    db.commit()
    return rem


def validation_service(db, tmp_path, sandbox, scanner):
    return ValidationService(db, settings(tmp_path), sandbox=sandbox, scanner=scanner)


def test_validation_pass_writes_logs_and_marks_remediation_validated(db, tmp_path, remediation):
    svc = validation_service(db, tmp_path, FakeSandbox(), FakeScanner())
    validation = svc.validate(remediation.remediation_id)
    assert validation.status == ValidationStatus.COMPLETED and validation.overall_result == CheckResult.PASS
    assert (validation.build_status, validation.test_status, validation.security_scan_status) == ("PASS", "PASS", "PASS")
    assert Path(validation.logs_path).is_file() and "::step build" in svc.read_logs(validation)
    assert remediation.status == RemediationStatus.VALIDATED
    assert validation.details["image"] == "python:3.12-slim"


def test_validation_with_skipped_tests_passes_with_warning(db, tmp_path, remediation):
    validation = validation_service(db, tmp_path, FakeSandbox(tests="SKIPPED"), FakeScanner()).validate(remediation.remediation_id)
    assert validation.overall_result == CheckResult.PASS and validation.test_status == "SKIPPED"
    assert any("skipped" in w.lower() for w in validation.details["warnings"])


@pytest.mark.parametrize("sandbox,scanner,expected", [
    (FakeSandbox(build="FAIL", tests="SKIPPED"), FakeScanner(), "FAIL"),
    (FakeSandbox(tests="FAIL"), FakeScanner(), "FAIL"),
    (FakeSandbox(), FakeScanner("FAIL"), "FAIL"),
    (FakeSandbox(), FakeScanner("UNKNOWN"), "UNKNOWN"),
])
def test_validation_failure_rules(db, tmp_path, remediation, sandbox, scanner, expected):
    validation = validation_service(db, tmp_path, sandbox, scanner).validate(remediation.remediation_id)
    assert validation.overall_result == expected
    assert remediation.status == RemediationStatus.VALIDATION_FAILED


def test_sandbox_infrastructure_error_marks_validation_failed_and_unknown(db, tmp_path, remediation):
    validation = validation_service(db, tmp_path, FakeSandbox(error="Docker daemon unreachable"), FakeScanner()).validate(remediation.remediation_id)
    assert validation.status == ValidationStatus.FAILED and validation.overall_result == CheckResult.UNKNOWN
    assert validation.build_status == "UNKNOWN" and "Docker" in validation.error_message


def test_artifacts_are_copied_back_into_the_workspace(db, tmp_path, remediation):
    sandbox = FakeSandbox(artifacts={"package-lock.json": '{"lockfileVersion": 3}'})
    validation = validation_service(db, tmp_path, sandbox, FakeScanner()).validate(remediation.remediation_id)
    ws = Path(remediation.proposed_change["workspace_path"])
    assert (ws / "package-lock.json").read_text() == '{"lockfileVersion": 3}'
    assert "package-lock.json" in validation.details["artifacts_written"]


def test_non_proposed_remediation_is_refused(db, tmp_path, remediation):
    remediation.status = RemediationStatus.FAILED
    db.commit()
    with pytest.raises(ValidationFailedError):
        validation_service(db, tmp_path, FakeSandbox(), FakeScanner()).start(remediation.remediation_id)
