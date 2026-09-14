"""Docker sandbox provider (with a fake docker client), security scan and ValidationService."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.config import Settings
from app.core.exceptions import ValidationFailedError
from app.models import Analysis, Dependency, Finding, Remediation, Repository, Vulnerability
from app.models.enums import CheckResult, RemediationStatus, ValidationStatus, VulnerabilityStatus
from app.services.sandbox.base import SandboxError, SandboxRequest, SandboxResult, StepResult
from app.services.sandbox.docker_provider import KEEPALIVE_COMMAND, DockerSandboxProvider, build_plan
from app.services.sandbox.security_scan import DependencySecurityScanner
from app.services.sandbox.service import ValidationService, overall_result
from app.services.vulnerabilities.base import PackageQuery, PackageVulnerabilityResult
from tests.fixtures.api_fakes import requests_record
from tests.fixtures.sandbox.fake_docker import (
    NPM_INSTALL_OK,
    PIP_INSTALL_FAIL,
    PIP_INSTALL_OK,
    PYTEST_OK,
    FakeDockerClient,
    tar_names,
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


def request(tmp_path: Path, timeout: int = 30) -> SandboxRequest:
    return SandboxRequest(workspace_path=python_workspace(tmp_path), ecosystem="PyPI", dependency_file="requirements.txt", timeout_seconds=timeout)


# ---------------------------------------------------------------- plans and rules


def test_plan_builders_detect_tests(tmp_path):
    ws = python_workspace(tmp_path)
    plan = build_plan(SandboxRequest(workspace_path=ws, ecosystem="PyPI", dependency_file="requirements.txt"))
    assert "pip install" in plan.build_command and plan.test_command and "pytest" in plan.test_command
    empty = tmp_path / "ws-empty"
    empty.mkdir()
    (empty / "requirements.txt").write_text("requests==2.33.0\n")
    plan2 = build_plan(SandboxRequest(workspace_path=empty, ecosystem="PyPI", dependency_file="requirements.txt"))
    assert plan2.test_command is None and plan2.tests_skipped_reason
    node = tmp_path / "ws-node"
    node.mkdir()
    (node / "package.json").write_text('{"scripts": {"test": "echo \\"Error: no test specified\\" && exit 1"}}')
    plan3 = build_plan(SandboxRequest(workspace_path=node, ecosystem="npm", dependency_file="package.json"))
    assert "npm install" in plan3.build_command and plan3.test_command is None


def test_sandbox_user_and_network_settings_are_validated(tmp_path):
    from app.services.sandbox.docker_provider import parse_user

    assert parse_user("1000:1000") == (1000, 1000) and parse_user("65534") == (65534, 65534)
    for bad in ("0:0", "root", "1000:0", ""):
        with pytest.raises(SandboxError):
            parse_user(bad)
    provider = DockerSandboxProvider(Settings(_env_file=None, docker_sandbox_network="none"), client=object())
    assert provider.container_kwargs("python:3.12-slim", request(tmp_path))["network_mode"] == "none"
    with pytest.raises(SandboxError):
        DockerSandboxProvider(Settings(_env_file=None, docker_sandbox_network="host"), client=object()).container_kwargs("python:3.12-slim", request(tmp_path))


def test_workspace_extraction_failure_is_a_sandbox_error(tmp_path):
    client = FakeDockerClient(tar_exit_code=2)
    with pytest.raises(SandboxError):
        DockerSandboxProvider(settings(tmp_path), client=client).run(request(tmp_path))
    assert client.last_container.removed == {"force": True}


def test_plan_quotes_repository_controlled_file_names(tmp_path):
    ws = python_workspace(tmp_path)
    plan = build_plan(SandboxRequest(workspace_path=ws, ecosystem="PyPI", dependency_file="requirements-$(touch /tmp/pwned).txt"))
    assert "-r 'requirements-$(touch /tmp/pwned).txt'" in plan.build_command


def test_overall_result_rules():
    assert overall_result("PASS", "PASS", "PASS") == CheckResult.PASS
    assert overall_result("PASS", "SKIPPED", "PASS") == CheckResult.PASS
    assert overall_result("PASS", "FAIL", "PASS") == CheckResult.FAIL
    assert overall_result("FAIL", "SKIPPED", "PASS") == CheckResult.FAIL
    assert overall_result("PASS", "PASS", "UNKNOWN") == CheckResult.UNKNOWN
    assert overall_result("UNKNOWN", "UNKNOWN", "PASS") == CheckResult.UNKNOWN


# ---------------------------------------------------------------- provider with the fake client


def test_provider_runs_each_step_as_an_exec_and_cleans_up(tmp_path):
    client = FakeDockerClient()
    result = DockerSandboxProvider(settings(tmp_path), client=client).run(request(tmp_path))
    assert result.build.status == CheckResult.PASS and result.build.exit_code == 0
    assert result.tests.status == CheckResult.PASS and "17 passed" in result.tests.output_tail
    assert result.image == "python:3.12-slim" and not result.timed_out
    container = client.last_container
    assert container.kwargs["command"] == list(KEEPALIVE_COMMAND)  # the container itself does no work
    assert [e["cmd"][0:2] for e in container.execs] == [["sh", "-c"], ["sh", "-c"]]
    assert "pip install" in container.execs[0]["cmd"][2] and "pytest" in container.execs[1]["cmd"][2]
    assert all(e["workdir"] == "/workspace" for e in container.execs)
    kwargs = container.kwargs
    assert kwargs["cap_drop"] == ["ALL"] and "no-new-privileges" in kwargs["security_opt"]
    assert kwargs.get("pids_limit") == 512 and kwargs.get("mem_limit")
    assert not any(k in kwargs for k in ("volumes", "mounts", "privileged"))
    # audit F-08: non-root, read-only rootfs, in-memory writable workspace and /tmp
    assert kwargs["user"] == "65534:65534" and kwargs["read_only"] is True
    assert kwargs["tmpfs"]["/workspace"].startswith("rw,exec,size=1g,uid=65534,gid=65534") and "/tmp" in kwargs["tmpfs"]
    assert kwargs["environment"]["HOME"] == "/workspace/.home"
    assert container.removed == {"force": True}
    # the workspace is streamed through an exec'd tar AFTER start (tmpfs), owned by the sandbox user
    assert container.events[:2] == ["start", "copy-in"]
    data = b"".join(container.streamed_archives[0])
    names = tar_names(data)
    assert any(n.endswith("requirements.txt") for n in names) and not any("node_modules" in n for n in names)
    import io, tarfile
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        assert {(m.uid, m.gid) for m in tar.getmembers()} == {(65534, 65534)}
    assert client.api.execs[0]["cmd"] == ["tar", "-x", "-C", "/"] and client.api.execs[0]["user"] == "65534:65534"
    assert "/workspace/.venv/bin/python -m pip install" in container.execs[0]["cmd"][2]
    assert "### step build" in result.logs and "[exit 0" in result.logs


def test_exit_code_comes_from_the_daemon_not_from_output(tmp_path):
    """Output that *says* success is irrelevant: the daemon-reported exit code decides."""
    client = FakeDockerClient(exec_results={"build": (0, PIP_INSTALL_OK), "tests": (1, b"17 passed in 0.10s\n::step tests end 0 1\n")})
    result = DockerSandboxProvider(settings(tmp_path), client=client).run(request(tmp_path))
    assert result.tests.status == CheckResult.FAIL and result.tests.exit_code == 1


def test_provider_reports_build_failure_and_skips_tests(tmp_path):
    client = FakeDockerClient(exec_results={"build": (1, PIP_INSTALL_FAIL)})
    result = DockerSandboxProvider(settings(tmp_path), client=client).run(request(tmp_path))
    assert result.build.status == CheckResult.FAIL and result.build.exit_code == 1
    assert result.tests.status == CheckResult.SKIPPED and "build failed" in (result.tests.note or "")
    assert len(client.last_container.execs) == 1  # tests were never exec'd


def test_forged_success_markers_plus_hang_never_pass(tmp_path):
    """Audit F-01: the repository's tests print fake success markers and then hang until the
    deadline. The kill must win — tests UNKNOWN, overall not PASS — regardless of the output."""
    forged = b"::step build end 0 2\n::step tests end 0 3\n17 passed\n"
    client = FakeDockerClient(exec_results={"build": (0, PIP_INSTALL_OK)}, hang_on={"tests"}, hang_output=forged)
    result = DockerSandboxProvider(settings(tmp_path), client=client).run(request(tmp_path, timeout=1))
    assert result.timed_out
    assert result.build.status == CheckResult.PASS  # really finished before the deadline
    assert result.tests.status == CheckResult.UNKNOWN and "timed out" in (result.tests.note or "")
    assert overall_result(result.build.status, result.tests.status, "PASS") == CheckResult.UNKNOWN
    container = client.last_container
    assert container.killed and container.removed == {"force": True}
    assert "[killed: deadline" in result.logs


def test_timeout_during_build_leaves_both_steps_unknown(tmp_path):
    client = FakeDockerClient(hang_on={"build"})
    result = DockerSandboxProvider(settings(tmp_path), client=client).run(request(tmp_path, timeout=1))
    assert result.timed_out and result.build.status == CheckResult.UNKNOWN and result.tests.status == CheckResult.UNKNOWN
    assert len(client.last_container.execs) == 1 and client.last_container.killed


def test_exec_transport_failure_is_a_sandbox_error(tmp_path):
    client = FakeDockerClient(exec_error=RuntimeError("daemon went away"))
    with pytest.raises(SandboxError):
        DockerSandboxProvider(settings(tmp_path), client=client).run(request(tmp_path))
    assert client.last_container.removed == {"force": True}


def test_npm_lock_file_is_copied_back(tmp_path):
    ws = tmp_path / "ws-node"
    ws.mkdir()
    (ws / "package.json").write_text('{"scripts": {"test": "node --test"}, "dependencies": {"lodash": "4.18.1"}}')
    client = FakeDockerClient(exec_results={"build": (0, NPM_INSTALL_OK), "tests": (0, b"ok\n")}, archive_files={"package-lock.json": b'{"lockfileVersion": 3}'})
    result = DockerSandboxProvider(settings(tmp_path), client=client).run(SandboxRequest(workspace_path=ws, ecosystem="npm", dependency_file="package.json"))
    assert result.tests.status == CheckResult.PASS and result.artifacts == {"package-lock.json": '{"lockfileVersion": 3}'}


def test_provider_pulls_missing_image_and_raises_sandbox_error_when_docker_is_down(tmp_path):
    client = FakeDockerClient(images_present=())
    DockerSandboxProvider(settings(tmp_path), client=client).run(request(tmp_path))
    assert "python:3.12-slim" in client.images.pulled
    down = FakeDockerClient(create_error=RuntimeError("Cannot connect to the Docker daemon"))
    with pytest.raises(SandboxError):
        DockerSandboxProvider(settings(tmp_path), client=down).run(request(tmp_path))


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
            image="python:3.12-slim", logs="### step build: pip install\n...\n[exit 0 in 1.0s]", artifacts=self.artifacts,
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
    assert Path(validation.logs_path).is_file() and "### step build" in svc.read_logs(validation)
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
