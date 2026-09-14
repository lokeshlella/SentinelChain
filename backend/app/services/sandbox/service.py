"""Validation stage: runs a proposed dependency change through the sandbox and the security scan.

Lifecycle of a ``Validation`` row::

    start(remediation_id)  -> PENDING   (remediation becomes VALIDATING)
    run(validation_id)     -> RUNNING -> COMPLETED | FAILED
    validate(remediation_id) = start + run (used by the background task)

Result rules (never invent a result):

* ``build_status`` / ``test_status`` come from the sandbox step markers (PASS / FAIL /
  SKIPPED / UNKNOWN), ``security_scan_status`` from :class:`DependencySecurityScanner`.
* ``overall_result``: FAIL when any check FAILed; UNKNOWN when the build, the tests or the
  security scan could not be evaluated (UNKNOWN); PASS otherwise. Tests SKIPPED do not
  block a PASS but are recorded in ``details.warnings`` so the report says
  "Apply with manual testing".
* Sandbox infrastructure errors (Docker unavailable, image cannot be pulled, ...) leave the
  row FAILED with ``error_message``; build and tests are UNKNOWN, the overall result UNKNOWN.
* The remediation becomes VALIDATED only for an overall PASS, VALIDATION_FAILED otherwise.
"""

from __future__ import annotations

import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.exceptions import NotFoundError, ValidationFailedError
from app.core.logging import get_stage_logger
from app.db.base import utcnow
from app.models import Remediation, Validation
from app.models.enums import CheckResult, RemediationStatus, ValidationStatus
from app.services.sandbox.base import SandboxError, SandboxProvider, SandboxRequest, SandboxResult, StepResult
from app.services.sandbox.docker_provider import DockerSandboxProvider
from app.services.sandbox.security_scan import DependencySecurityScanner, SecurityScanResult
from app.services.vulnerabilities.service import VulnerabilityService

log = get_stage_logger("Sandbox")

VALIDATABLE_STATUSES: frozenset[str] = frozenset(
    {RemediationStatus.PROPOSED, RemediationStatus.VALIDATED, RemediationStatus.VALIDATION_FAILED}
)
TESTS_SKIPPED_WARNING = "No test suite detected; tests were skipped"
LOGS_FILE_NAME = "logs.txt"


class ValidationService:
    """Creates and executes validations for proposed remediations."""

    def __init__(
        self,
        db: Session,
        settings: Settings | None = None,
        *,
        sandbox: SandboxProvider | None = None,
        scanner: DependencySecurityScanner | None = None,
        vulnerability_service=None,
    ) -> None:
        self.db = db
        self.settings = settings or get_settings()
        self.sandbox = sandbox or DockerSandboxProvider(self.settings)
        if scanner is None:
            vulnerability_service = vulnerability_service or VulnerabilityService(db, settings=self.settings)
            scanner = DependencySecurityScanner(vulnerability_service)
        self.scanner = scanner

    # ------------------------------------------------------------------ public API

    def start(self, remediation_id: int) -> Validation:
        """Create a PENDING validation for a remediation that carries a proposed change."""
        remediation = self._get_remediation(remediation_id)
        self._check_validatable(remediation)
        validation = Validation(
            remediation_id=remediation.remediation_id,
            status=ValidationStatus.PENDING,
            build_status=CheckResult.UNKNOWN,
            test_status=CheckResult.UNKNOWN,
            security_scan_status=CheckResult.UNKNOWN,
            overall_result=CheckResult.UNKNOWN,
        )
        remediation.status = RemediationStatus.VALIDATING
        self.db.add(validation)
        self.db.commit()
        log.info("Validation %d created for remediation %d", validation.validation_id, remediation.remediation_id)
        return validation

    def run(self, validation_id: int) -> Validation:
        """Execute a validation end to end and persist the outcome (never raises for check failures)."""
        validation = self.get(validation_id)
        remediation = validation.remediation
        validation.status = ValidationStatus.RUNNING
        validation.error_message = None
        self.db.commit()
        started = time.monotonic()
        log.info("Validation %d running for remediation %d", validation_id, remediation.remediation_id)
        try:
            self._execute(validation, remediation)
        except Exception as exc:  # noqa: BLE001 - a crash must leave an honest FAILED row, not a RUNNING one
            log.exception("Validation %d crashed", validation_id)
            self._fail(validation, f"{exc.__class__.__name__}: {exc}")
        validation.validated_at = utcnow()
        remediation.status = (
            RemediationStatus.VALIDATED if validation.overall_result == CheckResult.PASS else RemediationStatus.VALIDATION_FAILED
        )
        self.db.commit()
        log.info(
            "Validation %d %s in %.1fs: build %s, tests %s, security %s -> overall %s",
            validation_id, validation.status, time.monotonic() - started, validation.build_status,
            validation.test_status, validation.security_scan_status, validation.overall_result,
        )
        return validation

    def validate(self, remediation_id: int) -> Validation:
        return self.run(self.start(remediation_id).validation_id)

    def get(self, validation_id: int) -> Validation:
        validation = self.db.get(Validation, validation_id)
        if validation is None:
            raise NotFoundError(f"Validation {validation_id} not found")
        return validation

    def read_logs(self, validation: Validation) -> str:
        """The full sandbox log written for ``validation`` (an explanatory line when none exists)."""
        if not validation.logs_path:
            return f"No logs were recorded for validation {validation.validation_id} (status {validation.status})."
        path = Path(validation.logs_path)
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return f"Log file {path} could not be read: {exc}"

    # ------------------------------------------------------------------ execution

    def _execute(self, validation: Validation, remediation: Remediation) -> None:
        request = self._build_request(validation, remediation)
        dependency = remediation.finding.dependency
        new_version = remediation.recommended_version or ""
        warnings: list[str] = []
        sandbox_result, sandbox_error = self._run_sandbox(request)
        artifacts_written = self._write_artifacts(request.workspace_path, sandbox_result, warnings)
        scan = self._run_scan(request, dependency.package_name, new_version)
        logs_path = self._write_logs(validation, request, sandbox_result, sandbox_error, scan)

        build = sandbox_result.build if sandbox_result else _unknown_step("build", sandbox_error)
        tests = sandbox_result.tests if sandbox_result else _unknown_step("tests", sandbox_error)
        if tests.status == CheckResult.SKIPPED:
            warnings.append(_tests_skipped_warning(tests))
        if sandbox_result and sandbox_result.timed_out:
            warnings.append(f"Sandbox timed out after {request.timeout_seconds} s; the container was killed")
        if not scan.provider_available:
            warnings.append("Vulnerability provider unavailable; the security scan could not verify the new version")

        validation.build_status = build.status
        validation.test_status = tests.status
        validation.security_scan_status = scan.status
        validation.overall_result = overall_result(build.status, tests.status, scan.status)
        validation.logs_path = str(logs_path) if logs_path else None
        validation.details = {
            "image": sandbox_result.image if sandbox_result else self._image_name(request),
            "container_id": sandbox_result.container_id if sandbox_result else None,
            "steps": [_step_dict(build), _step_dict(tests)],
            "timed_out": bool(sandbox_result.timed_out) if sandbox_result else False,
            "security_scan": scan.to_dict(),
            "warnings": warnings,
            "artifacts_written": artifacts_written,
            "sandbox_error": sandbox_error,
            "request": {
                "ecosystem": request.ecosystem,
                "dependency_file": request.dependency_file,
                "workspace_path": str(request.workspace_path),
                "timeout_seconds": request.timeout_seconds,
                "package": dependency.package_name,
                "new_version": new_version,
            },
        }
        if sandbox_error:
            validation.status = ValidationStatus.FAILED
            validation.error_message = sandbox_error
        else:
            validation.status = ValidationStatus.COMPLETED

    def _run_sandbox(self, request: SandboxRequest) -> tuple[SandboxResult | None, str | None]:
        try:
            return self.sandbox.run(request), None
        except SandboxError as exc:
            log.error("Sandbox unavailable for %s: %s", request.workspace_path, exc)
            return None, str(exc)

    def _run_scan(self, request: SandboxRequest, package_name: str, new_version: str) -> SecurityScanResult:
        try:
            return self.scanner.scan(
                request.workspace_path, request.ecosystem, package_name, new_version, dependency_file=request.dependency_file
            )
        except Exception as exc:  # noqa: BLE001 - a scanner crash is UNKNOWN, never PASS
            log.exception("Security scan crashed for %s %s", package_name, new_version)
            return SecurityScanResult(
                status=CheckResult.UNKNOWN, provider_available=False, notes=[f"security scan crashed: {exc}"]
            )

    @staticmethod
    def _write_artifacts(workspace: Path, result: SandboxResult | None, warnings: list[str]) -> list[str]:
        """Copy files regenerated inside the sandbox (npm lock file) into the remediation workspace."""
        written: list[str] = []
        if result is None:
            return written
        for relative, content in result.artifacts.items():
            target = (workspace / relative).resolve()
            if workspace.resolve() not in target.parents:
                warnings.append(f"Artifact {relative} ignored: outside the workspace")
                continue
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
                written.append(relative)
            except OSError as exc:
                warnings.append(f"Artifact {relative} could not be written: {exc}")
        if written:
            log.info("%d artifact(s) copied back into %s: %s", len(written), workspace, ", ".join(written))
        return written

    def _write_logs(
        self,
        validation: Validation,
        request: SandboxRequest,
        result: SandboxResult | None,
        sandbox_error: str | None,
        scan: SecurityScanResult,
    ) -> Path | None:
        directory = self.settings.workspace_path / "validations" / str(validation.validation_id)
        path = directory / LOGS_FILE_NAME
        try:
            directory.mkdir(parents=True, exist_ok=True)
            path.write_text(_render_logs(validation, request, result, sandbox_error, scan), encoding="utf-8")
        except OSError as exc:
            log.warning("Could not write validation logs to %s: %s", path, exc)
            return None
        return path

    def _fail(self, validation: Validation, message: str) -> None:
        validation.status = ValidationStatus.FAILED
        validation.error_message = message
        validation.build_status = CheckResult.UNKNOWN
        validation.test_status = CheckResult.UNKNOWN
        validation.security_scan_status = CheckResult.UNKNOWN
        validation.overall_result = CheckResult.UNKNOWN
        details = dict(validation.details or {})
        details.setdefault("warnings", []).append(message)
        validation.details = details

    # ------------------------------------------------------------------ request building

    def _build_request(self, validation: Validation, remediation: Remediation) -> SandboxRequest:
        change = remediation.proposed_change or {}
        workspace = _workspace_of(change)
        dependency = remediation.finding.dependency
        repository = remediation.finding.analysis.repository
        profile = repository.profile or {}
        hints = dict(profile.get("hints") or {}) if isinstance(profile, dict) else {}
        return SandboxRequest(
            workspace_path=Path(workspace),
            ecosystem=dependency.ecosystem,
            dependency_file=str(change.get("file")),
            timeout_seconds=int(self.settings.docker_timeout),
            hints=hints,
            labels={
                "sentinel-chain.validation": str(validation.validation_id),
                "sentinel-chain.remediation": str(remediation.remediation_id),
            },
        )

    def _image_name(self, request: SandboxRequest) -> str | None:
        image_for = getattr(self.sandbox, "image_for", None)
        if image_for is None:
            return None
        try:
            return image_for(request.ecosystem)
        except SandboxError:
            return None

    # ------------------------------------------------------------------ preconditions

    def _get_remediation(self, remediation_id: int) -> Remediation:
        remediation = self.db.get(Remediation, remediation_id)
        if remediation is None:
            raise NotFoundError(f"Remediation {remediation_id} not found")
        return remediation

    @staticmethod
    def _check_validatable(remediation: Remediation) -> None:
        rid = remediation.remediation_id
        if remediation.status not in VALIDATABLE_STATUSES:
            raise ValidationFailedError(
                f"Remediation {rid} cannot be validated in status {remediation.status}; "
                f"expected one of {', '.join(sorted(VALIDATABLE_STATUSES))}",
                details={"remediation_id": rid, "status": remediation.status},
            )
        change = remediation.proposed_change or {}
        if not change.get("file"):
            raise ValidationFailedError(
                f"Remediation {rid} has no proposed change to validate", details={"remediation_id": rid}
            )
        workspace = _workspace_of(change)
        if not workspace or not Path(workspace).is_dir():
            raise ValidationFailedError(
                f"Remediation {rid} has no working copy on disk ({workspace or 'no workspace recorded'}); "
                "re-run the remediation to recreate it",
                details={"remediation_id": rid, "workspace": workspace},
            )
        if not (Path(workspace) / str(change["file"])).is_file():
            raise ValidationFailedError(
                f"Remediation {rid}: modified file {change['file']} is missing from the working copy",
                details={"remediation_id": rid, "file": change["file"]},
            )
        if not remediation.recommended_version:
            raise ValidationFailedError(
                f"Remediation {rid} has no recommended version to verify", details={"remediation_id": rid}
            )


# ---------------------------------------------------------------------- pure helpers


def overall_result(build: str, tests: str, security: str) -> CheckResult:
    """FAIL if any FAIL; UNKNOWN if build, tests or security is UNKNOWN; PASS otherwise (tests SKIPPED allowed)."""
    statuses = (build, tests, security)
    if CheckResult.FAIL in statuses:
        return CheckResult.FAIL
    if CheckResult.UNKNOWN in statuses:
        return CheckResult.UNKNOWN
    return CheckResult.PASS


def _workspace_of(change: dict[str, Any]) -> str | None:
    value = change.get("workspace_path") or change.get("workspace")
    return str(value) if value else None


def _tests_skipped_warning(tests: StepResult) -> str:
    """"No test suite" when the sandbox found none; otherwise the sandbox's own reason (e.g. build failed)."""
    if tests.note and "build failed" in tests.note:
        return f"Tests were skipped: {tests.note}"
    return TESTS_SKIPPED_WARNING


def _unknown_step(name: str, reason: str | None) -> StepResult:
    return StepResult(name=name, status=CheckResult.UNKNOWN, note=reason or "sandbox did not run")


def _step_dict(step: StepResult) -> dict[str, Any]:
    data = asdict(step)
    data["status"] = str(step.status)
    data["duration_seconds"] = round(float(step.duration_seconds or 0.0), 2)
    return data


def _render_logs(
    validation: Validation,
    request: SandboxRequest,
    result: SandboxResult | None,
    sandbox_error: str | None,
    scan: SecurityScanResult,
) -> str:
    lines = [
        f"# Sentinel Chain validation {validation.validation_id} (remediation {validation.remediation_id})",
        f"# ecosystem: {request.ecosystem}  dependency file: {request.dependency_file}",
        f"# workspace: {request.workspace_path}",
        f"# timeout: {request.timeout_seconds} s",
    ]
    if result is None:
        lines += ["", "## Sandbox", f"Sandbox did not run: {sandbox_error or 'unknown error'}"]
    else:
        lines += [
            f"# image: {result.image}  container: {result.container_id or '-'}  timed_out: {result.timed_out}",
            "",
            "## Steps",
        ]
        for step in (result.build, result.tests):
            lines.append(
                f"{step.name}: {step.status} (exit {step.exit_code if step.exit_code is not None else '-'}, "
                f"{step.duration_seconds:.1f}s) {step.command or ''}{f' -- {step.note}' if step.note else ''}"
            )
        lines += ["", "## Sandbox output", result.logs.rstrip("\n")]
    lines += ["", "## Security scan", f"status: {scan.status}"]
    lines += [f"- {note}" for note in scan.notes]
    if scan.target_vulnerabilities:
        lines.append(f"- vulnerabilities: {', '.join(scan.target_vulnerabilities)}")
    return "\n".join(lines) + "\n"


__all__ = ["ValidationService", "overall_result", "TESTS_SKIPPED_WARNING", "VALIDATABLE_STATUSES"]
