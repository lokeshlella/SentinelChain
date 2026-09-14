"""Security scan V1: verify that the proposed dependency state no longer contains the vulnerability.

The scanner re-reads the dependency files of the modified working copy (so it checks what
is actually written there, not what the remediation *intended* to write), confirms the target
package now carries the recommended version and asks the vulnerability provider (OSV) about
that exact version.

* PASS     — the manifest pins the new version and the provider knows no vulnerability for it.
* FAIL     — the manifest does not contain the expected version, or the new version is still
             affected by known vulnerabilities (their ids are listed).
* UNKNOWN  — the provider could not answer (``provider_available=False``), the version cannot
             be checked, or the workspace could not be read; never PASS in that case.

Only the target package is verified in V1 (``other_vulnerable`` stays empty and a note says
so); re-scanning every dependency would mean one OSV query per package and belongs to a
later version together with Trivy / Semgrep style scanners.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from app.core.exceptions import SentinelError
from app.core.logging import get_stage_logger
from app.core.versions import compare_versions, is_valid_version, normalize_package_name
from app.models.enums import CheckResult, VulnerabilityStatus
from app.services.dependencies.base import ExtractedDependency
from app.services.dependencies.service import DependencyService

log = get_stage_logger("Sandbox")

LOCK_FILE_NAMES: frozenset[str] = frozenset({"package-lock.json", "npm-shrinkwrap.json"})
OTHER_DEPENDENCIES_NOTE = "other dependencies are not re-scanned in V1"
MANIFEST_MISMATCH_NOTE = "manifest does not contain the expected version"

_RANGE_PREFIX_RE = re.compile(r"^[\s=v^~<>!]*")


@dataclass
class SecurityScanResult:
    status: CheckResult
    target_version_found: str | None = None
    target_vulnerabilities: list[str] = field(default_factory=list)
    other_vulnerable: list[dict[str, Any]] = field(default_factory=list)  # [{package, version, vulnerabilities}]
    provider_available: bool = True  # False only when the vulnerability provider could not answer
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": str(self.status),
            "target_version_found": self.target_version_found,
            "target_vulnerabilities": list(self.target_vulnerabilities),
            "other_vulnerable": [dict(item) for item in self.other_vulnerable],
            "provider_available": self.provider_available,
            "notes": list(self.notes),
        }


class DependencySecurityScanner:
    """Checks the target package of a proposed change against the vulnerability provider."""

    def __init__(self, vulnerability_service, dependency_service: DependencyService | None = None) -> None:
        self.vulnerabilities = vulnerability_service
        self.dependencies = dependency_service or DependencyService()

    def scan(
        self,
        workspace_path: Path | str,
        ecosystem: str,
        package_name: str,
        new_version: str,
        *,
        dependency_file: str | None = None,
    ) -> SecurityScanResult:
        """Verify ``package_name`` is at ``new_version`` in ``workspace_path`` and that version is not vulnerable.

        ``dependency_file`` (relative path of the modified manifest) is preferred when the
        package appears in several files.
        """
        result = SecurityScanResult(status=CheckResult.UNKNOWN, notes=[OTHER_DEPENDENCIES_NOTE])
        target = self._find_target(workspace_path, ecosystem, package_name, dependency_file, result)
        if target is None:
            return self._log(result, package_name, new_version)
        version = self._verified_version(target, new_version, ecosystem, result)
        if version is None:
            return self._log(result, package_name, new_version)
        self._check_provider(ecosystem, package_name, version, result)
        return self._log(result, package_name, new_version)

    # ------------------------------------------------------------------ steps

    def _find_target(
        self, workspace_path: Path | str, ecosystem: str, package_name: str, dependency_file: str | None, result: SecurityScanResult
    ) -> ExtractedDependency | None:
        try:
            extraction = self.dependencies.extract(workspace_path)
        except SentinelError as exc:
            result.notes.append(f"dependency files could not be read from the workspace: {exc.message}")
            return None
        except Exception as exc:  # noqa: BLE001 - extraction bugs must not crash the validation
            result.notes.append(f"dependency extraction failed: {exc}")
            return None
        wanted = normalize_package_name(package_name, ecosystem)
        matches = [
            dep
            for dep in extraction.dependencies
            if str(dep.ecosystem) == ecosystem and normalize_package_name(dep.package_name, ecosystem) == wanted
        ]
        if not matches:
            result.status = CheckResult.FAIL
            result.notes.append(f"{MANIFEST_MISMATCH_NOTE}: {package_name} is not declared in any {ecosystem} dependency file")
            return None
        return _prefer_manifest_entry(matches, dependency_file)

    @staticmethod
    def _verified_version(dep: ExtractedDependency, new_version: str, ecosystem: str, result: SecurityScanResult) -> str | None:
        """The version to check, or None (status already set) when the manifest disagrees with the change."""
        found = dep.version
        result.target_version_found = found if found is not None else dep.version_spec
        if found is not None:
            if _same_version(found, new_version, ecosystem):
                return new_version
            result.status = CheckResult.FAIL
            result.notes.append(f"{MANIFEST_MISMATCH_NOTE}: found {found} in {dep.source_file}, expected {new_version}")
            return None
        # No concrete version (a range without a lock file): accept a range whose base is the new version.
        base = _range_base(dep.version_spec)
        if base and _same_version(base, new_version, ecosystem):
            result.notes.append(
                f"{dep.source_file} declares the range {dep.version_spec!r}; no lock file resolved the installed "
                f"version, so the range minimum {new_version} was checked"
            )
            return new_version
        result.status = CheckResult.FAIL
        result.notes.append(
            f"{MANIFEST_MISMATCH_NOTE}: {dep.source_file} declares {dep.version_spec or 'no version'}, expected {new_version}"
        )
        return None

    def _check_provider(self, ecosystem: str, package_name: str, version: str, result: SecurityScanResult) -> None:
        try:
            answer = self.vulnerabilities.check_package(ecosystem, package_name, version)
        except Exception as exc:  # noqa: BLE001 - never PASS on a provider crash
            result.status = CheckResult.UNKNOWN
            result.provider_available = False
            result.notes.append(f"Vulnerability check unavailable: {exc}")
            return
        if answer.status == VulnerabilityStatus.SAFE and not answer.vulnerabilities:
            result.status = CheckResult.PASS
            result.notes.append(f"{package_name} {version}: no known vulnerabilities")
        elif answer.status == VulnerabilityStatus.VULNERABLE or answer.vulnerabilities:
            result.status = CheckResult.FAIL
            result.target_vulnerabilities = [rec.identifier for rec in answer.vulnerabilities]
            result.notes.append(
                f"{package_name} {version} is still affected by {len(result.target_vulnerabilities)} known "
                f"vulnerabilit{'y' if len(result.target_vulnerabilities) == 1 else 'ies'}"
            )
        else:
            result.status = CheckResult.UNKNOWN
            result.provider_available = False
            result.notes.append(answer.reason or "Vulnerability check unavailable")

    @staticmethod
    def _log(result: SecurityScanResult, package_name: str, new_version: str) -> SecurityScanResult:
        log.info(
            "Security scan for %s %s: %s (found %s, %d vulnerabilities, provider %s)",
            package_name, new_version, result.status, result.target_version_found,
            len(result.target_vulnerabilities), "available" if result.provider_available else "unavailable",
        )
        return result


# ---------------------------------------------------------------------- helpers


def _prefer_manifest_entry(matches: list[ExtractedDependency], dependency_file: str | None) -> ExtractedDependency:
    """The entry from the modified file if present, else any manifest entry, else the first (lock) entry."""
    if dependency_file:
        wanted = PurePosixPath(dependency_file).as_posix()
        for dep in matches:
            if PurePosixPath(dep.source_file).as_posix() == wanted:
                return dep
    for dep in matches:
        if PurePosixPath(dep.source_file).name not in LOCK_FILE_NAMES:
            return dep
    return matches[0]


def _same_version(a: str, b: str, ecosystem: str) -> bool:
    a, b = a.strip(), b.strip()
    if a == b:
        return True
    if is_valid_version(a, ecosystem) and is_valid_version(b, ecosystem):
        return compare_versions(a, b, ecosystem) == 0
    return False


def _range_base(spec: str | None) -> str | None:
    """``^4.18.0`` / ``~4.18.0`` / ``>=4.18.0`` / ``==4.18.0`` -> ``4.18.0``; None for complex specs."""
    if not spec:
        return None
    base = _RANGE_PREFIX_RE.sub("", spec.strip())
    if not base or any(ch in base for ch in " ,|<>=&"):
        return None
    return base


__all__ = ["DependencySecurityScanner", "SecurityScanResult", "OTHER_DEPENDENCIES_NOTE", "MANIFEST_MISMATCH_NOTE"]
