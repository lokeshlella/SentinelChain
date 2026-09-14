"""Pull-request generation from a validated remediation workspace.

Creates the PR record first, then asks the ``GitProvider`` to branch / commit /
push / open a DRAFT PR. Without credentials the record still carries the full
title, description and manual instructions ("GitHub PR creation unavailable").
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.exceptions import ConflictError, NotFoundError, ValidationFailedError
from app.core.logging import get_stage_logger
from app.core.paths import resolve_workspace_path
from app.models import PullRequest, Remediation, Validation
from app.models.enums import CheckResult, PullRequestStatus, RemediationStatus, ValidationStatus
from app.services.github.base import GitProvider, PullRequestResult, PullRequestSpec
from app.services.github.github_provider import GitHubProvider
from app.services.github.instructions import build_manual_instructions
from app.services.sandbox.service import is_partial_pass

log = get_stage_logger("GitHub")

FOOTER = "🤖 Generated with Sentinel Chain — draft pull request, review required. Never auto-merged."


class PullRequestService:
    def __init__(
        self,
        db: Session,
        settings: Settings | None = None,
        *,
        provider: GitProvider | None = None,
        report_service=None,
    ) -> None:
        self.db = db
        self.settings = settings or get_settings()
        self.provider = provider or GitHubProvider(self.settings.github_token)
        self._report_service = report_service

    # ------------------------------------------------------------------ public API

    def create(self, remediation_id: int, *, force: bool = False) -> PullRequest:
        remediation = self._get_remediation(remediation_id)
        validation = self._require_validation(remediation, force)
        finding = remediation.finding
        dependency = finding.dependency
        repository = finding.analysis.repository
        change = remediation.proposed_change or {}
        workspace = resolve_workspace_path(str(change.get("workspace_path") or ""), self.settings) or Path("")

        title = build_pr_title(dependency.package_name, remediation.current_version, remediation.recommended_version, finding.vulnerability.identifier)
        branch = build_branch_name(dependency.ecosystem, dependency.package_name, remediation.recommended_version)
        report_json, report_md, report_paths = self._evidence(finding.finding_id, remediation.remediation_id)
        body = build_pr_body(remediation, validation, report_paths.get("markdown"))
        changed_files = self._changed_files(workspace, change)

        pr = PullRequest(
            remediation_id=remediation.remediation_id,
            title=title,
            body=body,
            branch_name=branch,
            evidence=report_json,
            review_status=PullRequestStatus.UNAVAILABLE,
        )
        self.db.add(pr)
        self.db.commit()
        log.info("Pull request %d prepared for remediation %d (branch %s)", pr.pr_id, remediation.remediation_id, branch)

        spec = PullRequestSpec(
            workspace_path=workspace,
            base_branch=repository.branch or "main",
            head_branch=branch,
            title=title,
            body=body,
            commit_message=f"{title}\n\n{FOOTER}",
            changed_files=changed_files,
            repo_full_name=_github_full_name(repository),
            draft=True,
        )
        result = self._run_provider(spec, workspace, changed_files, title, report_paths.get("markdown"))
        pr.review_status = result.status
        pr.pr_url = result.url
        pr.pr_number = result.number
        pr.instructions = result.instructions
        pr.error_message = result.error
        if result.status in (PullRequestStatus.DRAFT, PullRequestStatus.OPEN):
            remediation.status = RemediationStatus.PR_CREATED
            log.info("Draft pull request created: %s", result.url)
        else:
            log.warning("GitHub PR creation %s: %s", result.status.lower(), result.error or result.instructions)
        self.db.commit()
        return pr

    def get(self, pr_id: int) -> PullRequest:
        pr = self.db.get(PullRequest, pr_id)
        if pr is None:
            raise NotFoundError(f"Pull request {pr_id} not found")
        return pr

    def list(self) -> list[PullRequest]:
        return list(self.db.scalars(select(PullRequest).order_by(PullRequest.pr_id.desc())))

    def list_for_remediation(self, remediation_id: int) -> list[PullRequest]:
        return list(self.db.scalars(select(PullRequest).where(PullRequest.remediation_id == remediation_id).order_by(PullRequest.pr_id)))

    # ------------------------------------------------------------------ steps

    def _get_remediation(self, remediation_id: int) -> Remediation:
        remediation = self.db.get(Remediation, remediation_id)
        if remediation is None:
            raise NotFoundError(f"Remediation {remediation_id} not found")
        change = remediation.proposed_change or {}
        if not change.get("file") or not change.get("workspace_path"):
            raise ValidationFailedError(f"Remediation {remediation_id} has no proposed change to publish")
        if not (resolve_workspace_path(str(change["workspace_path"]), self.settings) or Path("")).is_dir():
            raise ValidationFailedError(
                f"Remediation {remediation_id}: working copy is missing; re-run the remediation and validation"
            )
        return remediation

    def _require_validation(self, remediation: Remediation, force: bool) -> Validation:
        validation = self.db.scalar(
            select(Validation)
            .where(Validation.remediation_id == remediation.remediation_id, Validation.status == ValidationStatus.COMPLETED)
            .order_by(Validation.validation_id.desc())
            .limit(1)
        )
        if validation is None:
            raise ValidationFailedError(
                f"Remediation {remediation.remediation_id} has not been validated; validate it in the sandbox first",
                details={"remediation_id": remediation.remediation_id},
            )
        partial = is_partial_pass(validation.build_status, validation.test_status, validation.security_scan_status)
        if validation.overall_result != CheckResult.PASS and not partial and not force:
            raise ConflictError(
                f"Validation {validation.validation_id} result is {validation.overall_result}; "
                "pass force=true to open a pull request anyway",
                details={"validation_id": validation.validation_id, "overall_result": validation.overall_result},
            )
        return validation

    def _evidence(self, finding_id: int, remediation_id: int) -> tuple[dict[str, Any] | None, str | None, dict[str, str]]:
        """Evidence report JSON + markdown; failures degrade to None (the PR still gets created)."""
        try:
            service = self._report_service or _default_report_service(self.db)
            report = service.build(finding_id, remediation_id)
            directory = self.settings.workspace_path / "reports" / str(remediation_id)
            paths = service.write_report(report, directory)
            return service.to_json(report), service.to_markdown(report), paths
        except Exception as exc:  # noqa: BLE001 - the report is supporting evidence, not a blocker
            log.warning("Evidence report unavailable for remediation %d: %s", remediation_id, exc)
            return {"error": f"Evidence report unavailable: {exc}"}, None, {}

    def _run_provider(self, spec: PullRequestSpec, workspace: Path, files: list[str], title: str, body_file: str | None) -> PullRequestResult:
        if not self.provider.is_configured():
            return PullRequestResult(
                status=PullRequestStatus.UNAVAILABLE,
                branch=spec.head_branch,
                instructions=build_manual_instructions(
                    workspace_path=workspace, branch=spec.head_branch, changed_files=files, title=title,
                    body_file=body_file, reason="GITHUB_TOKEN is not configured",
                ),
                error="GitHub PR creation unavailable: GITHUB_TOKEN is not configured",
            )
        try:
            return self.provider.create_pull_request(spec)
        except Exception as exc:  # noqa: BLE001 - provider bugs must not lose the prepared PR
            log.exception("Git provider crashed")
            return PullRequestResult(
                status=PullRequestStatus.FAILED,
                branch=spec.head_branch,
                error=f"GitHub PR creation failed: {exc}",
                instructions=build_manual_instructions(
                    workspace_path=workspace, branch=spec.head_branch, changed_files=files, title=title,
                    body_file=body_file, reason=str(exc), failed=True,
                ),
            )

    @staticmethod
    def _changed_files(workspace: Path, change: dict) -> list[str]:
        files = [str(change["file"])]
        lock = Path(str(change["file"])).parent / "package-lock.json"
        if str(change["file"]).endswith("package.json") and (workspace / lock).is_file():
            files.append(lock.as_posix())
        return files


# ---------------------------------------------------------------------- pure builders


def build_pr_title(package: str, current: str | None, recommended: str | None, vulnerability_id: str) -> str:
    title = f"Sentinel Chain: bump {package} {current or '?'} → {recommended or '?'} ({vulnerability_id})"
    return title[:200]


def build_branch_name(ecosystem: str, package: str, version: str | None) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", package).strip("-.") or "package"
    ver = re.sub(r"[^A-Za-z0-9._-]+", "-", version or "fix").strip("-.")
    return f"sentinel-chain/{ecosystem.lower()}-{slug}-{ver}"


def build_pr_body(remediation: Remediation, validation: Validation, report_path: str | None) -> str:
    finding = remediation.finding
    dependency = finding.dependency
    vuln = finding.vulnerability
    ai = finding.ai_results or {}
    impact = ai.get("impact") or {}
    risk = ai.get("risk") or {}
    change = remediation.proposed_change or {}
    details = validation.details or {}
    warnings = details.get("warnings") or []
    aliases = ", ".join(vuln.aliases or []) or "none"
    cvss = f"{vuln.cvss_score} ({vuln.cvss_vector})" if vuln.cvss_score is not None else "not available"

    lines = [
        "## Summary",
        f"Sentinel Chain proposes upgrading **{dependency.package_name}** from `{remediation.current_version}` to "
        f"`{remediation.recommended_version}` in `{dependency.source_file}` to fix **{vuln.identifier}**. "
        "The change was applied to a temporary working copy and validated in an isolated Docker sandbox.",
        "",
        "## Vulnerability",
        f"- **Identifier:** {vuln.identifier} (aliases: {aliases})",
        f"- **Severity:** {vuln.severity} — CVSS {cvss}",
        f"- **Summary:** {vuln.summary or 'n/a'}",
        f"- **Reference:** {vuln.reference_url or 'n/a'}",
        "",
        "## Dependency",
        f"- **Package:** {dependency.package_name} ({dependency.ecosystem})",
        f"- **Version:** `{remediation.current_version}` → `{remediation.recommended_version}`",
        f"- **Declared in:** `{dependency.source_file}`"
        + (f" ({dependency.direct_or_transitive} dependency)" if dependency.direct_or_transitive in ("direct", "transitive") else ""),
        "",
        "## Application impact",
    ]
    if impact:
        lines.append(f"- **Impact level (AI inference):** {impact.get('impact_level')}")
        lines.append(f"- **Affected components (observed):** {', '.join(finding.affected_components or []) or 'none observed'}")
        lines += [f"- {_labelled('FACT', f)}" for f in impact.get("facts", [])[:6]]
        lines += [f"- {_labelled('INFERENCE', i)}" for i in impact.get("inferences", [])[:6]]
    else:
        lines.append(f"- AI impact assessment not available ({finding.ai_status}). Observed affected components: "
                     f"{', '.join(finding.affected_components or []) or 'none observed'}")
    lines += ["", "## Risk"]
    if risk:
        lines.append(f"- **Risk level (AI inference):** {risk.get('risk_level')} — {risk.get('reasoning', '')}")
        lines += [f"- {f}" for f in risk.get("factors", [])[:6]]
    else:
        lines.append(f"- **Risk level (provisional, severity-based):** {finding.risk_level}")
    lines += [
        "",
        "## Validation (Docker sandbox)",
        f"- **Build / install:** {validation.build_status}",
        f"- **Tests:** {validation.test_status}"
        + (" — no test suite was detected; the change is **not** behaviourally verified, test it manually before merging"
           if validation.test_status == CheckResult.SKIPPED else ""),
        f"- **Security scan (OSV on the new version):** {validation.security_scan_status}",
        f"- **Overall:** {validation.overall_result}"
        + (" (partially validated: install and security scan passed, tests skipped)"
           if is_partial_pass(validation.build_status, validation.test_status, validation.security_scan_status) else ""),
    ]
    lines += [f"- Warning: {w}" for w in warnings]
    lines += ["", "## Remediation rationale", remediation.recommendation or "n/a", "", "## Proposed change", f"```diff\n{change.get('diff', '')}\n```"]
    if report_path:
        lines += ["", f"Full evidence report: `{report_path}`"]
    lines += [
        "",
        "## Reviewer checklist",
        "- [ ] The upgrade is compatible with how the application uses the package",
        "- [ ] CI passes on this branch",
        "- [ ] Changelog / release notes of the new version were reviewed",
        "",
        FOOTER,
    ]
    return "\n".join(lines)


def _labelled(label: str, text: str) -> str:
    """Prefix with FACT:/INFERENCE: unless the model already did."""
    stripped = str(text).strip()
    return stripped if stripped.upper().startswith(("FACT:", "INFERENCE:")) else f"{label}: {stripped}"


def _github_full_name(repository) -> str | None:
    from app.services.repository.github_provider import parse_github_remote

    return parse_github_remote(repository.source_url) if repository.source_type == "github" else None


def _default_report_service(db: Session):
    from app.services.reports.service import ReportService

    return ReportService(db)
