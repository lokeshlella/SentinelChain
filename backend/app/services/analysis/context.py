"""Builds the evidence-only ``FindingContext`` handed to the AI agents from stored data.

Shared by the analysis pipeline (during a run) and the remediation service
(later, on demand). Nothing here is inferred: every field is read from rows
that were produced by the repository analyser, OSV or the knowledge graph.
"""

from __future__ import annotations

from app.core.logging import get_stage_logger
from app.core.versions import normalize_package_name
from app.models import Finding, Vulnerability
from app.services.agents.schemas import (
    DependencyContext,
    FindingContext,
    GraphContext,
    RepositoryContext,
    UsageContext,
    VulnerabilityContext,
)
from app.services.analysis.usage import UsageEvidence, usage_verdict
from app.services.repository.analyzer import RepositoryProfile

log = get_stage_logger("AI")


def fixed_versions_for(vuln: Vulnerability, ecosystem: str, package_name: str) -> list[str]:
    """Fixed versions recorded for ``package_name`` in the stored ``affected`` JSON."""
    wanted = normalize_package_name(package_name, ecosystem)
    out: list[str] = []
    for pkg in vuln.affected or []:
        if not isinstance(pkg, dict) or pkg.get("ecosystem") != ecosystem:
            continue
        if normalize_package_name(str(pkg.get("package_name", "")), ecosystem) != wanted:
            continue
        out.extend(v for v in pkg.get("fixed_versions", []) if v not in out)
    return out


def vulnerability_context(vuln: Vulnerability, ecosystem: str, package_name: str) -> VulnerabilityContext:
    return VulnerabilityContext(
        identifier=vuln.identifier,
        aliases=list(vuln.aliases or []),
        severity=vuln.severity,
        cvss_score=vuln.cvss_score,
        summary=vuln.summary,
        description=(vuln.description or "")[:1500] or None,
        fixed_versions=fixed_versions_for(vuln, ecosystem, package_name),
        reference_url=vuln.reference_url,
    )


def build_finding_context(finding: Finding, graph_service) -> FindingContext:
    """``graph_service`` must expose ``dependency_context(dep) -> GraphContext``."""
    dep = finding.dependency
    vuln = finding.vulnerability
    repository = finding.analysis.repository
    profile = RepositoryProfile.from_dict(repository.profile or {})
    usage_ctx = (
        UsageEvidence.from_dict(finding.usage_evidence).to_context()
        if finding.usage_evidence
        else UsageContext(components=list(finding.affected_components or []))
    )
    verdict = usage_verdict(finding.usage_evidence, dep.direct_or_transitive)
    usage_ctx.verdict_kind, usage_ctx.verdict = verdict.kind, verdict.message
    try:
        graph_ctx = graph_service.dependency_context(dep) if graph_service is not None else GraphContext(available=False)
    except Exception as exc:  # noqa: BLE001 - the graph is optional evidence
        log.warning("Graph context unavailable for dependency %d: %s", dep.dependency_id, exc)
        graph_ctx = GraphContext(available=False)
    return FindingContext(
        repository=RepositoryContext(
            name=repository.name,
            language=repository.language,
            source_type=repository.source_type,
            components=[c.path for c in repository.components],
            dependency_files=list(profile.dependency_files),
        ),
        dependency=DependencyContext(
            package_name=dep.package_name,
            ecosystem=dep.ecosystem,
            version=dep.version,
            version_spec=dep.version_spec,
            scope=dep.direct_or_transitive,
            source_file=dep.source_file,
        ),
        vulnerability=vulnerability_context(vuln, dep.ecosystem, dep.package_name),
        usage=usage_ctx,
        graph=graph_ctx,
    )
