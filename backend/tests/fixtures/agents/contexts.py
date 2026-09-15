"""Builders for realistic FindingContext objects used by the agent tests.

The vulnerability text is copied from the real OSV record GHSA-j8r2-6x86-q33q
(requests < 2.31.0, Proxy-Authorization header leak).
"""

from __future__ import annotations

from app.services.agents.schemas import (
    DependencyAnalysisResult,
    DependencyContext,
    FindingContext,
    GraphContext,
    ImpactAssessmentResult,
    RepositoryContext,
    RiskAssessmentResult,
    UsageContext,
    UsageReferenceContext,
    VulnerabilityContext,
)

GHSA_ID = "GHSA-j8r2-6x86-q33q"


def make_context(
    *,
    usage_components: list[str] | None = None,
    repo_components: list[str] | None = None,
    references: list[UsageReferenceContext] | None = None,
    graph_available: bool = True,
    description: str | None = None,
    scope: str = "unknown",
    truncated: bool = False,
    severity: str = "MEDIUM",
) -> FindingContext:
    usage_components = ["src/app"] if usage_components is None else usage_components
    repo_components = ["src/app", "tests"] if repo_components is None else repo_components
    if references is None:
        references = [
            UsageReferenceContext(file="src/app/services/weather.py", line=3, snippet="import requests"),
            UsageReferenceContext(
                file="src/app/services/weather.py", line=18, snippet="response = requests.get(url, timeout=10)"
            ),
        ]
    files = sorted({r.file for r in references})
    return FindingContext(
        repository=RepositoryContext(
            name="demo-project",
            language="Python",
            source_type="local",
            components=repo_components,
            dependency_files=["requirements.txt"],
        ),
        dependency=DependencyContext(
            package_name="requests",
            ecosystem="PyPI",
            version="2.25.1",
            version_spec="==2.25.1",
            scope=scope,
            source_file="requirements.txt",
        ),
        vulnerability=VulnerabilityContext(
            identifier=GHSA_ID,
            aliases=["CVE-2023-32681", "PYSEC-2023-74"],
            severity=severity,
            cvss_score=6.1,
            summary="Unintended leak of Proxy-Authorization header in requests",
            description=description
            if description is not None
            else "Since Requests v2.3.0, Requests has been vulnerable to potentially leaking `Proxy-Authorization` "
            "headers to destination servers, specifically during redirects to an HTTPS origin.",
            fixed_versions=["2.31.0"],
            reference_url=f"https://github.com/psf/requests/security/advisories/{GHSA_ID}",
        ),
        usage=UsageContext(
            import_names=["requests"],
            references=references,
            files=files,
            components=usage_components,
            truncated=truncated,
        ),
        graph=GraphContext(
            available=graph_available,
            components_using=list(usage_components) if graph_available else [],
            depends_on=["urllib3@1.26.5", "certifi@2021.5.30"] if graph_available else [],
            depended_on_by=[],
            vulnerabilities=[GHSA_ID] if graph_available else [],
            paths=[["Repository:demo-project", "Component:src/app", "Dependency:requests@2.25.1"]]
            if graph_available
            else [],
        ),
    )


def valid_dependency_output() -> dict:
    return {
        "summary": "requests is an HTTP client library; the repository imports it in src/app/services/weather.py.",
        "usage_evidence": ["FACT: src/app/services/weather.py line 3 imports requests"],
        "confidence": 0.9,
    }


def valid_impact_output(components: list[str] | None = None) -> dict:
    return {
        "facts": ["FACT: src/app/services/weather.py imports requests"],
        "inferences": ["INFERENCE: outbound HTTP calls through a proxy could leak credentials"],
        "reasoning": "The weather service performs HTTP calls with requests, so the leak affects src/app.",
        "affected_components": ["src/app"] if components is None else components,
        "impact_level": "MEDIUM",
        "confidence": 0.8,
    }


def valid_risk_output() -> dict:
    return {
        "factors": ["FACT: severity MEDIUM (CVSS 6.1)", "INFERENCE: exploitation requires a proxy with credentials"],
        "reasoning": "Moderate severity, package is used, a fix exists.",
        "risk_level": "MEDIUM",
        "confidence": 0.85,
    }


def valid_remediation_output(version: str | None = "2.31.0") -> dict:
    return {
        "reasoning": "2.31.0 is the lowest verified-safe version and fixes the header leak.",
        "recommended_version": version,
        "alternative_package": None,
        "compatibility_notes": "Only src/app/services/weather.py references the package.",
        "confidence": 0.9,
    }


def prior_results() -> tuple[DependencyAnalysisResult, ImpactAssessmentResult, RiskAssessmentResult]:
    return (
        DependencyAnalysisResult.model_validate(valid_dependency_output()),
        ImpactAssessmentResult.model_validate(valid_impact_output()),
        RiskAssessmentResult.model_validate(valid_risk_output()),
    )
