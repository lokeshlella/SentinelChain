"""Smoke test for the AI agents against the real local Ollama server.

Builds a realistic FindingContext (the ``requests`` 2.25.1 →
GHSA-j8r2-6x86-q33q case, vulnerability text taken from the real OSV record),
runs ``AIOrchestrator.analyze_finding`` and ``recommend_remediation`` and
prints the structured results, the parse/retry counts and the latency.

    cd backend && .venv/bin/python scripts/ai_smoke.py [--refresh-osv] [--json]

Nothing is invented: the only data the agents see is what is printed under
"CONTEXT". Use ``--refresh-osv`` to re-fetch the vulnerability text from OSV.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import get_settings  # noqa: E402
from app.core.logging import configure_logging  # noqa: E402
from app.services.agents.orchestrator import AIOrchestrator  # noqa: E402
from app.services.agents.schemas import (  # noqa: E402
    DependencyContext,
    FindingContext,
    GraphContext,
    RepositoryContext,
    UsageContext,
    UsageReferenceContext,
    VulnerabilityContext,
)
from app.services.llm.factory import get_default_provider  # noqa: E402

OSV_ID = "GHSA-j8r2-6x86-q33q"

# Copied from https://api.osv.dev/v1/vulns/GHSA-j8r2-6x86-q33q (summary + first paragraph of details).
OSV_SUMMARY = "Unintended leak of Proxy-Authorization header in requests"
OSV_DETAILS = (
    "Since Requests v2.3.0, Requests has been vulnerable to potentially leaking `Proxy-Authorization` "
    "headers to destination servers, specifically during redirects to an HTTPS origin. This is a product "
    "of how `rebuild_proxies` is used to recompute and reattach the `Proxy-Authorization` header to "
    "requests when redirected. Note this behavior has _only_ been observed to affect proxied requests "
    "when credentials are supplied in the URL user information component "
    "(e.g. `https://username:password@proxy:8080`). Current vulnerable behavior(s): HTTP -> HTTPS: leak; "
    "HTTPS -> HTTP: no leak; HTTPS -> HTTPS: leak; HTTP -> HTTP: no leak."
)


def build_context(refresh_osv: bool) -> FindingContext:
    summary, details, aliases, fixed = OSV_SUMMARY, OSV_DETAILS, ["CVE-2023-32681", "PYSEC-2023-74"], ["2.31.0"]
    if refresh_osv:
        import httpx

        record = httpx.get(f"https://api.osv.dev/v1/vulns/{OSV_ID}", timeout=20).json()
        summary = record.get("summary") or summary
        details = (record.get("details") or details)[:1200]
        aliases = record.get("aliases") or aliases
        fixed = [
            e["fixed"]
            for a in record.get("affected", [])
            if a.get("package", {}).get("ecosystem") == "PyPI"
            for r in a.get("ranges", [])
            for e in r.get("events", [])
            if "fixed" in e
        ] or fixed
    return FindingContext(
        repository=RepositoryContext(
            name="demo-project",
            language="Python",
            source_type="local",
            components=["src/app", "tests"],
            dependency_files=["requirements.txt"],
        ),
        dependency=DependencyContext(
            package_name="requests",
            ecosystem="PyPI",
            version="2.25.1",
            version_spec="==2.25.1",
            scope="unknown",
            source_file="requirements.txt",
        ),
        vulnerability=VulnerabilityContext(
            identifier=OSV_ID,
            aliases=aliases,
            severity="MEDIUM",
            cvss_score=6.1,
            summary=summary,
            description=details,
            fixed_versions=fixed,
            reference_url=f"https://github.com/psf/requests/security/advisories/{OSV_ID}",
        ),
        usage=UsageContext(
            import_names=["requests"],
            references=[
                UsageReferenceContext(file="src/app/services/weather.py", line=3, snippet="import requests"),
                UsageReferenceContext(
                    file="src/app/services/weather.py",
                    line=18,
                    snippet="response = requests.get(url, params=params, timeout=10, proxies=self.proxies)",
                ),
                UsageReferenceContext(file="requirements.txt", line=2, snippet="requests==2.25.1"),
            ],
            files=["src/app/services/weather.py", "requirements.txt"],
            components=["src/app"],
            truncated=False,
        ),
        graph=GraphContext(
            available=True,
            components_using=["src/app"],
            depends_on=[],
            depended_on_by=[],
            vulnerabilities=[OSV_ID],
            paths=[
                ["Repository:demo-project", "Component:src/app", "Dependency:requests@2.25.1"],
                ["Repository:demo-project", "Dependency:requests@2.25.1", f"Vulnerability:{OSV_ID}"],
            ],
        ),
    )


# Deterministic candidate set as remediation/candidates.py would compute it (registry + OSV verified).
CANDIDATES = {
    "current_version": "2.25.1",
    "minimum_fixed_version": "2.31.0",
    "preferred_version": "2.31.0",
    "allowed_versions": ["2.31.0", "2.32.4"],
    "latest_version": "2.32.4",
    "same_major": True,
    "verified_safe": True,
    "remaining_vulnerabilities": [],
    "notes": ["2.31.0 is the lowest version verified safe against OSV for GHSA-j8r2-6x86-q33q"],
    "registry_available": True,
}


class _CountingProvider:
    """Wraps an LLMProvider and counts generate() calls and provider errors."""

    def __init__(self, inner) -> None:
        self._inner = inner
        self.calls = 0
        self.errors = 0

    def __getattr__(self, name):
        return getattr(self._inner, name)

    @property
    def model_name(self) -> str:
        return self._inner.model_name

    def generate(self, *args, **kwargs):
        self.calls += 1
        try:
            return self._inner.generate(*args, **kwargs)
        except Exception:
            self.errors += 1
            raise

    def health(self):
        return self._inner.health()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--refresh-osv", action="store_true", help="fetch the vulnerability text from OSV")
    parser.add_argument("--json", action="store_true", help="print results as JSON only")
    args = parser.parse_args()

    settings = get_settings()
    configure_logging("INFO" if not args.json else "WARNING")

    provider = _CountingProvider(get_default_provider(settings))
    orchestrator = AIOrchestrator(provider, settings)
    ok, detail = orchestrator.available()
    print(f"Ollama: {'available' if ok else 'UNAVAILABLE'} — {detail}")
    if not ok:
        print("Start Ollama (`ollama serve`) and pull the model (`ollama pull {}`)".format(settings.ollama_model))
        return 2

    context = build_context(args.refresh_osv)
    if not args.json:
        print("\nCONTEXT")
        print(json.dumps(context.model_dump(), indent=2)[:4000])

    t0 = time.perf_counter()
    finding_result = orchestrator.analyze_finding(context)
    t_analyze = time.perf_counter() - t0

    t1 = time.perf_counter()
    remediation_error: str | None = None
    remediation = None
    try:
        remediation = orchestrator.recommend_remediation(context, CANDIDATES, prior=finding_result)
    except Exception as exc:  # noqa: BLE001 - smoke script reports, never hides
        remediation_error = f"{exc.__class__.__name__}: {exc}"
    t_remediate = time.perf_counter() - t1

    parsed = sum(
        1
        for r in (finding_result.dependency_analysis, finding_result.impact, finding_result.risk, remediation)
        if r is not None
    )
    output = {
        "model": provider.model_name,
        "analyze_finding": finding_result.model_dump(),
        "recommend_remediation": remediation.model_dump() if remediation else None,
        "remediation_error": remediation_error,
        "timings_s": {"analyze_finding": round(t_analyze, 1), "recommend_remediation": round(t_remediate, 1)},
        "structured_output": {
            "llm_calls": provider.calls,
            "provider_errors": provider.errors,
            "results_parsed": parsed,
            "correction_retries": provider.calls - provider.errors - parsed,
        },
    }
    print("\nRESULTS")
    print(json.dumps(output, indent=2))
    return 0 if finding_result.status == "COMPLETED" and remediation is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
