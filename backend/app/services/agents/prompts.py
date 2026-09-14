"""Prompt construction for the AI agents.

Design notes (a ~3B local model runs these prompts):

* Evidence is rendered as short bullet lists under fixed, explicit headers so
  the model can quote it verbatim. Every list is capped and states how many
  entries were omitted — the prompt never silently hides evidence.
* Each builder ends with the exact JSON keys expected and the allowed enum
  values, and the whole prompt is kept below ``MAX_PROMPT_CHARS``.
* Nothing in a prompt is invented: only values from :class:`FindingContext`
  (and the deterministic candidate set) are rendered.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from app.services.agents.schemas import (
    DependencyAnalysisResult,
    FindingContext,
    ImpactAssessmentResult,
    RiskAssessmentResult,
)

MAX_PROMPT_CHARS = 6000
LEVEL_VALUES = "CRITICAL, HIGH, MEDIUM, LOW, NONE, UNKNOWN"

SYSTEM_PROMPT = """You are Sentinel Chain, a senior software supply-chain security analyst.
You analyse ONE vulnerable dependency of ONE application at a time and answer with structured JSON.

MANDATORY RULES:
1. Use ONLY the evidence given in the user message. Do not use outside knowledge about this repository.
2. Label every statement as FACT (directly supported by the evidence) or INFERENCE (your own reasoning).
3. NEVER invent file paths, components, packages, versions, vulnerability identifiers or numbers. If the evidence does not contain something, say it is unknown.
4. Only name files and components that appear in the evidence lists.
5. Only recommend versions that appear under CANDIDATE VERSIONS.
6. Respond with ONE JSON object and nothing else: no markdown, no code fences, no comments, no text before or after the JSON.
7. Use exactly the JSON keys requested. Enum values must be UPPERCASE and taken from the allowed list."""


@dataclass(frozen=True)
class _Limits:
    """Caps applied while rendering evidence (a compact variant is used when the prompt is too long)."""

    references: int = 12
    files: int = 15
    components: int = 25
    graph_items: int = 12
    paths: int = 5
    prior_items: int = 6
    summary_chars: int = 300
    description_chars: int = 900
    text_chars: int = 500


_FULL = _Limits()
_COMPACT = _Limits(
    references=5, files=8, components=12, graph_items=6, paths=3, prior_items=3,
    summary_chars=200, description_chars=300, text_chars=250,
)


# ------------------------------------------------------------------ rendering helpers


def _clip(text: str | None, limit: int) -> str:
    text = " ".join(str(text or "").split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 15)].rstrip() + " ...[truncated]"


# Upper bound for component name lists rendered inside the impact task block.
_COMPONENT_LIST_CAP = 40


def _join_capped(items: list[Any], limit: int, sep: str = ", ") -> str:
    shown = [str(i) for i in items[:limit]]
    omitted = len(items) - len(shown)
    text = sep.join(shown) if shown else "none"
    if omitted > 0:
        text += f" (+{omitted} more omitted)"
    return text


def _bullets(items: list[str], limit: int, indent: str = "  ") -> list[str]:
    lines = [f"{indent}- {item}" for item in items[:limit]]
    omitted = len(items) - len(lines)
    if omitted > 0:
        lines.append(f"{indent}- ({omitted} more omitted)")
    return lines


def _section(title: str, lines: list[str]) -> str:
    return "\n".join([title] + lines)


def _repository_section(ctx: FindingContext, limits: _Limits) -> str:
    repo = ctx.repository
    return _section(
        "REPOSITORY",
        [
            f"- name: {repo.name}",
            f"- language: {repo.language or 'unknown'}",
            f"- source: {repo.source_type}",
            f"- components ({len(repo.components)}): {_join_capped(repo.components, limits.components)}",
            f"- dependency files: {_join_capped(repo.dependency_files, limits.files)}",
        ],
    )


def _dependency_section(ctx: FindingContext) -> str:
    dep = ctx.dependency
    version = dep.version or "unknown (not pinned)"
    if dep.version_spec and dep.version_spec != dep.version:
        version += f" (declared as {dep.version_spec})"
    return _section(
        "DEPENDENCY",
        [
            f"- package: {dep.package_name} ({dep.ecosystem})",
            f"- installed version: {version}",
            f"- scope: {dep.scope}",
            f"- declared in: {dep.source_file}",
        ],
    )


def _vulnerability_section(ctx: FindingContext, limits: _Limits) -> str:
    vuln = ctx.vulnerability
    identifier = vuln.identifier
    if vuln.aliases:
        identifier += f" (aliases: {_join_capped([a for a in vuln.aliases if a != vuln.identifier], 5)})"
    severity = vuln.severity or "UNKNOWN"
    if vuln.cvss_score is not None:
        severity += f" (CVSS {vuln.cvss_score})"
    lines = [
        f"- id: {identifier}",
        f"- severity: {severity}",
        f"- fixed in: {_join_capped(vuln.fixed_versions, 6) if vuln.fixed_versions else 'unknown'}",
        f"- summary: {_clip(vuln.summary, limits.summary_chars) or 'not provided'}",
    ]
    if vuln.description:
        lines.append(f"- details: {_clip(vuln.description, limits.description_chars)}")
    if vuln.reference_url:
        lines.append(f"- reference: {vuln.reference_url}")
    return _section("VULNERABILITY", lines)


def _usage_section(ctx: FindingContext, limits: _Limits) -> str:
    usage = ctx.usage
    pkg = ctx.dependency.package_name
    if not usage.references and not usage.files and not usage.components:
        return _section(
            "SOURCE USAGE EVIDENCE (FACTS)",
            [f"- no import or reference to '{pkg}' was found in the repository's own source files"],
        )
    lines = [
        f"- import names searched: {_join_capped(usage.import_names, 6)}",
        f"- files referencing the package ({len(usage.files)}): {_join_capped(usage.files, limits.files)}",
        f"- components containing those files ({len(usage.components)}): "
        f"{_join_capped(usage.components, limits.components)}",
    ]
    if usage.references:
        lines.append(f"- references ({len(usage.references)}):")
        rendered = [f"{r.file}:{r.line}: {_clip(r.snippet, 120)}" for r in usage.references]
        lines.extend(_bullets(rendered, limits.references))
    if usage.truncated:
        lines.append("- note: the scanner stopped early; more references may exist")
    return _section("SOURCE USAGE EVIDENCE (FACTS)", lines)


def _graph_section(ctx: FindingContext, limits: _Limits) -> str:
    graph = ctx.graph
    if not graph.available:
        return _section("KNOWLEDGE GRAPH (FACTS)", ["- knowledge graph unavailable: no graph facts for this finding"])
    lines = [
        f"- components using the dependency: {_join_capped(graph.components_using, limits.graph_items)}",
        f"- it depends on: {_join_capped(graph.depends_on, limits.graph_items)}",
        f"- depended on by: {_join_capped(graph.depended_on_by, limits.graph_items)}",
        f"- known vulnerabilities of the dependency: {_join_capped(graph.vulnerabilities, limits.graph_items)}",
    ]
    if graph.paths:
        lines.append(f"- dependency paths ({len(graph.paths)}):")
        lines.extend(_bullets([" -> ".join(p) for p in graph.paths], limits.paths))
    return _section("KNOWLEDGE GRAPH (FACTS)", lines)


def _prior_dependency_section(result: DependencyAnalysisResult | None, limits: _Limits) -> str | None:
    if result is None:
        return None
    lines = [f"- summary: {_clip(result.summary, limits.text_chars)}", f"- confidence: {result.confidence:.2f}"]
    if result.usage_evidence:
        lines.append("- usage evidence:")
        lines.extend(_bullets([_clip(e, 160) for e in result.usage_evidence], limits.prior_items))
    return _section("PREVIOUS STEP: DEPENDENCY ANALYSIS", lines)


def _prior_impact_section(result: ImpactAssessmentResult | None, limits: _Limits) -> str | None:
    if result is None:
        return None
    lines = [
        f"- impact level: {result.impact_level}",
        f"- affected components: {_join_capped(result.affected_components, limits.components)}",
        f"- reasoning: {_clip(result.reasoning, limits.text_chars)}",
        f"- confidence: {result.confidence:.2f}",
    ]
    if result.facts:
        lines.append("- facts:")
        lines.extend(_bullets([_clip(f, 160) for f in result.facts], limits.prior_items))
    if result.inferences:
        lines.append("- inferences:")
        lines.extend(_bullets([_clip(i, 160) for i in result.inferences], limits.prior_items))
    return _section("PREVIOUS STEP: IMPACT ASSESSMENT", lines)


def _prior_risk_section(result: RiskAssessmentResult | None, limits: _Limits) -> str | None:
    if result is None:
        return None
    lines = [
        f"- risk level: {result.risk_level}",
        f"- factors: {_join_capped(result.factors, limits.prior_items, sep='; ')}",
        f"- reasoning: {_clip(result.reasoning, limits.text_chars)}",
        f"- confidence: {result.confidence:.2f}",
    ]
    return _section("PREVIOUS STEP: RISK EVALUATION", lines)


def _evidence_block(ctx: FindingContext, limits: _Limits, extra: list[str | None]) -> str:
    sections = [
        _repository_section(ctx, limits),
        _dependency_section(ctx),
        _vulnerability_section(ctx, limits),
        _usage_section(ctx, limits),
        _graph_section(ctx, limits),
        *extra,
    ]
    return "\n\n".join(s for s in sections if s)


def _assemble(render_evidence: Callable[[_Limits], str], task: str) -> str:
    """Join evidence + task, shrinking the evidence until the prompt fits ``MAX_PROMPT_CHARS``."""
    for limits in (_FULL, _COMPACT):
        prompt = f"{render_evidence(limits)}\n\n{task}"
        if len(prompt) <= MAX_PROMPT_CHARS:
            return prompt
    evidence = render_evidence(_COMPACT)
    budget = MAX_PROMPT_CHARS - len(task) - 60
    if budget < 200:  # the task text alone is (almost) the whole budget: keep it intact
        return f"{evidence[:200]}\n[evidence truncated]\n\n{task}"
    return f"{evidence[:budget].rstrip()}\n- [evidence truncated to fit the prompt budget]\n\n{task}"


def allowed_component_names(ctx: FindingContext) -> list[str]:
    """Components the impact agent may name: usage evidence ∪ repository components (ordered, unique)."""
    seen: list[str] = []
    for name in [*ctx.usage.components, *ctx.repository.components]:
        if name and name not in seen:
            seen.append(name)
    return seen


# ------------------------------------------------------------------ public builders


def build_dependency_analysis_prompt(ctx: FindingContext) -> str:
    """Prompt for :class:`DependencyAnalysisAgent` → ``DependencyAnalysisResult``."""
    pkg = ctx.dependency.package_name
    task = f"""TASK: Explain what the package '{pkg}' is and how THIS repository uses it, based only on the evidence above.
- "summary": 2-4 sentences. Say what the package does (INFERENCE from its name/summary is allowed, label it) and where the repository references it (FACT).
- "usage_evidence": a list of short FACT statements, each quoting a file, component or graph relation from the evidence (for example "FACT: src/app/services/weather.py line 3 imports {pkg}"). Use an empty list if there is no usage evidence.
- "confidence": a number between 0 and 1 (how well the evidence supports the summary).

Return ONLY this JSON object:
{{"summary": "<string>", "usage_evidence": ["<FACT string>", "..."], "confidence": <number 0-1>}}"""
    return _assemble(lambda limits: _evidence_block(ctx, limits, []), task)


def build_impact_prompt(ctx: FindingContext, dependency_analysis: DependencyAnalysisResult | None) -> str:
    """Prompt for :class:`ImpactAssessmentAgent` → ``ImpactAssessmentResult``."""
    allowed = allowed_component_names(ctx)
    using = ctx.usage.components
    evidenced = {*using, *ctx.graph.components_using}
    unevidenced = [c for c in allowed if c not in evidenced]
    # Components with evidence are listed first so they always survive the cap; a
    # repository with hundreds of top-level directories must not push the vulnerability
    # and usage sections out of the prompt budget.
    allowed_ordered = [c for c in allowed if c in evidenced] + unevidenced
    allowed_text = (
        _join_capped(allowed_ordered, _COMPONENT_LIST_CAP) if allowed else "none (no components are known)"
    )
    using_text = _join_capped(using, _COMPONENT_LIST_CAP) if using else "none (no source references were found)"
    unevidenced_text = _join_capped(unevidenced, _COMPONENT_LIST_CAP) if unevidenced else "none"
    if using:
        components_rule = (
            '- "affected_components": component names copied exactly from the ALLOWED COMPONENTS list. '
            "Include every component listed under COMPONENTS WITH SOURCE REFERENCES; never add a component "
            "listed under COMPONENTS WITHOUT EVIDENCE OF USE."
        )
        level_rule = f'- "impact_level": one of {LEVEL_VALUES}. Use UNKNOWN if the evidence is insufficient.'
    else:
        components_rule = (
            '- "affected_components": MUST be an empty list [] because no source file references the package '
            "(FACT). Do not list any component."
        )
        level_rule = (
            f'- "impact_level": one of {LEVEL_VALUES}. The package is declared but no source file references it, '
            "so choose NONE, LOW or UNKNOWN and say why."
        )
    task = f"""ALLOWED COMPONENTS (affected_components may ONLY contain names from this list): {allowed_text}
COMPONENTS WITH SOURCE REFERENCES TO THE PACKAGE (FACT): {using_text}
COMPONENTS WITHOUT EVIDENCE OF USE (FACT - do not list them as affected): {unevidenced_text}

TASK: Assess the impact of vulnerability {ctx.vulnerability.identifier} on THIS application. Fill the keys in this order:
- "facts": 2-5 short statements supported by the evidence, each starting with "FACT:" (which files/components reference the package, what the vulnerability does, which versions fix it).
- "inferences": 1-4 short conclusions, each starting with "INFERENCE:" (how the vulnerable behaviour could affect this application).
- "reasoning": 2-4 sentences explaining the impact level using the vulnerability details and the usage evidence.
{components_rule}
{level_rule}
- "confidence": a number between 0 and 1.

Return ONLY this JSON object:
{{"facts": ["FACT: ..."], "inferences": ["INFERENCE: ..."], "reasoning": "<string>", "affected_components": ["<allowed component>"], "impact_level": "<{LEVEL_VALUES.replace(', ', '|')}>", "confidence": <number 0-1>}}"""
    return _assemble(
        lambda limits: _evidence_block(ctx, limits, [_prior_dependency_section(dependency_analysis, limits)]),
        task,
    )


def build_risk_prompt(
    ctx: FindingContext,
    dependency_analysis: DependencyAnalysisResult | None,
    impact: ImpactAssessmentResult | None,
) -> str:
    """Prompt for :class:`RiskEvaluationAgent` → ``RiskAssessmentResult``."""
    task = f"""TASK: Evaluate the overall risk of vulnerability {ctx.vulnerability.identifier} in dependency {ctx.dependency.package_name} for THIS application.
Consider: the vulnerability severity and details (FACT), whether the package is actually referenced by the application code (FACT), the assessed impact (previous step), whether a fixed version exists (FACT), and how exploitable the issue is (INFERENCE).
Fill the keys in this order:
- "factors": 3-6 short statements, each starting with "FACT:" or "INFERENCE:", that drive the risk level.
- "reasoning": 2-4 sentences explaining the risk level.
- "risk_level": one of {LEVEL_VALUES}. Use UNKNOWN only when the evidence is insufficient.
- "confidence": a number between 0 and 1.

Return ONLY this JSON object:
{{"factors": ["FACT: ...", "INFERENCE: ..."], "reasoning": "<string>", "risk_level": "<{LEVEL_VALUES.replace(', ', '|')}>", "confidence": <number 0-1>}}"""
    return _assemble(
        lambda limits: _evidence_block(
            ctx,
            limits,
            [_prior_dependency_section(dependency_analysis, limits), _prior_impact_section(impact, limits)],
        ),
        task,
    )


def _candidates_section(candidates: dict[str, Any], limits: _Limits) -> str:
    allowed = [str(v) for v in (candidates.get("allowed_versions") or [])]
    preferred = candidates.get("preferred_version")
    lines = [
        f"- current version: {candidates.get('current_version') or 'unknown'}",
        f"- allowed versions: {_join_capped(allowed, 10) if allowed else 'none known (say so; do not invent one)'}",
        f"- preferred (lowest verified-safe) version: {preferred or 'none'}",
        f"- minimum fixed version: {candidates.get('minimum_fixed_version') or 'unknown'}",
        f"- latest published version: {candidates.get('latest_version') or 'unknown'}",
    ]
    same_major = candidates.get("same_major")
    if same_major is not None:
        lines.append(f"- preferred version keeps the same major version: {'yes' if same_major else 'no'}")
    verified = candidates.get("verified_safe")
    if verified is not None:
        lines.append(f"- candidates verified safe against OSV: {'yes' if verified else 'no'}")
    remaining = candidates.get("remaining_vulnerabilities") or []
    if remaining:
        lines.append(f"- vulnerabilities still affecting the preferred version: {_join_capped(list(remaining), 6)}")
    if candidates.get("registry_available") is False:
        lines.append("- note: the package registry could not be reached; versions come from OSV data only")
    notes = [str(n) for n in (candidates.get("notes") or [])]
    if notes:
        lines.append("- notes:")
        lines.extend(_bullets([_clip(n, 160) for n in notes], limits.prior_items))
    return _section("CANDIDATE VERSIONS (only these may be recommended)", lines)


def build_remediation_prompt(
    ctx: FindingContext,
    candidates: dict[str, Any],
    dependency_analysis: DependencyAnalysisResult | None,
    impact: ImpactAssessmentResult | None,
    risk: RiskAssessmentResult | None,
) -> str:
    """Prompt for :class:`RemediationAgent` → ``RemediationResult``.

    ``candidates`` is the plain-dict view of the deterministic ``CandidateSet``
    (see :func:`app.services.agents.orchestrator.candidate_view`).
    """
    allowed = [str(v) for v in (candidates.get("allowed_versions") or [])]
    allowed_text = ", ".join(allowed) if allowed else "none"
    pkg = ctx.dependency.package_name
    task = f"""TASK: Recommend how to remediate vulnerability {ctx.vulnerability.identifier} in {pkg} {ctx.dependency.version or '(unpinned)'}. Fill the keys in this order:
- "reasoning": 2-4 sentences: which allowed version to move to and why, referencing the vulnerability fix and the usage evidence (label FACT vs INFERENCE).
- "recommended_version": copy EXACTLY one of the allowed versions [{allowed_text}]; choose the preferred version unless the evidence justifies another allowed version. Use null only if the allowed list is empty.
- "alternative_package": null unless the evidence explicitly names a replacement package.
- "compatibility_notes": 1-3 sentences on what a developer should check before merging (which files reference the package is FACT; possible breaking changes between the versions are INFERENCE).
- "confidence": a number between 0 and 1.

Return ONLY this JSON object:
{{"reasoning": "<string>", "recommended_version": "<allowed version or null>", "alternative_package": null, "compatibility_notes": "<string>", "confidence": <number 0-1>}}"""
    return _assemble(
        lambda limits: _evidence_block(
            ctx,
            limits,
            [
                _prior_dependency_section(dependency_analysis, limits),
                _prior_impact_section(impact, limits),
                _prior_risk_section(risk, limits),
                _candidates_section(candidates, limits),
            ],
        ),
        task,
    )


__all__ = [
    "MAX_PROMPT_CHARS",
    "SYSTEM_PROMPT",
    "allowed_component_names",
    "build_dependency_analysis_prompt",
    "build_impact_prompt",
    "build_remediation_prompt",
    "build_risk_prompt",
]
