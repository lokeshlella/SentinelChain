"""Unit tests for the agent prompt builders (evidence rendering, caps, instructions)."""

from __future__ import annotations

import re

from app.services.agents.prompts import (
    MAX_PROMPT_CHARS,
    SYSTEM_PROMPT,
    allowed_component_names,
    build_dependency_analysis_prompt,
    build_impact_prompt,
    build_remediation_prompt,
    build_risk_prompt,
)
from app.services.agents.schemas import UsageReferenceContext
from tests.fixtures.agents.contexts import GHSA_ID, make_context, prior_results

HEADERS = [
    "REPOSITORY",
    "DEPENDENCY",
    "VULNERABILITY",
    "SOURCE USAGE EVIDENCE (FACTS)",
    "KNOWLEDGE GRAPH (FACTS)",
]
LEVELS = "CRITICAL, HIGH, MEDIUM, LOW, NONE, UNKNOWN"
CANDIDATES = {
    "current_version": "2.25.1",
    "minimum_fixed_version": "2.31.0",
    "preferred_version": "2.31.0",
    "allowed_versions": ["2.31.0", "2.32.4"],
    "latest_version": "2.32.4",
    "same_major": True,
    "verified_safe": True,
    "remaining_vulnerabilities": [],
    "notes": ["2.31.0 verified safe against OSV"],
    "registry_available": True,
}


def test_system_prompt_states_the_rules():
    for needle in ("ONLY the evidence", "FACT", "INFERENCE", "NEVER invent", "JSON object", "no code fences"):
        assert needle in SYSTEM_PROMPT


def test_dependency_prompt_renders_all_evidence_sections():
    prompt = build_dependency_analysis_prompt(make_context())
    for header in HEADERS:
        assert header in prompt
    assert "- package: requests (PyPI)" in prompt
    assert "- installed version: 2.25.1" in prompt
    assert f"- id: {GHSA_ID} (aliases: CVE-2023-32681, PYSEC-2023-74)" in prompt
    assert "- severity: MEDIUM (CVSS 6.1)" in prompt
    assert "- fixed in: 2.31.0" in prompt
    assert "src/app/services/weather.py:3: import requests" in prompt
    assert "components containing those files (1): src/app" in prompt
    assert "Repository:demo-project -> Component:src/app -> Dependency:requests@2.25.1" in prompt
    assert "- it depends on: urllib3@1.26.5, certifi@2021.5.30" in prompt
    # instructions: exact keys and JSON-only
    assert '{"summary": "<string>", "usage_evidence": ["<FACT string>", "..."], "confidence": <number 0-1>}' in prompt
    assert prompt.rstrip().endswith("}")
    assert len(prompt) <= MAX_PROMPT_CHARS


def test_prompt_without_usage_evidence_says_so_and_graph_unavailable_is_explicit():
    ctx = make_context(usage_components=[], references=[], graph_available=False)
    prompt = build_dependency_analysis_prompt(ctx)
    assert "no direct import of 'requests' was found" in prompt
    # audit V2-01: absence of a direct import is never presented as evidence of non-use
    assert "NOT evidence that the package is unused" in prompt
    assert "knowledge graph unavailable" in prompt
    assert "references (" not in prompt


def test_impact_prompt_lists_allowed_components_and_enum_values():
    ctx = make_context(usage_components=["src/app"], repo_components=["src/app", "tests", "docs"])
    dep, _, _ = prior_results()
    prompt = build_impact_prompt(ctx, dep)
    assert "ALLOWED COMPONENTS (affected_components may ONLY contain names from this list): src/app, tests, docs" in prompt
    assert "COMPONENTS WITH SOURCE REFERENCES TO THE PACKAGE (FACT): src/app" in prompt
    assert "COMPONENTS WITHOUT EVIDENCE OF USE (FACT - do not list them as affected): tests, docs" in prompt
    assert f'"impact_level": one of {LEVELS}' in prompt
    assert '"impact_level": "<CRITICAL|HIGH|MEDIUM|LOW|NONE|UNKNOWN>"' in prompt
    assert "PREVIOUS STEP: DEPENDENCY ANALYSIS" in prompt
    assert dep.summary in prompt
    for key in ("facts", "inferences", "reasoning", "affected_components", "impact_level", "confidence"):
        assert f'"{key}"' in prompt
    assert len(prompt) <= MAX_PROMPT_CHARS


def test_impact_prompt_without_prior_result_has_no_previous_step():
    prompt = build_impact_prompt(make_context(usage_components=[], references=[]), None)
    assert "PREVIOUS STEP" not in prompt
    assert "COMPONENTS WITH SOURCE REFERENCES TO THE PACKAGE (FACT): none" in prompt


def test_impact_prompt_rules_depend_on_usage_evidence():
    with_usage = build_impact_prompt(make_context(usage_components=["src/app"]), None)
    assert "Include every component listed under COMPONENTS WITH SOURCE REFERENCES" in with_usage
    assert "MUST be an empty list" not in with_usage

    without_usage = build_impact_prompt(make_context(usage_components=[], references=[]), None)
    assert '"affected_components": MUST be an empty list []' in without_usage
    assert "NONE is not allowed" in without_usage
    assert "choose NONE" not in without_usage


# ---------------------------------------------------------------- audit V2-01: no fail-open wording


def test_impact_rule_without_usage_depends_on_scope_and_scan_completeness():
    direct = build_impact_prompt(make_context(usage_components=[], references=[], scope="direct"), None)
    assert "choose LOW or UNKNOWN and say why. NONE is not allowed." in direct
    assert "use UNKNOWN unless the evidence shows otherwise" not in direct

    transitive = build_impact_prompt(make_context(usage_components=[], references=[], scope="transitive"), None)
    assert "the dependency is transitive (pulled in by another dependency" in transitive
    assert "use UNKNOWN unless the evidence shows otherwise. NONE is not allowed." in transitive

    unknown = build_impact_prompt(make_context(usage_components=[], references=[], scope="unknown"), None)
    assert "the manifest cannot tell whether it is direct or transitive" in unknown
    assert "use UNKNOWN unless the evidence shows otherwise" in unknown

    truncated = build_impact_prompt(make_context(usage_components=[], references=[], scope="direct", truncated=True), None)
    assert "and the scan is incomplete" in truncated
    assert "use UNKNOWN unless the evidence shows otherwise" in truncated
    assert "the scanner stopped early (file or size cap); the scan is incomplete" in truncated


def test_dependency_section_explains_the_scope():
    assert "- scope: transitive (pulled in by another dependency" in build_dependency_analysis_prompt(make_context(scope="transitive"))
    assert "- scope: direct (declared by the repository itself)" in build_dependency_analysis_prompt(make_context(scope="direct"))
    assert "- scope: unknown (the manifest cannot tell" in build_dependency_analysis_prompt(make_context())


def test_risk_prompt_states_the_severity_floor_and_that_no_import_is_not_proof():
    dep, impact, _ = prior_results()
    prompt = build_risk_prompt(make_context(usage_components=[], references=[]), dep, impact)
    assert "FLOOR: the severity alone already makes this MEDIUM" in prompt
    assert "never lower it" in prompt
    assert "the absence of one is not proof of non-use" in prompt
    assert "actually referenced by the application code" not in prompt

    high = build_risk_prompt(make_context(severity="HIGH"), dep, impact)
    assert "FLOOR: the severity alone already makes this HIGH" in high

    unrated = build_risk_prompt(make_context(severity="UNKNOWN"), dep, impact)
    assert "FLOOR" not in unrated
    assert "The advisory carries no severity, so there is no floor" in unrated


def test_allowed_component_names_is_union_in_evidence_order_without_duplicates():
    ctx = make_context(usage_components=["tests", "src/app"], repo_components=["src/app", "tests", "docs"])
    assert allowed_component_names(ctx) == ["tests", "src/app", "docs"]


def test_risk_prompt_includes_both_previous_steps():
    dep, impact, _ = prior_results()
    prompt = build_risk_prompt(make_context(), dep, impact)
    assert "PREVIOUS STEP: DEPENDENCY ANALYSIS" in prompt
    assert "PREVIOUS STEP: IMPACT ASSESSMENT" in prompt
    assert "- impact level: MEDIUM" in prompt
    assert "- affected components: src/app" in prompt
    assert f'"risk_level": one of {LEVELS}' in prompt
    assert '{"factors": ["FACT: ...", "INFERENCE: ..."], "reasoning": "<string>", "risk_level":' in prompt
    assert len(prompt) <= MAX_PROMPT_CHARS


def test_risk_prompt_tolerates_missing_impact():
    dep, _, _ = prior_results()
    prompt = build_risk_prompt(make_context(), dep, None)
    assert "PREVIOUS STEP: DEPENDENCY ANALYSIS" in prompt
    assert "PREVIOUS STEP: IMPACT ASSESSMENT" not in prompt


def test_remediation_prompt_renders_candidates_and_restricts_versions():
    dep, impact, risk = prior_results()
    prompt = build_remediation_prompt(make_context(), CANDIDATES, dep, impact, risk)
    assert "CANDIDATE VERSIONS (only these may be recommended)" in prompt
    assert "- allowed versions: 2.31.0, 2.32.4" in prompt
    assert "- preferred (lowest verified-safe) version: 2.31.0" in prompt
    assert "- latest published version: 2.32.4" in prompt
    assert "same major version: yes" in prompt
    assert "2.31.0 verified safe against OSV" in prompt
    assert "copy EXACTLY one of the allowed versions [2.31.0, 2.32.4]" in prompt
    assert "PREVIOUS STEP: RISK EVALUATION" in prompt and "- risk level: MEDIUM" in prompt
    for key in ("reasoning", "recommended_version", "alternative_package", "compatibility_notes", "confidence"):
        assert f'"{key}"' in prompt
    assert len(prompt) <= MAX_PROMPT_CHARS


def test_remediation_prompt_with_no_candidates_tells_model_not_to_invent():
    empty = {"allowed_versions": [], "preferred_version": None, "registry_available": False}
    prompt = build_remediation_prompt(make_context(), empty, None, None, None)
    assert "- allowed versions: none known (say so; do not invent one)" in prompt
    assert "registry could not be reached" in prompt
    assert "Use null only if the allowed list is empty" in prompt


def test_long_reference_list_is_capped_with_omitted_count():
    refs = [
        UsageReferenceContext(file=f"src/app/module_{i}.py", line=i, snippet=f"import requests  # {i}")
        for i in range(40)
    ]
    prompt = build_dependency_analysis_prompt(make_context(references=refs))
    assert "references (40):" in prompt
    assert re.search(r"\(\d+ more omitted\)", prompt)
    assert "files referencing the package (40):" in prompt
    assert "(+" in prompt and "more omitted)" in prompt
    assert len(prompt) <= MAX_PROMPT_CHARS


def test_huge_description_is_truncated_and_task_block_survives():
    ctx = make_context(description="Lorem ipsum dolor sit amet. " * 2000)  # ~56k chars
    prompt = build_impact_prompt(ctx, None)
    assert len(prompt) <= MAX_PROMPT_CHARS
    assert "...[truncated]" in prompt
    assert prompt.rstrip().endswith("}")  # the JSON instruction block is intact at the end
    assert "TASK: Assess the impact" in prompt


def test_extreme_evidence_hits_hard_truncation_but_keeps_task():
    refs = [
        UsageReferenceContext(file=f"src/very/long/path/number_{i}/module_{i}.py", line=i, snippet="x" * 120)
        for i in range(300)
    ]
    ctx = make_context(
        references=refs,
        repo_components=[f"component_{i}" for i in range(200)],
        description="word " * 3000,
    )
    prompt = build_risk_prompt(ctx, None, None)
    assert len(prompt) <= MAX_PROMPT_CHARS
    assert "TASK: Evaluate the overall risk" in prompt
    assert prompt.rstrip().endswith("}")


def test_impact_prompt_keeps_vulnerability_section_with_many_components():
    """Hundreds of repository components must not push the vulnerability evidence out of the prompt."""
    from app.services.agents.prompts import MAX_PROMPT_CHARS, build_impact_prompt

    ctx = make_context(repo_components=[f"packages/service_{i}" for i in range(200)])
    prompt = build_impact_prompt(ctx, None)
    assert "VULNERABILITY" in prompt
    assert ctx.vulnerability.identifier in prompt
    assert len(prompt) <= MAX_PROMPT_CHARS
    assert "more omitted" in prompt or "+" in prompt  # the component list was capped
