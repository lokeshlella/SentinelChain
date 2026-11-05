"""Which product features a build exposes, per academic review phase.

Sentinel Chain is reviewed in two phases. Phase 1 is the deterministic supply-chain analysis:
repository ingestion and profiling, dependency extraction, PostgreSQL persistence, OSV.dev
vulnerability detection, source-usage evidence and the Neo4j knowledge graph. Phase 2 adds the
agentic layer on top of it: the Ollama agents, remediation, Docker sandbox validation, evidence
reports and GitHub pull requests.

``SENTINEL_PHASE`` picks the set (default 2: everything). ``SENTINEL_FEATURES`` adds individual
Phase-2 features to a Phase-1 build, e.g. ``SENTINEL_FEATURES=ai``. A disabled feature is hidden
in the dashboard, its API routes answer 404, and the pipeline never calls Ollama, Docker or
GitHub for it. Nothing is deleted: the same database shows everything again in phase 2.
"""

from __future__ import annotations

from app.core.config import Settings, get_settings

PHASE_1_FEATURES = ("repositories", "dependencies", "vulnerabilities", "usage", "knowledge_graph")
PHASE_2_FEATURES = ("ai", "remediation", "validation", "reports", "pull_requests")
ALL_FEATURES = PHASE_1_FEATURES + PHASE_2_FEATURES

# A feature only works on top of the ones it builds on; enabling it enables those too.
PREREQUISITES: dict[str, tuple[str, ...]] = {
    "validation": ("remediation",),
    "pull_requests": ("remediation", "validation"),
}


def current_phase(settings: Settings | None = None) -> int:
    """1 for a Phase-1 build, otherwise 2 (an out-of-range value never disables more than phase 1 does)."""
    settings = settings or get_settings()
    return 1 if settings.sentinel_phase <= 1 else 2


def requested_extras(settings: Settings | None = None) -> tuple[set[str], set[str]]:
    """``SENTINEL_FEATURES`` split into (known Phase-2 features, unknown names)."""
    settings = settings or get_settings()
    names = {n.strip().lower() for n in (settings.sentinel_features or "").split(",") if n.strip()}
    return names & set(PHASE_2_FEATURES), names - set(PHASE_2_FEATURES)


def enabled_features(settings: Settings | None = None) -> dict[str, bool]:
    """``{feature: enabled}`` for every feature, in a stable order."""
    settings = settings or get_settings()
    enabled = set(PHASE_1_FEATURES)
    if current_phase(settings) == 2:
        enabled |= set(PHASE_2_FEATURES)
    else:
        extras, _unknown = requested_extras(settings)
        pending = list(extras)
        while pending:
            name = pending.pop()
            if name not in enabled:
                enabled.add(name)
                pending.extend(PREREQUISITES.get(name, ()))
    return {name: name in enabled for name in ALL_FEATURES}


def feature_enabled(name: str, settings: Settings | None = None) -> bool:
    return enabled_features(settings).get(name, False)


def describe(settings: Settings | None = None) -> str:
    """One line for the startup log."""
    settings = settings or get_settings()
    on = [name for name, enabled in enabled_features(settings).items() if enabled]
    _extras, unknown = requested_extras(settings)
    line = f"phase {current_phase(settings)} ({', '.join(on)})"
    if unknown:
        line += f" (ignored unknown SENTINEL_FEATURES: {', '.join(sorted(unknown))})"
    return line
