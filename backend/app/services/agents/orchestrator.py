"""AI orchestration for one finding: dependency → impact → risk (→ remediation).

The orchestrator is the only place that decides *what to trust* from the
model:

* ``impact.affected_components`` is filtered to components that appear in the
  evidence (``usage.components ∪ repository.components``); anything else is
  dropped and recorded in ``dropped_components``.
* ``remediation.recommended_version`` must be one of the deterministic
  candidate versions; otherwise it is replaced by the preferred candidate and
  the substitution is written into ``reasoning``.
* An unavailable LLM (``LLMError`` on the very first call) yields status
  ``UNAVAILABLE`` without further calls; bad output from one agent is recorded
  in ``failures`` and later agents still run with whatever is available.
"""

from __future__ import annotations

import time
from dataclasses import asdict, is_dataclass
from typing import Any

from app.core.config import Settings
from app.core.logging import get_stage_logger
from app.services.agents.base import AgentError
from app.services.agents.dependency_agent import DependencyAnalysisAgent
from app.services.agents.impact_agent import ImpactAssessmentAgent
from app.services.agents.prompts import allowed_component_names
from app.services.agents.remediation_agent import RemediationAgent
from app.services.agents.risk_agent import RiskEvaluationAgent
from app.services.agents.schemas import (
    AgentFailure,
    DependencyAnalysisResult,
    FindingAIResult,
    FindingContext,
    ImpactAssessmentResult,
    RemediationResult,
    RiskAssessmentResult,
)
from app.services.llm.base import LLMError, LLMProvider

logger = get_stage_logger("AI")

_CANDIDATE_KEYS = (
    "current_version",
    "minimum_fixed_version",
    "preferred_version",
    "allowed_versions",
    "latest_version",
    "same_major",
    "verified_safe",
    "remaining_vulnerabilities",
    "notes",
    "registry_available",
)


# ------------------------------------------------------------------ candidate helpers


def candidate_view(candidates: Any) -> dict[str, Any]:
    """Plain-dict view of a ``CandidateSet``-like object (dict, dataclass, Pydantic or attrs).

    The remediation module is developed separately, so only duck typing is
    assumed: ``allowed_versions`` (list[str]) and ``preferred_version``
    (str | None) are the fields the guardrail relies on; the others are
    rendered into the prompt when present.
    """
    if candidates is None:
        data: dict[str, Any] = {}
    elif isinstance(candidates, dict):
        data = dict(candidates)
    elif hasattr(candidates, "model_dump") and callable(candidates.model_dump):
        data = dict(candidates.model_dump())
    elif hasattr(candidates, "to_dict") and callable(candidates.to_dict):
        data = dict(candidates.to_dict())
    elif is_dataclass(candidates) and not isinstance(candidates, type):
        data = asdict(candidates)
    else:
        data = {key: getattr(candidates, key) for key in _CANDIDATE_KEYS if hasattr(candidates, key)}
    view = {key: data.get(key) for key in _CANDIDATE_KEYS}
    view["allowed_versions"] = [str(v) for v in (view.get("allowed_versions") or []) if v is not None]
    view["notes"] = [str(n) for n in (view.get("notes") or [])]
    view["remaining_vulnerabilities"] = [str(v) for v in (view.get("remaining_vulnerabilities") or [])]
    if view.get("preferred_version") is not None:
        view["preferred_version"] = str(view["preferred_version"])
    return view


def _normalize_version(value: str | None) -> str:
    text = str(value or "").strip()
    for prefix in ("==", "=", "v", "V"):
        if text.startswith(prefix):
            text = text[len(prefix):].strip()
    return text


def _match_allowed_version(proposed: str | None, allowed: list[str]) -> str | None:
    """Return the allowed spelling matching ``proposed`` (tolerating ``v``/``==`` prefixes), else None."""
    wanted = _normalize_version(proposed)
    if not wanted:
        return None
    for candidate in allowed:
        if _normalize_version(candidate) == wanted:
            return candidate
    return None


# ------------------------------------------------------------------ component helpers


def _normalize_component(name: str) -> str:
    text = str(name or "").strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    text = text.rstrip("/")
    return text or "."


def filter_components(proposed: list[str], allowed: list[str]) -> tuple[list[str], list[str]]:
    """Keep only ``proposed`` names present in ``allowed`` (evidence spelling wins).

    Returns ``(kept, dropped)``; ``kept`` is de-duplicated and ordered as the
    model listed it, ``dropped`` keeps the model's original strings.
    """
    exact = {_normalize_component(a): a for a in allowed}
    folded = {key.lower(): value for key, value in exact.items()}
    kept: list[str] = []
    dropped: list[str] = []
    for name in proposed:
        key = _normalize_component(name)
        match = exact.get(key) or folded.get(key.lower())
        if match is None:
            dropped.append(str(name))
        elif match not in kept:
            kept.append(match)
    return kept, dropped


# ------------------------------------------------------------------ orchestrator


class AIOrchestrator:
    """Runs the agents for one finding and applies the evidence guardrails."""

    def __init__(
        self,
        provider: LLMProvider,
        settings: Settings,
        *,
        dependency_agent: DependencyAnalysisAgent | None = None,
        impact_agent: ImpactAssessmentAgent | None = None,
        risk_agent: RiskEvaluationAgent | None = None,
        remediation_agent: RemediationAgent | None = None,
    ) -> None:
        self.provider = provider
        self.settings = settings
        self.dependency_agent = dependency_agent or DependencyAnalysisAgent(provider, settings)
        self.impact_agent = impact_agent or ImpactAssessmentAgent(provider, settings)
        self.risk_agent = risk_agent or RiskEvaluationAgent(provider, settings)
        self.remediation_agent = remediation_agent or RemediationAgent(provider, settings)

    # ---------------------------------------------------------------- availability

    def available(self) -> tuple[bool, str]:
        """``(available, detail)`` from the provider's health check (never raises)."""
        try:
            return self.provider.health()
        except Exception as exc:  # noqa: BLE001 - health must never break the caller
            return False, f"LLM health check failed: {exc}"

    # ---------------------------------------------------------------- analysis

    def analyze_finding(self, context: FindingContext) -> FindingAIResult:
        """Run DependencyAnalysis → ImpactAssessment → RiskEvaluation for ``context``."""
        label = f"{context.dependency.package_name}@{context.dependency.version or '?'} / {context.vulnerability.identifier}"
        result = FindingAIResult(status="FAILED", model=self.provider.model_name)
        started = time.monotonic()
        logger.info("Analysing finding %s with model %s", label, result.model)

        # 1. Dependency analysis — the first LLM call decides whether the LLM is usable at all.
        outcome = self._run_agent(self.dependency_agent, result, context, first_call=True)
        if outcome is _UNAVAILABLE:
            result.status = "UNAVAILABLE"
            logger.warning("LLM unavailable for finding %s: %s", label, result.failures[-1].error)
            return result
        result.dependency_analysis = outcome

        # 2. Impact assessment (+ component guardrail).
        impact = self._run_agent(self.impact_agent, result, context, result.dependency_analysis)
        if isinstance(impact, ImpactAssessmentResult):
            result.impact = self._apply_component_guardrail(context, impact, result)

        # 3. Risk evaluation.
        risk = self._run_agent(self.risk_agent, result, context, result.dependency_analysis, result.impact)
        if isinstance(risk, RiskAssessmentResult):
            result.risk = risk

        succeeded = all(r is not None for r in (result.dependency_analysis, result.impact, result.risk))
        result.status = "COMPLETED" if succeeded else "FAILED"
        elapsed = time.monotonic() - started
        logger.info(
            "Finding %s: status=%s impact=%s risk=%s failures=%d dropped_components=%d (%.1fs)",
            label,
            result.status,
            result.impact.impact_level if result.impact else None,
            result.risk.risk_level if result.risk else None,
            len(result.failures),
            len(result.dropped_components),
            elapsed,
        )
        return result

    def _run_agent(self, agent: Any, result: FindingAIResult, *args: Any, first_call: bool = False) -> Any:
        """Run one agent; record failures on ``result`` instead of raising.

        Returns the agent result, ``None`` when the agent produced invalid
        output (or a later provider error), or the ``_UNAVAILABLE`` sentinel
        when the very first LLM call of this finding failed at the provider level.
        """
        started = time.monotonic()
        try:
            output = agent.run(*args)
        except AgentError as exc:
            result.failures.append(AgentFailure(agent=exc.agent, error=exc.error, raw_output=exc.raw_output))
            logger.warning("%s produced invalid output (%.1fs): %s", exc.agent, time.monotonic() - started, exc.error)
            return None
        except LLMError as exc:
            result.failures.append(AgentFailure(agent=agent.name, error=str(exc)))
            logger.warning("%s: LLM error (%.1fs): %s", agent.name, time.monotonic() - started, exc)
            return _UNAVAILABLE if first_call else None
        except Exception as exc:  # noqa: BLE001 - an agent bug must never abort the analysis
            result.failures.append(AgentFailure(agent=agent.name, error=f"unexpected {exc.__class__.__name__}: {exc}"))
            logger.exception("%s crashed (%.1fs)", agent.name, time.monotonic() - started)
            return None
        logger.info("%s finished in %.1fs", agent.name, time.monotonic() - started)
        return output

    @staticmethod
    def _apply_component_guardrail(
        context: FindingContext, impact: ImpactAssessmentResult, result: FindingAIResult
    ) -> ImpactAssessmentResult:
        allowed = allowed_component_names(context)
        kept, dropped = filter_components(impact.affected_components, allowed)
        if dropped:
            logger.warning(
                "ImpactAssessmentAgent named %d component(s) absent from the evidence; dropped: %s",
                len(dropped), ", ".join(dropped),
            )
            result.dropped_components.extend(dropped)
        return impact.model_copy(update={"affected_components": kept})

    # ---------------------------------------------------------------- remediation

    def recommend_remediation(
        self,
        context: FindingContext,
        candidates: Any,
        *,
        prior: FindingAIResult | dict | None = None,
    ) -> RemediationResult:
        """Ask the RemediationAgent to pick among ``candidates`` and enforce the version guardrail.

        ``candidates`` is a ``CandidateSet`` (or any object/dict exposing
        ``allowed_versions`` and ``preferred_version``). ``prior`` may carry the
        finding's earlier agent results (a ``FindingAIResult`` or its dict form)
        so the model sees the impact/risk reasoning. ``LLMError`` and
        ``AgentError`` propagate: the remediation service decides how to degrade.
        """
        view = candidate_view(candidates)
        dependency_analysis, impact, risk = _unpack_prior(prior)
        started = time.monotonic()
        logger.info(
            "Recommending remediation for %s@%s (%d allowed version(s), preferred=%s)",
            context.dependency.package_name,
            context.dependency.version or "?",
            len(view["allowed_versions"]),
            view.get("preferred_version"),
        )
        result = self.remediation_agent.run(context, view, dependency_analysis, impact, risk)
        result = self._apply_version_guardrail(result, view)
        logger.info(
            "Remediation recommendation: %s -> %s (confidence %.2f, %.1fs)",
            context.dependency.version or "?",
            result.recommended_version,
            result.confidence,
            time.monotonic() - started,
        )
        return result

    @staticmethod
    def _apply_version_guardrail(result: RemediationResult, view: dict[str, Any]) -> RemediationResult:
        allowed: list[str] = view["allowed_versions"]
        preferred: str | None = view.get("preferred_version")
        fallback = preferred if preferred is not None else (allowed[0] if allowed else None)
        proposed = result.recommended_version
        note: str | None = None

        if proposed is None:
            if fallback is not None:
                note = f"(no version proposed by the model; using the preferred candidate {fallback})"
            final = fallback
        else:
            matched = _match_allowed_version(proposed, allowed)
            if matched is not None:
                final = matched
            else:
                final = fallback
                note = f"(adjusted: model proposed {proposed} which is not an allowed candidate)"
                if fallback is None:
                    note += "; no safe candidate version is known, so no version is recommended"

        if note:
            logger.warning("Version guardrail: %s", note)
            reasoning = f"{result.reasoning.rstrip()} {note}".strip()
            return result.model_copy(update={"recommended_version": final, "reasoning": reasoning})
        if final != proposed:  # spelling normalised to the candidate's (e.g. "v2.32.4" -> "2.32.4")
            return result.model_copy(update={"recommended_version": final})
        return result


def _unpack_prior(
    prior: FindingAIResult | dict | None,
) -> tuple[DependencyAnalysisResult | None, ImpactAssessmentResult | None, RiskAssessmentResult | None]:
    if prior is None:
        return None, None, None
    if isinstance(prior, dict):
        try:
            prior = FindingAIResult.model_validate({"status": "COMPLETED", **prior})
        except Exception:  # noqa: BLE001 - prior results are a hint, never a hard requirement
            logger.warning("Ignoring unreadable prior AI results for remediation prompt")
            return None, None, None
    return prior.dependency_analysis, prior.impact, prior.risk


class _Unavailable:
    """Sentinel: the LLM could not be reached on the first call."""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<LLM unavailable>"


_UNAVAILABLE = _Unavailable()


__all__ = ["AIOrchestrator", "candidate_view", "filter_components"]
