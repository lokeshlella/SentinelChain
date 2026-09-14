"""Base class shared by the AI agents.

An agent = one prompt builder + one strict output model. ``run`` delegates to
:func:`generate_structured`, so parsing, validation and correction retries are
identical for every agent. Malformed output surfaces as :class:`AgentError`;
provider failures (:class:`LLMError`) propagate unchanged so the orchestrator
can tell "the LLM is down" apart from "the LLM answered badly".
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ClassVar, Generic, TypeVar

from pydantic import BaseModel

from app.core.config import Settings
from app.core.logging import get_stage_logger
from app.services.agents.prompts import SYSTEM_PROMPT
from app.services.llm.base import LLMProvider
from app.services.llm.structured import StructuredOutputError, generate_structured, strict_schema

logger = get_stage_logger("AI")

ResultT = TypeVar("ResultT", bound=BaseModel)


class AgentError(Exception):
    """An agent could not produce a valid structured result."""

    def __init__(self, agent: str, error: str, raw_output: str | None = None) -> None:
        super().__init__(f"{agent}: {error}")
        self.agent = agent
        self.error = error
        self.raw_output = raw_output


class BaseAgent(ABC, Generic[ResultT]):
    """Template for the four V1 agents.

    Subclasses set ``name`` and ``output_model`` and implement
    :meth:`build_prompt`; the positional/keyword arguments of ``run`` are
    forwarded to ``build_prompt`` unchanged.
    """

    name: ClassVar[str] = "agent"
    output_model: ClassVar[type[BaseModel]]
    system_prompt: ClassVar[str] = SYSTEM_PROMPT
    #: Order in which the model must emit the JSON keys (reasoning before verdicts helps small models).
    field_order: ClassVar[tuple[str, ...] | None] = None

    def __init__(self, provider: LLMProvider, settings: Settings) -> None:
        self.provider = provider
        self.settings = settings

    @property
    def max_retries(self) -> int:
        return int(getattr(self.settings, "llm_max_retries", 2))

    def json_schema(self) -> dict:
        """Decoding schema sent to the provider: every key required, in ``field_order``."""
        return strict_schema(self.output_model, self.field_order)

    @abstractmethod
    def build_prompt(self, *args: Any, **kwargs: Any) -> str:
        """Render the user prompt for this agent from the given context."""

    def run(self, *args: Any, **kwargs: Any) -> ResultT:
        """Build the prompt, query the model and return a validated result.

        Raises :class:`AgentError` when the model output stays invalid after
        the configured retries; :class:`LLMError` propagates unchanged.
        """
        prompt = self.build_prompt(*args, **kwargs)
        logger.info("%s: querying %s (prompt %d chars)", self.name, self.provider.model_name, len(prompt))
        try:
            result = generate_structured(
                self.provider,
                prompt,
                self.system_prompt,
                self.output_model,
                max_retries=self.max_retries,
                json_schema=self.json_schema(),
            )
        except StructuredOutputError as exc:
            logger.warning("%s failed after %d attempt(s): %s", self.name, exc.attempts, exc.message)
            raise AgentError(self.name, exc.message, exc.raw_output) from exc
        return result  # type: ignore[return-value]
