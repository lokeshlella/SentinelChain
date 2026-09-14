"""LLM provider contract. V1 ships OllamaProvider; V2 can add other providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar


@dataclass
class LLMResponse:
    text: str
    model: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    duration_ms: int | None = None


class LLMError(Exception):
    """The provider could not produce a response (unreachable, timeout, model missing, ...)."""


class LLMProvider(ABC):
    name: ClassVar[str]

    @property
    @abstractmethod
    def model_name(self) -> str: ...

    @abstractmethod
    def generate(
        self,
        prompt: str,
        *,
        system: str | None = None,
        json_schema: dict | None = None,
        temperature: float | None = None,
    ) -> LLMResponse:
        """Return the model's raw text. When ``json_schema`` is given, ask the model for JSON
        matching the schema (best effort — callers must still validate the output)."""

    @abstractmethod
    def health(self) -> tuple[bool, str]:
        """(available, detail)."""
