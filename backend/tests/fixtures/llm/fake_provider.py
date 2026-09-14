"""A scripted, network-free LLMProvider for unit tests.

``FakeLLMProvider([...])`` answers each ``generate`` call with the next queued
item: a string becomes the model text, a dict is JSON-encoded, and an
exception instance is raised. Every call is recorded in ``calls`` so tests can
assert on prompts, system prompts and schemas.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from app.services.llm.base import LLMProvider, LLMResponse


@dataclass
class RecordedCall:
    prompt: str
    system: str | None
    json_schema: dict | None
    temperature: float | None


@dataclass
class FakeLLMProvider(LLMProvider):
    """Queue-driven provider. Raises AssertionError when called more often than scripted."""

    responses: list[Any] = field(default_factory=list)
    model: str = "fake-model:1b"
    healthy: bool = True
    health_detail: str = "fake model available"
    calls: list[RecordedCall] = field(default_factory=list)

    name = "fake"

    @property
    def model_name(self) -> str:
        return self.model

    def generate(
        self,
        prompt: str,
        *,
        system: str | None = None,
        json_schema: dict | None = None,
        temperature: float | None = None,
    ) -> LLMResponse:
        self.calls.append(RecordedCall(prompt, system, json_schema, temperature))
        if not self.responses:
            raise AssertionError(f"FakeLLMProvider received an unscripted call #{len(self.calls)}")
        item = self.responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        text = json.dumps(item) if isinstance(item, dict) else str(item)
        return LLMResponse(text=text, model=self.model, prompt_tokens=10, completion_tokens=5, duration_ms=1)

    def health(self) -> tuple[bool, str]:
        return self.healthy, self.health_detail
