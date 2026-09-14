"""Ollama implementation of :class:`LLMProvider`.

Talks to a local Ollama server over its HTTP API (``/api/chat`` for generation,
``/api/tags`` for health). Every transport / server problem is mapped to
:class:`LLMError` with an actionable message so callers can report the LLM as
"unavailable" instead of crashing the workflow.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from app.core.logging import get_stage_logger
from app.services.llm.base import LLMError, LLMProvider, LLMResponse

logger = get_stage_logger("AI")

_JSON_MODE = "json"


class OllamaProvider(LLMProvider):
    """LLM provider backed by a local Ollama server.

    Parameters
    ----------
    base_url:
        Ollama server root, e.g. ``http://localhost:11434``.
    model:
        Model tag as shown by ``ollama list`` (e.g. ``llama3.2:3b``).
    timeout:
        Seconds to wait for a single response (local 3B models on CPU can be slow).
    num_ctx:
        Context window requested from the server.
    temperature:
        Default sampling temperature (callers may override per request).
    client:
        Optional pre-built :class:`httpx.Client` (tests inject a ``MockTransport``).
    """

    name = "ollama"

    def __init__(
        self,
        base_url: str,
        model: str,
        timeout: float = 180,
        num_ctx: int = 8192,
        temperature: float = 0.1,
        client: httpx.Client | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.num_ctx = num_ctx
        self.temperature = temperature
        self._client = client or httpx.Client(timeout=httpx.Timeout(timeout, connect=10.0))

    # ------------------------------------------------------------------ contract

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
        """Run one chat completion and return the raw assistant text.

        When ``json_schema`` is given it is passed as Ollama's ``format`` so the
        server constrains decoding to the schema. If the server rejects the schema
        (HTTP 400) the request is retried once with ``format="json"``.
        """
        fmt: dict | str | None = json_schema if json_schema else None
        payload = self._build_payload(prompt, system=system, fmt=fmt, temperature=temperature)
        response = self._post_chat(payload)

        if response.status_code == 400 and isinstance(fmt, dict):
            logger.warning(
                "Ollama rejected the JSON schema format (400: %s); retrying with format='json'",
                _error_text(response),
            )
            payload = self._build_payload(prompt, system=system, fmt=_JSON_MODE, temperature=temperature)
            response = self._post_chat(payload)

        self._raise_for_status(response)
        return self._parse_response(response)

    def health(self) -> tuple[bool, str]:
        """GET ``/api/tags`` and check that the configured model is present (prefix match)."""
        try:
            response = self._client.get(f"{self.base_url}/api/tags", timeout=5)
        except httpx.HTTPError as exc:
            return False, f"Ollama unreachable at {self.base_url}: {exc.__class__.__name__}"
        if response.status_code != 200:
            return False, f"Ollama at {self.base_url} answered HTTP {response.status_code}"
        try:
            models = [str(m.get("name", "")) for m in response.json().get("models", [])]
        except (ValueError, AttributeError):
            return False, "Ollama returned an unreadable /api/tags response"
        if self._model_present(models):
            return True, f"model '{self.model}' available at {self.base_url}"
        available = ", ".join(models) if models else "none"
        return False, f"model '{self.model}' not pulled (available: {available}); run `ollama pull {self.model}`"

    # ------------------------------------------------------------------ helpers

    def _model_present(self, models: list[str]) -> bool:
        """Exact match, or ``<model>:latest`` when no tag was given (mirrors Ollama's own resolution).

        A looser prefix match would report ``llama3.2`` as available when only
        ``llama3.2:3b`` is pulled, although every generate() call would then 404.
        """
        wanted = {self.model}
        if ":" not in self.model:
            wanted.add(f"{self.model}:latest")
        return any(name in wanted for name in models if name)

    def _build_payload(
        self,
        prompt: str,
        *,
        system: str | None,
        fmt: dict | str | None,
        temperature: float | None,
    ) -> dict[str, Any]:
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.temperature if temperature is None else temperature,
                "num_ctx": self.num_ctx,
            },
        }
        if fmt is not None:
            payload["format"] = fmt
        return payload

    def _post_chat(self, payload: dict[str, Any]) -> httpx.Response:
        url = f"{self.base_url}/api/chat"
        try:
            # Keep a short connect timeout so an unreachable host fails fast; only the
            # read timeout scales with the model speed.
            return self._client.post(url, json=payload, timeout=httpx.Timeout(self.timeout, connect=10.0))
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            raise LLMError(f"Ollama unreachable at {self.base_url}; start it with `ollama serve`") from exc
        except httpx.TimeoutException as exc:
            raise LLMError(
                f"Ollama did not answer within {self.timeout:g}s (model {self.model}); "
                "increase OLLAMA_TIMEOUT or use a smaller model"
            ) from exc
        except httpx.HTTPError as exc:
            raise LLMError(f"Ollama request to {url} failed: {exc}") from exc

    def _raise_for_status(self, response: httpx.Response) -> None:
        if response.status_code == 200:
            return
        detail = _error_text(response)
        if response.status_code == 404 or "not found" in detail.lower():
            raise LLMError(f"Model {self.model} not available; run `ollama pull {self.model}`")
        raise LLMError(f"Ollama answered HTTP {response.status_code}: {detail}")

    def _parse_response(self, response: httpx.Response) -> LLMResponse:
        try:
            data = response.json()
        except ValueError as exc:
            raise LLMError("Ollama returned a non-JSON response body") from exc
        if not isinstance(data, dict):
            raise LLMError("Ollama returned an unexpected response shape")
        if data.get("error"):
            raise LLMError(f"Ollama error: {data['error']}")
        message = data.get("message") or {}
        text = message.get("content") if isinstance(message, dict) else None
        if text is None:
            raise LLMError("Ollama response contained no message content")
        total_ns = data.get("total_duration")
        return LLMResponse(
            text=str(text),
            model=str(data.get("model") or self.model),
            prompt_tokens=_int_or_none(data.get("prompt_eval_count")),
            completion_tokens=_int_or_none(data.get("eval_count")),
            duration_ms=int(total_ns / 1e6) if isinstance(total_ns, (int, float)) else None,
        )


def _error_text(response: httpx.Response) -> str:
    """Best-effort human readable error from an Ollama error body."""
    try:
        body = response.json()
        if isinstance(body, dict) and body.get("error"):
            err = body["error"]
            if isinstance(err, str):
                # Ollama sometimes nests a JSON error document inside the string.
                try:
                    nested = json.loads(err)
                    if isinstance(nested, dict) and isinstance(nested.get("error"), dict):
                        return str(nested["error"].get("message") or err)[:300]
                except ValueError:
                    pass
                return err[:300]
            return str(err)[:300]
    except ValueError:
        pass
    return (response.text or "").strip()[:300]


def _int_or_none(value: Any) -> int | None:
    return int(value) if isinstance(value, (int, float)) else None
