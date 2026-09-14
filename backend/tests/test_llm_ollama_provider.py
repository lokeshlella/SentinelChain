"""Unit tests for OllamaProvider using httpx.MockTransport (no network)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from app.core.config import Settings
from app.services.llm.base import LLMError, LLMProvider
from app.services.llm.factory import get_default_provider
from app.services.llm.ollama_provider import OllamaProvider

FIXTURES = Path(__file__).parent / "fixtures" / "llm"
CHAT_RESPONSE = json.loads((FIXTURES / "ollama_chat_response.json").read_text())
TAGS_RESPONSE = json.loads((FIXTURES / "ollama_tags_response.json").read_text())
BASE_URL = "http://ollama.test:11434"
SCHEMA = {"type": "object", "properties": {"summary": {"type": "string"}}, "required": ["summary"]}


def make_provider(handler, **kwargs) -> tuple[OllamaProvider, list[httpx.Request]]:
    """Provider wired to a MockTransport; returns it together with the captured requests."""
    requests: list[httpx.Request] = []

    def recording_handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return handler(request)

    client = httpx.Client(transport=httpx.MockTransport(recording_handler))
    defaults = dict(base_url=BASE_URL + "/", model="llama3.2:3b", timeout=42, num_ctx=4096, temperature=0.2)
    defaults.update(kwargs)
    return OllamaProvider(client=client, **defaults), requests


def ok_chat(_: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json=CHAT_RESPONSE)


# ------------------------------------------------------------------ request / response mapping


def test_generate_builds_chat_request_and_maps_response():
    provider, requests = make_provider(ok_chat)
    response = provider.generate("USER PROMPT", system="SYSTEM PROMPT", json_schema=SCHEMA)

    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert str(request.url) == f"{BASE_URL}/api/chat"  # trailing slash of base_url stripped
    body = json.loads(request.content)
    assert body["model"] == "llama3.2:3b"
    assert body["messages"] == [
        {"role": "system", "content": "SYSTEM PROMPT"},
        {"role": "user", "content": "USER PROMPT"},
    ]
    assert body["stream"] is False
    assert body["format"] == SCHEMA
    assert body["options"] == {"temperature": 0.2, "num_ctx": 4096}

    assert response.text == '{"summary": "HTTP Client for Python", "confidence": 0.9}'
    assert response.model == "llama3.2:3b"
    assert response.prompt_tokens == 54
    assert response.completion_tokens == 18
    assert response.duration_ms == 9486  # total_duration 9486746209 ns
    assert isinstance(provider, LLMProvider) and provider.model_name == "llama3.2:3b"


def test_generate_without_system_or_schema_omits_them():
    provider, requests = make_provider(ok_chat)
    provider.generate("hi", temperature=0.9)
    body = json.loads(requests[0].content)
    assert body["messages"] == [{"role": "user", "content": "hi"}]
    assert "format" not in body
    assert body["options"]["temperature"] == 0.9  # per-call override wins


def test_missing_token_counts_map_to_none():
    provider, _ = make_provider(lambda r: httpx.Response(200, json={"model": "m", "message": {"content": "{}"}}))
    response = provider.generate("p")
    assert response.text == "{}" and response.prompt_tokens is None and response.duration_ms is None


# ------------------------------------------------------------------ schema fallback


def test_400_for_schema_format_retries_once_with_json_mode():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if isinstance(body.get("format"), dict):
            return httpx.Response(400, json={"error": "JSON schema conversion failed: Unrecognized schema"})
        return httpx.Response(200, json=CHAT_RESPONSE)

    provider, requests = make_provider(handler)
    response = provider.generate("p", json_schema={"type": "banana"})
    assert response.text.startswith("{")
    assert len(requests) == 2
    assert json.loads(requests[0].content)["format"] == {"type": "banana"}
    assert json.loads(requests[1].content)["format"] == "json"


def test_400_in_json_mode_is_not_retried_again():
    provider, requests = make_provider(lambda r: httpx.Response(400, json={"error": "bad request"}))
    with pytest.raises(LLMError, match="HTTP 400"):
        provider.generate("p", json_schema=SCHEMA)
    assert len(requests) == 2  # schema attempt + one json-mode fallback, then give up


def test_400_without_schema_is_an_error_immediately():
    provider, requests = make_provider(lambda r: httpx.Response(400, json={"error": "bad request"}))
    with pytest.raises(LLMError, match="bad request"):
        provider.generate("p")
    assert len(requests) == 1


# ------------------------------------------------------------------ error mapping


def test_404_model_missing_gives_pull_instruction():
    provider, _ = make_provider(
        lambda r: httpx.Response(404, json={"error": "model 'llama3.2:3b' not found"}), model="llama3.2:3b"
    )
    with pytest.raises(LLMError) as info:
        provider.generate("p")
    assert str(info.value) == "Model llama3.2:3b not available; run `ollama pull llama3.2:3b`"


def test_connection_error_gives_serve_instruction():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    provider, _ = make_provider(handler)
    with pytest.raises(LLMError) as info:
        provider.generate("p")
    assert str(info.value) == f"Ollama unreachable at {BASE_URL}; start it with `ollama serve`"


def test_timeout_mentions_configured_seconds():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    provider, _ = make_provider(handler, timeout=42)
    with pytest.raises(LLMError, match="42s"):
        provider.generate("p")


def test_server_error_status_is_reported():
    provider, _ = make_provider(lambda r: httpx.Response(500, text="boom"))
    with pytest.raises(LLMError, match="HTTP 500: boom"):
        provider.generate("p")


def test_non_json_body_is_an_error():
    provider, _ = make_provider(lambda r: httpx.Response(200, text="<html>not json</html>"))
    with pytest.raises(LLMError, match="non-JSON"):
        provider.generate("p")


def test_error_field_in_200_body_is_an_error():
    provider, _ = make_provider(lambda r: httpx.Response(200, json={"error": "something broke"}))
    with pytest.raises(LLMError, match="something broke"):
        provider.generate("p")


def test_missing_message_content_is_an_error():
    provider, _ = make_provider(lambda r: httpx.Response(200, json={"model": "m", "done": True}))
    with pytest.raises(LLMError, match="no message content"):
        provider.generate("p")


# ------------------------------------------------------------------ health


def test_health_reports_model_available():
    provider, requests = make_provider(lambda r: httpx.Response(200, json=TAGS_RESPONSE))
    ok, detail = provider.health()
    assert ok is True and "llama3.2:3b" in detail
    assert requests[0].method == "GET" and str(requests[0].url) == f"{BASE_URL}/api/tags"


def test_health_untagged_model_does_not_match_tagged_pull():
    # Ollama resolves "llama3.2" to "llama3.2:latest", so only "llama3.2:3b" being pulled
    # means generate() would 404 — health must not report it as available.
    provider, _ = make_provider(lambda r: httpx.Response(200, json=TAGS_RESPONSE), model="llama3.2")
    ok, detail = provider.health()
    assert ok is False and "ollama pull llama3.2" in detail


def test_health_untagged_model_matches_latest_tag():
    tags = {"models": [{"name": "mistral:latest"}]}
    provider, _ = make_provider(lambda r: httpx.Response(200, json=tags), model="mistral")
    assert provider.health()[0] is True


def test_health_model_not_pulled():
    provider, _ = make_provider(lambda r: httpx.Response(200, json=TAGS_RESPONSE), model="mistral:7b")
    ok, detail = provider.health()
    assert ok is False
    assert "ollama pull mistral:7b" in detail and "llama3.2:3b" in detail


def test_health_unreachable():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    provider, _ = make_provider(handler)
    ok, detail = provider.health()
    assert ok is False and "unreachable" in detail


def test_health_bad_status_and_unreadable_body():
    provider, _ = make_provider(lambda r: httpx.Response(503, text="down"))
    assert provider.health() == (False, f"Ollama at {BASE_URL} answered HTTP 503")
    provider, _ = make_provider(lambda r: httpx.Response(200, text="not json"))
    assert provider.health()[0] is False


# ------------------------------------------------------------------ factory


def test_get_default_provider_uses_settings():
    settings = Settings(
        ollama_base_url="http://example.test:11434",
        ollama_model="phi3:mini",
        ollama_timeout=7,
        ollama_num_ctx=2048,
        ollama_temperature=0.5,
    )
    provider = get_default_provider(settings)
    assert isinstance(provider, OllamaProvider)
    assert provider.base_url == "http://example.test:11434"
    assert provider.model_name == "phi3:mini"
    assert provider.timeout == 7 and provider.num_ctx == 2048 and provider.temperature == 0.5
