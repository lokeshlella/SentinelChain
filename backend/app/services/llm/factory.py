"""Factory for the default LLM provider (Ollama is the only provider in V1)."""

from __future__ import annotations

from app.core.config import Settings, get_settings
from app.services.llm.base import LLMProvider
from app.services.llm.ollama_provider import OllamaProvider


def get_default_provider(settings: Settings | None = None) -> LLMProvider:
    """Build the provider configured by ``OLLAMA_BASE_URL`` / ``OLLAMA_MODEL``.

    Construction never touches the network; call :meth:`LLMProvider.health` to
    find out whether the server and model are actually usable.
    """
    settings = settings or get_settings()
    return OllamaProvider(
        base_url=settings.ollama_base_url,
        model=settings.ollama_model,
        timeout=settings.ollama_timeout,
        num_ctx=settings.ollama_num_ctx,
        temperature=settings.ollama_temperature,
    )
