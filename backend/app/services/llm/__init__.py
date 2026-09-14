"""LLM access layer: provider contract, the Ollama implementation and structured output."""

from app.services.llm.base import LLMError, LLMProvider, LLMResponse
from app.services.llm.factory import get_default_provider
from app.services.llm.ollama_provider import OllamaProvider
from app.services.llm.structured import StructuredOutputError, extract_json, generate_structured, strict_schema

__all__ = [
    "LLMError",
    "LLMProvider",
    "LLMResponse",
    "OllamaProvider",
    "StructuredOutputError",
    "extract_json",
    "generate_structured",
    "get_default_provider",
    "strict_schema",
]
