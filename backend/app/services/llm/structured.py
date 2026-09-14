"""Structured (JSON → Pydantic) output on top of any :class:`LLMProvider`.

Application logic never consumes free-form model text. ``generate_structured``
asks the provider for JSON, extracts the outermost object from whatever the
model wrote (code fences, leading prose, trailing commas are tolerated),
validates it against a Pydantic model and — when that fails — re-prompts the
model with the validation error and its previous output. After
``max_retries`` corrections a :class:`StructuredOutputError` carrying the raw
output is raised; nothing is ever fabricated.
"""

from __future__ import annotations

import json
import re
from typing import Sequence, TypeVar

from pydantic import BaseModel, ValidationError

from app.core.logging import get_stage_logger
from app.services.llm.base import LLMProvider

logger = get_stage_logger("AI")

ModelT = TypeVar("ModelT", bound=BaseModel)

_FENCE_RE = re.compile(r"```[a-zA-Z0-9_-]*\s*\n?(.*?)```", re.DOTALL)
_TRAILING_COMMA_RE = re.compile(r",(\s*[}\]])")
_MAX_RAW_IN_PROMPT = 1500
_MAX_ERROR_IN_PROMPT = 800


class StructuredOutputError(Exception):
    """The model did not produce output matching the requested schema."""

    def __init__(self, message: str, raw_output: str | None = None, attempts: int = 0) -> None:
        super().__init__(message)
        self.message = message
        self.raw_output = raw_output
        self.attempts = attempts


# ---------------------------------------------------------------------- extraction


def extract_json(text: str) -> dict:
    """Return the single outermost JSON object contained in ``text``.

    Tolerates markdown code fences, prose before/after the object and trailing
    commas before ``}`` / ``]`` (a light repair). Raises
    :class:`StructuredOutputError` when no JSON object can be decoded or the
    decoded value is not an object.
    """
    if text is None or not str(text).strip():
        raise StructuredOutputError("Model returned empty output", raw_output=text)
    source = str(text)
    candidates = [source]
    fenced = [m.group(1) for m in _FENCE_RE.finditer(source) if "{" in m.group(1)]
    # Prefer fenced blocks (the model was explicit), then the whole text.
    candidates = fenced + candidates

    last_error: str | None = None
    for candidate in candidates:
        obj, error = _decode_first_object(candidate)
        if obj is not None:
            return obj
        last_error = error or last_error
    raise StructuredOutputError(f"No JSON object found in model output ({last_error or 'no opening brace'})", raw_output=source)


def _decode_first_object(text: str) -> tuple[dict | None, str | None]:
    """Try to decode a JSON object starting at each ``{`` in ``text``.

    ``json.JSONDecoder.raw_decode`` parses one value and ignores anything after
    it, which handles trailing prose; trying every opening brace handles
    leading prose that itself contains braces. Falls back to a trailing-comma
    repair of the whole text.
    """
    decoder = json.JSONDecoder()
    variants = [text]
    repaired = _TRAILING_COMMA_RE.sub(r"\1", text)
    if repaired != text:
        variants.append(repaired)

    last_error: str | None = None
    for variant in variants:
        for start in _brace_positions(variant):
            try:
                value, _ = decoder.raw_decode(variant, start)
            except ValueError as exc:
                last_error = f"{exc.msg} at position {exc.pos}" if isinstance(exc, json.JSONDecodeError) else str(exc)
                continue
            if isinstance(value, dict):
                return value, None
            last_error = f"decoded a {type(value).__name__}, expected an object"
    return None, last_error


def _brace_positions(text: str, limit: int = 50):
    count = 0
    for index, char in enumerate(text):
        if char == "{":
            yield index
            count += 1
            if count >= limit:
                return


# ---------------------------------------------------------------------- schema


def strict_schema(model: type[BaseModel], field_order: Sequence[str] | None = None) -> dict:
    """JSON schema for ``model`` with every top-level property required, optionally re-ordered.

    Pydantic omits fields that have defaults from ``required``; a grammar-
    constrained decoder (Ollama ``format``) then lets the model skip them. Making
    them required forces the model to fill each key. ``field_order`` controls the
    order in which the model must emit the keys (e.g. reasoning before verdict).
    Validation still happens against the Pydantic model, so this only *tightens*
    what the model may produce.
    """
    schema = model.model_json_schema()
    props: dict = dict(schema.get("properties", {}))
    if field_order:
        ordered = {key: props[key] for key in field_order if key in props}
        ordered.update({key: value for key, value in props.items() if key not in ordered})
        props = ordered
    schema["properties"] = props
    schema["required"] = list(props.keys())
    return schema


# ---------------------------------------------------------------------- validation


def format_validation_error(exc: ValidationError) -> str:
    """Compact, model-friendly description of a Pydantic validation failure."""
    parts: list[str] = []
    for err in exc.errors()[:6]:
        location = ".".join(str(p) for p in err.get("loc", ())) or "<root>"
        message = err.get("msg", "invalid value")
        given = err.get("input")
        given_text = ""
        if given is not None and not isinstance(given, (dict, list)):
            given_text = f" (got {json.dumps(given)[:80]})"
        parts.append(f"{location}: {message}{given_text}")
    return "; ".join(parts)


def _correction_prompt(original_prompt: str, error: str, raw_output: str | None, schema: dict) -> str:
    raw = (raw_output or "").strip()
    if len(raw) > _MAX_RAW_IN_PROMPT:
        raw = raw[:_MAX_RAW_IN_PROMPT] + " ...[truncated]"
    error_text = error if len(error) <= _MAX_ERROR_IN_PROMPT else error[:_MAX_ERROR_IN_PROMPT] + " ..."
    return (
        f"{original_prompt}\n\n"
        f"Your previous output was invalid: {error_text}\n"
        f"Previous output: {raw or '<empty>'}\n"
        f"Return ONLY a JSON object matching this schema: {json.dumps(schema, separators=(',', ':'))}"
    )


def generate_structured(
    provider: LLMProvider,
    prompt: str,
    system: str | None,
    output_model: type[ModelT],
    max_retries: int = 2,
    json_schema: dict | None = None,
    *,
    temperature: float | None = None,
) -> ModelT:
    """Ask ``provider`` for JSON and validate it into ``output_model``.

    ``max_retries`` correction rounds follow the first attempt. Provider errors
    (:class:`LLMError`) propagate unchanged so callers can distinguish "the LLM
    is unavailable" from "the LLM produced bad output".
    """
    schema = json_schema if json_schema is not None else output_model.model_json_schema()
    attempts = 0
    current_prompt = prompt
    raw_output: str | None = None
    last_error = "no attempt made"
    total_rounds = max(0, int(max_retries)) + 1

    for round_index in range(total_rounds):
        attempts = round_index + 1
        response = provider.generate(current_prompt, system=system, json_schema=schema, temperature=temperature)
        raw_output = response.text
        try:
            data = extract_json(raw_output)
            result = output_model.model_validate(data)
        except StructuredOutputError as exc:
            last_error = exc.message
        except ValidationError as exc:
            last_error = format_validation_error(exc)
        except (TypeError, ValueError) as exc:
            # Raised by field validators (e.g. a non-numeric confidence) — Pydantic does not
            # wrap these, but they are still "invalid output" and deserve a correction round.
            last_error = f"{exc.__class__.__name__}: {exc}"
        else:
            logger.info(
                "%s parsed on attempt %d/%d (model=%s, prompt_tokens=%s, completion_tokens=%s, %sms)",
                output_model.__name__, attempts, total_rounds, response.model,
                response.prompt_tokens, response.completion_tokens, response.duration_ms,
            )
            return result
        logger.warning(
            "%s invalid on attempt %d/%d: %s", output_model.__name__, attempts, total_rounds, last_error
        )
        current_prompt = _correction_prompt(prompt, last_error, raw_output, schema)

    raise StructuredOutputError(
        f"{output_model.__name__}: model output invalid after {attempts} attempt(s): {last_error}",
        raw_output=raw_output,
        attempts=attempts,
    )
