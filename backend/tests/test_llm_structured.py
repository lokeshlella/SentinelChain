"""Unit tests for app.services.llm.structured (JSON extraction + validated generation)."""

from __future__ import annotations

import json

import pytest
from pydantic import BaseModel, Field, ValidationError

from app.services.agents.schemas import ImpactAssessmentResult, RemediationResult
from app.services.llm.base import LLMError
from app.services.llm.structured import (
    StructuredOutputError,
    extract_json,
    format_validation_error,
    generate_structured,
    strict_schema,
)
from tests.fixtures.llm.fake_provider import FakeLLMProvider


class Verdict(BaseModel):
    level: str = Field(pattern="^(LOW|HIGH)$")
    reasons: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)


# ------------------------------------------------------------------ extract_json


class TestExtractJson:
    def test_plain_object(self):
        assert extract_json('{"a": 1, "b": [1, 2]}') == {"a": 1, "b": [1, 2]}

    def test_json_code_fence(self):
        text = 'Here you go:\n```json\n{"level": "LOW", "confidence": 0.4}\n```\nDone.'
        assert extract_json(text) == {"level": "LOW", "confidence": 0.4}

    def test_bare_code_fence(self):
        assert extract_json('```\n{"x": true}\n```') == {"x": True}

    def test_leading_and_trailing_prose(self):
        text = 'Sure! The answer is {"level": "HIGH", "confidence": 1} — let me know if you need more.'
        assert extract_json(text) == {"level": "HIGH", "confidence": 1}

    def test_prose_with_braces_before_object(self):
        text = 'Note: use {package} placeholders. Result: {"ok": true}'
        assert extract_json(text) == {"ok": True}

    def test_trailing_commas_in_object_and_array(self):
        text = '{"reasons": ["a", "b",], "level": "LOW", "confidence": 0.2,}'
        assert extract_json(text) == {"reasons": ["a", "b"], "level": "LOW", "confidence": 0.2}

    def test_nested_braces_return_outermost_object(self):
        text = '{"outer": {"inner": {"deep": [{"k": "v"}]}}, "n": 1}'
        assert extract_json(text) == {"outer": {"inner": {"deep": [{"k": "v"}]}}, "n": 1}

    def test_braces_inside_strings_do_not_confuse_parser(self):
        text = '{"snippet": "def f(): return {\\"a\\": 1}", "confidence": 0.5}'
        assert extract_json(text) == {"snippet": 'def f(): return {"a": 1}', "confidence": 0.5}

    def test_first_of_two_objects_is_returned(self):
        assert extract_json('{"first": 1} {"second": 2}') == {"first": 1}

    def test_invalid_json_raises_with_raw_output(self):
        with pytest.raises(StructuredOutputError) as info:
            extract_json("The model says: {level: HIGH, confidence: high}")
        assert info.value.raw_output == "The model says: {level: HIGH, confidence: high}"
        assert "No JSON object" in str(info.value)

    def test_array_is_not_an_object(self):
        with pytest.raises(StructuredOutputError) as info:
            extract_json("[1, 2, 3]")
        assert "no opening brace" in str(info.value) or "expected an object" in str(info.value)

    @pytest.mark.parametrize("text", ["", "   \n", None])
    def test_empty_output_raises(self, text):
        with pytest.raises(StructuredOutputError, match="empty"):
            extract_json(text)  # type: ignore[arg-type]

    def test_plain_text_without_braces_raises(self):
        with pytest.raises(StructuredOutputError):
            extract_json("I cannot help with that.")


# ------------------------------------------------------------------ strict_schema


class TestStrictSchema:
    def test_all_top_level_keys_become_required(self):
        pydantic_schema = ImpactAssessmentResult.model_json_schema()
        assert "affected_components" not in pydantic_schema["required"]  # has a default
        schema = strict_schema(ImpactAssessmentResult)
        assert set(schema["required"]) == set(schema["properties"]) == {
            "affected_components", "impact_level", "facts", "inferences", "reasoning", "confidence",
        }
        # enum definition is preserved so the decoder can constrain the level
        assert schema["$defs"]["ImpactLevel"]["enum"] == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]

    def test_field_order_is_applied_and_unknown_names_ignored(self):
        schema = strict_schema(RemediationResult, ("reasoning", "recommended_version", "not-a-field"))
        keys = list(schema["properties"])
        assert keys[:2] == ["reasoning", "recommended_version"]
        assert set(keys) == set(RemediationResult.model_fields)
        assert schema["required"] == keys

    def test_original_model_schema_is_not_mutated(self):
        before = json.dumps(RemediationResult.model_json_schema(), sort_keys=True)
        strict_schema(RemediationResult, ("confidence",))
        assert json.dumps(RemediationResult.model_json_schema(), sort_keys=True) == before


# ------------------------------------------------------------------ validation error formatting


def test_format_validation_error_is_compact_and_names_the_field():
    with pytest.raises(ValidationError) as info:
        Verdict.model_validate({"level": "SEVERE", "confidence": 3})
    text = format_validation_error(info.value)
    assert "level:" in text and "SEVERE" in text
    assert "confidence:" in text
    assert len(text) < 400


# ------------------------------------------------------------------ generate_structured


def test_valid_first_answer_is_returned_without_retry():
    provider = FakeLLMProvider([{"level": "LOW", "reasons": ["r"], "confidence": 0.3}])
    result = generate_structured(provider, "PROMPT", "SYSTEM", Verdict, max_retries=2)
    assert result == Verdict(level="LOW", reasons=["r"], confidence=0.3)
    assert len(provider.calls) == 1
    call = provider.calls[0]
    assert call.prompt == "PROMPT" and call.system == "SYSTEM"
    assert call.json_schema == Verdict.model_json_schema()  # default schema is the model's own


def test_explicit_json_schema_is_forwarded_to_the_provider():
    provider = FakeLLMProvider([{"level": "LOW", "confidence": 0.3}])
    schema = strict_schema(Verdict, ("confidence", "level"))
    generate_structured(provider, "P", None, Verdict, json_schema=schema)
    assert provider.calls[0].json_schema is schema
    assert provider.calls[0].system is None


def test_invalid_then_valid_retries_with_correction_prompt():
    provider = FakeLLMProvider(
        [
            "Sure, here is my analysis without any JSON.",
            '```json\n{"level": "HIGH", "reasons": [], "confidence": 0.9}\n```',
        ]
    )
    result = generate_structured(provider, "ORIGINAL PROMPT", "SYS", Verdict, max_retries=2)
    assert result.level == "HIGH" and result.confidence == 0.9
    assert len(provider.calls) == 2
    correction = provider.calls[1].prompt
    assert correction.startswith("ORIGINAL PROMPT")  # the evidence is kept for the retry
    assert "Your previous output was invalid:" in correction
    assert "Previous output: Sure, here is my analysis without any JSON." in correction
    assert "Return ONLY a JSON object matching this schema:" in correction
    assert '"properties"' in correction and '"level"' in correction
    assert provider.calls[1].system == "SYS"


def test_validation_error_triggers_retry_with_field_name_in_prompt():
    provider = FakeLLMProvider(
        [
            {"level": "SEVERE", "confidence": 0.5},
            {"level": "HIGH", "confidence": 0.5},
        ]
    )
    result = generate_structured(provider, "P", None, Verdict, max_retries=1)
    assert result.level == "HIGH"
    assert "level:" in provider.calls[1].prompt and "SEVERE" in provider.calls[1].prompt


def test_failure_after_retries_raises_with_last_raw_output_and_attempts():
    provider = FakeLLMProvider(["garbage one", "garbage two", "garbage three"])
    with pytest.raises(StructuredOutputError) as info:
        generate_structured(provider, "P", None, Verdict, max_retries=2)
    err = info.value
    assert err.attempts == 3
    assert err.raw_output == "garbage three"
    assert "Verdict" in str(err) and "after 3 attempt(s)" in str(err)
    assert len(provider.calls) == 3
    assert not provider.responses  # every scripted answer was consumed


def test_zero_retries_means_a_single_attempt():
    provider = FakeLLMProvider(["nope"])
    with pytest.raises(StructuredOutputError) as info:
        generate_structured(provider, "P", None, Verdict, max_retries=0)
    assert info.value.attempts == 1
    assert len(provider.calls) == 1


def test_llm_error_propagates_without_retry():
    provider = FakeLLMProvider([LLMError("Ollama unreachable at http://localhost:11434; start it with `ollama serve`")])
    with pytest.raises(LLMError, match="ollama serve"):
        generate_structured(provider, "P", None, Verdict, max_retries=2)
    assert len(provider.calls) == 1


def test_long_previous_output_is_truncated_in_correction_prompt():
    provider = FakeLLMProvider(["x" * 5000, {"level": "LOW", "confidence": 0}])
    generate_structured(provider, "P", None, Verdict, max_retries=1)
    correction = provider.calls[1].prompt
    assert "...[truncated]" in correction
    assert correction.count("x") < 2000


def test_out_of_range_confidence_triggers_a_correction_round_not_a_clamp():
    """Audit F-15: 1.7 (or a percentage like 90) must not be silently normalised to 1.0."""
    provider = FakeLLMProvider([
        {"reasoning": "r", "recommended_version": "1.2.3", "confidence": 1.7},
        {"reasoning": "r", "recommended_version": "1.2.3", "confidence": 0.7},
    ])
    result = generate_structured(provider, "P", None, RemediationResult, max_retries=1)
    assert result.confidence == 0.7 and len(provider.calls) == 2
    assert "between 0 and 1" in provider.calls[1].prompt
