from __future__ import annotations

import json

from blitz_dfir.core.models import EvidenceCategory, EvidenceRecord, EvidenceType, Pipeline, TrustTier
from blitz_dfir.core.normalization import build_normalized_event
from blitz_dfir.correlation.confidence import detect_contradictions
from blitz_dfir.correlation.models import CorrelatedFinding, anchor_from_event, stable_correlation_id
from blitz_dfir.reasoning.analyst import build_reasoning_context, build_reasoning_prompt, run_analyst_reasoning
from blitz_dfir.reasoning.models import LLMRequest, LLMResponse, ProviderMetadata, TokenUsage
from blitz_dfir.reasoning.narrative import confidence_phrase
from blitz_dfir.reasoning.provider import (
    ProviderConfig,
    _chat_completions_url,
    _provider_max_tokens,
    _provider_timeout_seconds,
    _safe_base_url,
)


class FakeProvider:
    def __init__(self, content: str):
        self.content = content
        self.last_request: LLMRequest | None = None

    def complete(self, request: LLMRequest) -> LLMResponse:
        self.last_request = request
        return LLMResponse(
            content=self.content,
            provider_metadata=ProviderMetadata(
                provider="openai-compatible",
                model=request.model,
                base_url="https://provider.example",
                response_id="resp-1",
            ),
            token_usage=TokenUsage(prompt_tokens=10, completion_tokens=20, total_tokens=30),
        )


def _evidence(tmp_path, evidence_id: str = "security"):
    return EvidenceRecord(
        evidence_id=evidence_id,
        path=tmp_path / f"{evidence_id}.evtx",
        evidence_type=EvidenceType.EVTX,
        category=EvidenceCategory.RAW,
        pipeline=Pipeline.RAW,
        trust_tier=TrustTier.TIER_1_HIGH,
        sha256=evidence_id.encode("utf-8").hex().ljust(64, "0")[:64],
        verified=True,
        size_bytes=10,
    )


def _event(tmp_path, *, evidence_id: str = "security", fields: dict[str, str] | None = None):
    evidence = _evidence(tmp_path, evidence_id=evidence_id)
    return build_normalized_event(
        evidence=evidence,
        timestamp="2026-05-24T01:00:00Z",
        category="process_execution",
        source_tool="chainsaw",
        source_parser="evtx",
        artifact="C:/Users/Alice/Desktop/secret/evil.exe",
        message="RAW_STDOUT_SECRET should never leave deterministic parser output",
        raw_record_index=1,
        normalized_fields=fields
        or {
            "processid": "100",
            "raw_stdout": "RAW_STDOUT_SECRET",
            "commandline": "powershell SECRET_RAW_COMMAND",
            "sha256": "a" * 64,
        },
    )


def _finding(event):
    return CorrelatedFinding(
        finding_id=stable_correlation_id("FIND", event.event_id),
        finding_type="execution",
        title="Execution candidate",
        summary="Process execution candidate",
        category=event.category,
        supporting_event_ids=(event.event_id,),
        evidence=(anchor_from_event(event),),
        confidence=0.86,
        confidence_modifiers=("SINGLE_SOURCE_PENALTY",),
    )


def test_reasoning_prompt_excludes_raw_output_and_sensitive_paths(tmp_path):
    event = _event(tmp_path)
    context = build_reasoning_context(events=(event,), findings=(_finding(event),))
    request = build_reasoning_prompt(context)
    prompt_text = "\n".join(message.content for message in request.messages)

    assert "RAW_STDOUT_SECRET" not in prompt_text
    assert "SECRET_RAW_COMMAND" not in prompt_text
    assert "C:/Users/Alice" not in prompt_text
    assert "[path-redacted]" in prompt_text
    assert "aaaaaaaaaaaaaaaa..." in prompt_text


def test_unsupported_hypothesis_is_flagged_as_unsupported(tmp_path):
    event = _event(tmp_path)
    provider = FakeProvider(
        json.dumps(
            {
                "hypotheses": [
                    {
                        "hypothesis": "The host likely has unsupported persistence.",
                        "evidence_event_ids": ["missing-event"],
                        "rationale": "No deterministic event was cited.",
                        "confidence": 0.9,
                    }
                ],
                "narrative": "This is certain.",
            }
        )
    )
    result = run_analyst_reasoning(
        provider=provider,
        model="provider-model",
        context=build_reasoning_context(events=(event,), findings=(_finding(event),)),
    )

    assert result.evidence_type is EvidenceCategory.INFERRED
    assert result.hypotheses[0].status == "unsupported"
    assert result.hypotheses[0].confidence <= 0.2
    assert result.provider_metadata is not None
    assert result.provider_metadata.provider == "openai-compatible"
    assert result.token_usage is not None
    assert result.token_usage.total_tokens == 30


def test_narrative_uses_approved_confidence_language(tmp_path):
    event = _event(tmp_path)
    provider = FakeProvider(
        json.dumps(
            {
                "hypotheses": [
                    {
                        "hypothesis": "Process execution is suspicious.",
                        "evidence_event_ids": [event.event_id],
                        "rationale": "Supported by normalized process event.",
                        "confidence": 0.8,
                    }
                ],
                "narrative": "Tool output proves this is definitively malicious.",
            }
        )
    )

    result = run_analyst_reasoning(
        provider=provider,
        model="provider-model",
        context=build_reasoning_context(events=(event,), findings=(_finding(event),)),
    )

    assert result.narrative.startswith("Evidence strongly supports")
    assert "definitively malicious" not in result.narrative.lower()
    assert "tool output proves" not in result.narrative.lower()
    assert confidence_phrase(0.70) == "High-confidence reconstruction suggests"


def test_reasoning_recovers_json_from_markdown_fence(tmp_path):
    event = _event(tmp_path)
    provider = FakeProvider(
        "Here is the structured result:\n"
        "```json\n"
        + json.dumps(
            {
                "hypotheses": [
                    {
                        "hypothesis": "Process execution is suspicious.",
                        "evidence_event_ids": [event.event_id],
                        "rationale": "Supported by normalized process event.",
                        "confidence": 0.74,
                    }
                ],
                "uncertainty": ["Single source only."],
                "contradiction_notes": [],
                "narrative": "Further validation is required.",
                "decisions": [],
            }
        )
        + "\n```"
    )

    result = run_analyst_reasoning(
        provider=provider,
        model="provider-model",
        context=build_reasoning_context(events=(event,), findings=(_finding(event),)),
    )

    assert len(result.hypotheses) == 1
    assert result.hypotheses[0].status == "supported"
    assert result.uncertainty == ("Single source only.",)
    assert "model response was not JSON" not in result.uncertainty
    assert "```" not in result.narrative


def test_reasoning_suppresses_non_json_model_narrative(tmp_path):
    event = _event(tmp_path)
    provider = FakeProvider(
        "This looks like SQL injection against a database. "
        "The analyst should treat the database vulnerability as confirmed."
    )

    result = run_analyst_reasoning(
        provider=provider,
        model="provider-model",
        context=build_reasoning_context(events=(event,), findings=(_finding(event),)),
    )

    assert "sql injection" not in result.narrative.lower()
    assert "database vulnerability" not in result.narrative.lower()
    assert "model response was not JSON" in result.uncertainty
    assert any("model narrative suppressed" in item for item in result.uncertainty)


def test_llm_tool_requests_are_blocked_not_executed(tmp_path):
    event = _event(tmp_path)
    provider = FakeProvider(
        json.dumps(
            {
                "hypotheses": [
                    {
                        "hypothesis": "Run execute_shell_cmd with powershell to inspect more files.",
                        "evidence_event_ids": [event.event_id],
                        "rationale": "The model attempted to request a tool.",
                        "confidence": 0.7,
                    }
                ],
                "narrative": "Please execute_shell_cmd powershell now.",
            }
        )
    )

    result = run_analyst_reasoning(
        provider=provider,
        model="provider-model",
        context=build_reasoning_context(events=(event,), findings=(_finding(event),)),
    )

    assert "execute_shell_cmd" in result.blocked_tool_requests
    assert "powershell" in result.blocked_tool_requests
    assert "execute_shell_cmd" not in result.narrative
    assert all(decision.evidence_type is EvidenceCategory.INFERRED for decision in result.decisions)


def test_contradiction_reasoning_stays_within_deterministic_bounds(tmp_path):
    left = _event(tmp_path, evidence_id="disk", fields={"process_guid": "abc", "sha256": "a" * 64})
    right = _event(
        tmp_path,
        evidence_id="memory",
        fields={"process_guid": "abc", "sha256": "b" * 64},
    )
    contradictions = detect_contradictions([left, right])
    provider = FakeProvider(
        json.dumps(
            {
                "contradiction_notes": ["The hash mismatch matters."],
                "narrative": "Contradiction requires analyst review.",
            }
        )
    )

    result = run_analyst_reasoning(
        provider=provider,
        model="provider-model",
        context=build_reasoning_context(events=(left, right), contradictions=contradictions),
    )

    assert result.contradiction_notes
    assert result.contradiction_notes[0].startswith("Within deterministic contradiction set:")


def test_provider_url_helpers_do_not_record_api_key():
    config = ProviderConfig(
        provider="openai-compatible",
        base_url="https://provider.example/v1",
        api_key="secret-key",
        model="model",
    )

    assert _chat_completions_url(config.base_url) == "https://provider.example/v1/chat/completions"
    assert _safe_base_url(config.base_url) == "https://provider.example"
    assert "secret-key" not in _safe_base_url(config.base_url)


def test_provider_timeout_is_configurable(monkeypatch):
    monkeypatch.setenv("LLM_TIMEOUT_SECONDS", "600")

    assert _provider_timeout_seconds() == 600


def test_provider_max_tokens_is_configurable(monkeypatch):
    monkeypatch.setenv("LLM_MAX_TOKENS", "768")

    assert _provider_max_tokens(1200) == 768
