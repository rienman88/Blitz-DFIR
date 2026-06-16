from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from blitz_dfir.core.integrity import hash_text
from blitz_dfir.core.models import NormalizedEvent, SignalWarning
from blitz_dfir.correlation.models import CorrelatedFinding, Contradiction
from blitz_dfir.reasoning.models import AnalystDecision, LLMMessage, LLMRequest, ReasoningResult
from blitz_dfir.reasoning.narrative import build_narrative, scrub_forbidden_language
from blitz_dfir.reasoning.provider import LLMProvider

MAX_PROMPT_EVENTS = 50
MAX_PROMPT_FINDINGS = 25
MAX_PROMPT_CONTRADICTIONS = 25
MAX_TEXT_FIELD = 180

FORBIDDEN_PAYLOAD_PATTERNS = (
    "raw_stdout",
    "raw_stderr",
    "raw_csv",
    "raw_json",
    "memory_dump",
    "execute_shell_cmd",
    "powershell",
    "cmd.exe /c",
)

TOOL_REQUEST_RE = re.compile(
    r"(execute_shell_cmd|subprocess|powershell|cmd\.exe|bash\s+-c|run\s+command|delete\s+evidence)",
    re.I,
)


class ReasoningContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: tuple[dict[str, object], ...] = ()
    findings: tuple[dict[str, object], ...] = ()
    contradictions: tuple[dict[str, object], ...] = ()
    warnings: tuple[dict[str, object], ...] = ()
    coverage: dict[str, object] = Field(default_factory=dict)
    confidence: dict[str, object] = Field(default_factory=dict)


def build_reasoning_context(
    *,
    events: tuple[NormalizedEvent, ...] = (),
    findings: tuple[CorrelatedFinding, ...] = (),
    contradictions: tuple[Contradiction, ...] = (),
    warnings: tuple[SignalWarning, ...] = (),
    coverage: Mapping[str, object] | None = None,
    confidence: Mapping[str, object] | None = None,
) -> ReasoningContext:
    return ReasoningContext(
        events=tuple(_event_summary(event) for event in events[:MAX_PROMPT_EVENTS]),
        findings=tuple(_finding_summary(finding) for finding in findings[:MAX_PROMPT_FINDINGS]),
        contradictions=tuple(
            _contradiction_summary(contradiction)
            for contradiction in contradictions[:MAX_PROMPT_CONTRADICTIONS]
        ),
        warnings=tuple(_warning_summary(warning) for warning in warnings[:MAX_PROMPT_CONTRADICTIONS]),
        coverage=dict(coverage or {}),
        confidence=dict(confidence or {}),
    )


def build_reasoning_prompt(context: ReasoningContext) -> LLMRequest:
    system = (
        "You are an incident-response reasoning assistant. Use only the provided bounded "
        "summaries. Do not request commands, tools, scripts, file writes, or evidence changes. "
        "Every conclusion must be labeled as INFERRED and must distinguish evidence support "
        "from uncertainty."
    )
    payload = json.dumps(context.model_dump(), separators=(",", ":"), ensure_ascii=True)
    for forbidden in FORBIDDEN_PAYLOAD_PATTERNS:
        payload = payload.replace(forbidden, "[redacted]")
    user = (
        "Return a single JSON object only. Do not use Markdown fences, prose introductions, "
        "or explanatory text outside the JSON object. Required keys: hypotheses, uncertainty, "
        "contradiction_notes, narrative, and decisions. Hypotheses must include hypothesis, "
        "evidence_event_ids, rationale, and confidence. "
        f"Bounded context: {payload}"
    )
    return LLMRequest(
        model="",
        messages=(
            LLMMessage(role="system", content=system),
            LLMMessage(role="user", content=user),
        ),
    )


def run_analyst_reasoning(
    *,
    provider: LLMProvider,
    model: str,
    context: ReasoningContext,
) -> ReasoningResult:
    request = build_reasoning_prompt(context).model_copy(update={"model": model})
    prompt_text = "\n".join(message.content for message in request.messages)
    prompt_hash = hash_text(prompt_text)
    response = provider.complete(request)
    parsed = _parse_llm_json(response.content)
    blocked = _blocked_tool_requests(response.content)

    from blitz_dfir.reasoning.contradiction import contradiction_notes_from_payload
    from blitz_dfir.reasoning.hypotheses import hypotheses_from_payload

    known_events = {str(event["event_id"]) for event in context.events if "event_id" in event}
    hypotheses = hypotheses_from_payload(parsed.get("hypotheses", ()), known_event_ids=known_events)
    contradiction_notes = contradiction_notes_from_payload(
        parsed.get("contradiction_notes", ()),
        context=context,
    )
    uncertainty = _bounded_text_tuple(parsed.get("uncertainty", ()))
    narrative = build_narrative(
        findings=context.findings,
        hypotheses=hypotheses,
        contradictions=contradiction_notes,
        model_narrative=str(parsed.get("narrative", "")),
    )
    decisions = _decisions_from_payload(parsed.get("decisions", ()), known_event_ids=known_events)
    if not decisions:
        decisions = (
            AnalystDecision(
                decision_id=f"DEC-{prompt_hash[:12].upper()}",
                why="Assess bounded normalized and correlated evidence summaries",
                expected="Supported hypotheses and uncertainty statements",
                actual="Reasoning output validated and labeled INFERRED",
                evidence_event_ids=tuple(sorted(known_events))[:10],
            ),
        )
    return ReasoningResult(
        hypotheses=hypotheses,
        uncertainty=uncertainty,
        contradiction_notes=contradiction_notes,
        narrative=scrub_forbidden_language(narrative),
        decisions=decisions,
        blocked_tool_requests=blocked,
        prompt_hash=prompt_hash,
        provider_metadata=response.provider_metadata,
        token_usage=response.token_usage,
    )


def _event_summary(event: NormalizedEvent) -> dict[str, object]:
    return {
        "event_id": event.event_id,
        "timestamp_utc": event.timestamp_utc,
        "category": event.category,
        "artifact": _safe_artifact(event.artifact),
        "source_tool": event.source_tool,
        "source_parser": event.source_parser,
        "evidence_id": event.evidence_id,
        "evidence_type": event.evidence_type.value,
        "trust_level": event.trust_level.value,
        "confidence": event.confidence,
        "fields": _safe_fields(event.normalized_fields),
        "warnings": [warning.warning_type for warning in event.warnings],
    }


def _finding_summary(finding: CorrelatedFinding) -> dict[str, object]:
    return {
        "finding_id": finding.finding_id,
        "finding_type": finding.finding_type,
        "title": _bounded_text(finding.title),
        "summary": _bounded_text(finding.summary),
        "supporting_event_ids": finding.supporting_event_ids,
        "confidence": finding.confidence,
        "confidence_modifiers": finding.confidence_modifiers,
        "attack_stages": finding.attack_stages,
    }


def _contradiction_summary(contradiction: Contradiction) -> dict[str, object]:
    return {
        "contradiction_id": contradiction.contradiction_id,
        "subject": _bounded_text(contradiction.subject),
        "field": contradiction.field,
        "left_value": _safe_artifact(contradiction.left_value),
        "right_value": _safe_artifact(contradiction.right_value),
        "severity": contradiction.severity,
        "reason": contradiction.reason,
        "event_ids": tuple(anchor.event_id for anchor in contradiction.evidence),
    }


def _warning_summary(warning: SignalWarning) -> dict[str, object]:
    return {
        "warning_type": warning.warning_type,
        "severity": warning.severity,
        "artifact": _safe_artifact(warning.artifact),
        "impact": _bounded_text(warning.impact),
        "confidence_penalty": warning.confidence_penalty,
    }


def _safe_fields(fields: Mapping[str, str]) -> dict[str, str]:
    allowed = {
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "dns_query",
        "http_host",
        "tls_sni",
        "byte_count",
        "unusual_port",
        "processid",
        "newprocessid",
        "parentprocessid",
        "pid",
        "ppid",
        "user",
        "username",
        "sha256",
        "md5",
    }
    safe: dict[str, str] = {}
    for key in sorted(fields):
        if key not in allowed:
            continue
        value = fields[key]
        if key in {"sha256", "md5"} and len(value) > 16:
            safe[key] = f"{value[:16]}..."
        else:
            safe[key] = _safe_artifact(value)
    return safe


def _safe_artifact(value: str) -> str:
    text = _bounded_text(value)
    text = re.sub(r"[A-Za-z]:/[^\s,;]+", "[path-redacted]", text)
    text = re.sub(r"/(?:Users|home|mnt|media|tmp)/[^\s,;]+", "[path-redacted]", text)
    text = re.sub(r"\\\\[^\\\s]+\\[^\s,;]+", "[path-redacted]", text)
    return text


def _bounded_text(value: object, limit: int = MAX_TEXT_FIELD) -> str:
    text = "" if value is None else str(value)
    text = " ".join(text.split())
    return text[:limit]


def _parse_llm_json(content: str) -> dict[str, Any]:
    parsed = _load_json_object(content)
    if parsed is None:
        extracted = _extract_json_object(content)
        parsed = _load_json_object(extracted) if extracted else None
    if parsed is None:
        return {
            "narrative": "",
            "hypotheses": [],
            "uncertainty": (
                "model response was not JSON",
                "model narrative suppressed because it was not valid structured output",
            ),
        }
    if not isinstance(parsed, dict):
        return {
            "narrative": "",
            "hypotheses": [],
            "uncertainty": (
                "model response was not a JSON object",
                "model narrative suppressed because it was not valid structured output",
            ),
        }
    return parsed


def _load_json_object(content: str) -> object | None:
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return None


def _extract_json_object(content: str) -> str | None:
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, flags=re.I | re.S)
    if fenced:
        return fenced.group(1)

    start = content.find("{")
    if start == -1:
        return None

    depth = 0
    in_string = False
    escaped = False
    for index, char in enumerate(content[start:], start=start):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return content[start : index + 1]
    return None


def _blocked_tool_requests(content: str) -> tuple[str, ...]:
    matches = sorted({match.group(0).lower() for match in TOOL_REQUEST_RE.finditer(content)})
    return tuple(matches)


def _bounded_text_tuple(value: object) -> tuple[str, ...]:
    if isinstance(value, list | tuple):
        return tuple(_bounded_text(item) for item in value if _bounded_text(item))
    if isinstance(value, str) and value.strip():
        return (_bounded_text(value),)
    return ()


def _decisions_from_payload(value: object, *, known_event_ids: set[str]) -> tuple[AnalystDecision, ...]:
    if not isinstance(value, list):
        return ()
    decisions: list[AnalystDecision] = []
    for index, item in enumerate(value, 1):
        if not isinstance(item, dict):
            continue
        event_ids = tuple(
            event_id
            for event_id in item.get("evidence_event_ids", ())
            if isinstance(event_id, str) and event_id in known_event_ids
        )
        decisions.append(
            AnalystDecision(
                decision_id=f"DEC-{index:03d}",
                why=_bounded_text(item.get("why", "bounded reasoning step")),
                expected=_bounded_text(item.get("expected", "evidence-supported output")),
                actual=_bounded_text(item.get("actual", "validated model output")),
                evidence_event_ids=event_ids,
            )
        )
    return tuple(decisions)
