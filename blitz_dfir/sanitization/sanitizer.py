from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any

from blitz_dfir.core.models import SignalWarning

MAX_FIELD_LENGTH = 2048
DEFAULT_MAX_EVENTS = 5000
MAX_EVENTS_ENV = "BLITZ_MAX_EVENTS"
MAX_EVENTS_HARD_LIMIT = 5_000_000


def _read_max_events() -> int:
    raw_value = os.getenv(MAX_EVENTS_ENV)
    if raw_value is None or raw_value.strip() == "":
        return DEFAULT_MAX_EVENTS
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{MAX_EVENTS_ENV} must be an integer") from exc
    if value < 1 or value > MAX_EVENTS_HARD_LIMIT:
        raise ValueError(f"{MAX_EVENTS_ENV} must be between 1 and {MAX_EVENTS_HARD_LIMIT}")
    return value


MAX_EVENTS = _read_max_events()


def configure_max_events(value: int) -> None:
    if value < 1 or value > MAX_EVENTS_HARD_LIMIT:
        raise ValueError(f"max events must be between 1 and {MAX_EVENTS_HARD_LIMIT}")
    global MAX_EVENTS
    MAX_EVENTS = value


def get_max_events() -> int:
    return MAX_EVENTS

ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
BIDI_CHARS_RE = re.compile("[\u202a-\u202e\u2066-\u2069]")
MARKDOWN_CONTROL_RE = re.compile(r"(```+|~~~+|<!--|-->)")
XML_WRAPPER_RE = re.compile(r"</?(system|assistant|user|instruction|instructions|prompt)[^>]*>", re.I)
PROMPT_INJECTION_RE = re.compile(
    r"(ignore\s+(all\s+)?previous\s+instructions|system\s+prompt|assistant\s*:|"
    r"you\s+are\s+chatgpt|###\s*system\s+override\s*###|delete\s+findings)",
    re.I,
)


@dataclass(frozen=True)
class SanitizedValue:
    value: str
    warnings: tuple[SignalWarning, ...]


def sanitize_text(value: Any, *, artifact: str, field: str) -> SanitizedValue:
    text = "" if value is None else str(value)
    warnings: list[SignalWarning] = []
    original = text

    text = ANSI_ESCAPE_RE.sub("", text)
    text = BIDI_CHARS_RE.sub("", text)
    text = CONTROL_CHARS_RE.sub("", text)
    text = XML_WRAPPER_RE.sub("[filtered]", text)
    text = MARKDOWN_CONTROL_RE.sub("[filtered]", text)
    text = PROMPT_INJECTION_RE.sub("[filtered]", text)

    if text != original:
        warnings.append(
            SignalWarning(
                warning_type="FIELD_SANITIZED",
                severity="MEDIUM",
                artifact=artifact,
                impact=f"sanitized field: {field}",
                metadata={"field": field},
            )
        )

    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) > MAX_FIELD_LENGTH:
        text = encoded[:MAX_FIELD_LENGTH].decode("utf-8", errors="replace")
        warnings.append(
            SignalWarning(
                warning_type="FIELD_TRUNCATION",
                severity="MEDIUM",
                artifact=artifact,
                impact=f"field exceeded {MAX_FIELD_LENGTH} bytes and was truncated",
                metadata={"field": field, "max_length": MAX_FIELD_LENGTH},
            )
        )

    return SanitizedValue(text, tuple(warnings))


def sanitize_mapping(values: dict[str, Any], *, artifact: str) -> tuple[dict[str, str], tuple[SignalWarning, ...]]:
    sanitized: dict[str, str] = {}
    warnings: list[SignalWarning] = []
    for key, value in values.items():
        safe_key = sanitize_text(key, artifact=artifact, field="field_name")
        safe_value = sanitize_text(value, artifact=artifact, field=safe_key.value)
        sanitized[safe_key.value] = safe_value.value
        warnings.extend(safe_key.warnings)
        warnings.extend(safe_value.warnings)
    return sanitized, tuple(warnings)


def event_cap_warning(*, artifact: str, processed: int, total: int) -> SignalWarning:
    max_events = get_max_events()
    return SignalWarning(
        warning_type="EVENT_TRUNCATION",
        severity="HIGH",
        artifact=artifact,
        impact=f"processed {processed} of {total} records due to MAX_EVENTS cap",
        metadata={"processed_events": processed, "estimated_total": total, "max_events": max_events},
    )
