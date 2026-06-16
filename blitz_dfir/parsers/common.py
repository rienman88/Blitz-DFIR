from __future__ import annotations

from typing import Any

from blitz_dfir.core.models import EvidenceRecord, SignalWarning
from blitz_dfir.parsers.models import ParsedRecord
from blitz_dfir.parsers.parser_validation import validate_timestamp
from blitz_dfir.sanitization.sanitizer import sanitize_mapping, sanitize_text


def make_record(
    *,
    parser: str,
    source_tool: str,
    evidence: EvidenceRecord,
    timestamp: Any,
    event_type: Any,
    artifact: Any,
    message: Any = "",
    raw_reference: Any = None,
    fields: dict[str, Any] | None = None,
    warnings: list[SignalWarning],
) -> ParsedRecord:
    artifact_text = sanitize_text(artifact, artifact=evidence.evidence_id, field="artifact")
    timestamp_text = sanitize_text(timestamp, artifact=evidence.evidence_id, field="timestamp")
    event_type_text = sanitize_text(event_type, artifact=evidence.evidence_id, field="event_type")
    message_text = sanitize_text(message, artifact=evidence.evidence_id, field="message")
    raw_reference_text = sanitize_text(
        raw_reference,
        artifact=evidence.evidence_id,
        field="raw_reference",
    )
    sanitized_fields, field_warnings = sanitize_mapping(fields or {}, artifact=evidence.evidence_id)
    warnings.extend(artifact_text.warnings)
    warnings.extend(timestamp_text.warnings)
    warnings.extend(event_type_text.warnings)
    warnings.extend(message_text.warnings)
    warnings.extend(raw_reference_text.warnings)
    warnings.extend(field_warnings)
    safe_timestamp = validate_timestamp(
        timestamp_text.value or None,
        artifact=evidence.evidence_id,
        warnings=warnings,
    )
    return ParsedRecord(
        parser=parser,
        source_tool=source_tool,
        evidence_id=evidence.evidence_id,
        evidence_type=evidence.category,
        trust_tier=evidence.trust_tier,
        timestamp=safe_timestamp,
        event_type=event_type_text.value or "unknown",
        artifact=artifact_text.value or evidence.evidence_id,
        message=message_text.value,
        raw_reference=raw_reference_text.value or None,
        fields=sanitized_fields,
        warnings=tuple(warnings),
    )

