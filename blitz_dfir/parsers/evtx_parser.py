from __future__ import annotations

import json
from typing import Any

from blitz_dfir.core.models import EvidenceRecord, SignalWarning
from blitz_dfir.parsers.common import make_record
from blitz_dfir.parsers.models import ParsedRecord, ParserResult
from blitz_dfir.parsers.parser_validation import (
    build_parser_result,
    malformed_record_warning,
    parser_degradation_warning,
    validate_parser_compatibility,
)


def parse_evtx_json(text: str, evidence: EvidenceRecord) -> ParserResult:
    validate_parser_compatibility("evtx", evidence)
    warnings: list[SignalWarning] = []
    records: list[ParsedRecord] = []
    malformed = 0
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        warnings.append(parser_degradation_warning(artifact=evidence.evidence_id, reason="invalid JSON"))
        return build_parser_result(
            parser="evtx",
            source_tool="chainsaw",
            evidence=evidence,
            records=[],
            warnings=warnings,
            malformed_count=1,
        )
    items = payload if isinstance(payload, list) else payload.get("events", []) if isinstance(payload, dict) else []
    if not isinstance(items, list):
        warnings.append(parser_degradation_warning(artifact=evidence.evidence_id, reason="events is not a list"))
        items = []
    for index, item in enumerate(items, 1):
        if not isinstance(item, dict):
            malformed += 1
            warnings.append(
                malformed_record_warning(
                    artifact=evidence.evidence_id,
                    reason="event is not an object",
                    index=index,
                )
            )
            continue
        record_warnings: list[SignalWarning] = []
        records.append(
            make_record(
                parser="evtx",
                source_tool="chainsaw",
                evidence=evidence,
                timestamp=_first(item, "timestamp", "TimeCreated", "EventTime", "datetime"),
                event_type=_first(item, "event_id", "EventID", "event_type", default="evtx_event"),
                artifact=_first(item, "channel", "Channel", "source", default=evidence.evidence_id),
                message=_first(item, "message", "Message", "EventData", default=""),
                raw_reference=_first(item, "record_id", "EventRecordID", default=None),
                fields=item,
                warnings=record_warnings,
            )
        )
        warnings.extend(record_warnings)
    return build_parser_result(
        parser="evtx",
        source_tool="chainsaw",
        evidence=evidence,
        records=records,
        warnings=warnings,
        malformed_count=malformed,
    )


def _first(values: dict[str, Any], *keys: str, default: Any = "") -> Any:
    for key in keys:
        if key in values:
            return values[key]
    return default
