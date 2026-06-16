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


def parse_pcap_json(text: str, evidence: EvidenceRecord) -> ParserResult:
    validate_parser_compatibility("pcap", evidence)
    warnings: list[SignalWarning] = []
    records: list[ParsedRecord] = []
    malformed = 0
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        warnings.append(parser_degradation_warning(artifact=evidence.evidence_id, reason="invalid JSON"))
        return build_parser_result(
            parser="pcap",
            source_tool="tshark",
            evidence=evidence,
            records=[],
            warnings=warnings,
            malformed_count=1,
        )
    items = payload if isinstance(payload, list) else []
    for index, item in enumerate(items, 1):
        fields = _extract_fields(item)
        if fields is None:
            malformed += 1
            warnings.append(
                malformed_record_warning(
                    artifact=evidence.evidence_id,
                    reason="packet is not a tshark JSON object",
                    index=index,
                )
            )
            continue
        src = _first(fields, "ip.src", "ipv6.src")
        dst = _first(fields, "ip.dst", "ipv6.dst")
        artifact = f"{src or '?'}->{dst or '?'}"
        record_warnings: list[SignalWarning] = []
        records.append(
            make_record(
                parser="pcap",
                source_tool="tshark",
                evidence=evidence,
                timestamp=_first(fields, "frame.time_epoch", "frame.time"),
                event_type="network_flow",
                artifact=artifact,
                message=_first(fields, "dns.qry.name", "http.host", "tls.handshake.extensions_server_name", default=""),
                raw_reference=index,
                fields=fields,
                warnings=record_warnings,
            )
        )
        warnings.extend(record_warnings)
    return build_parser_result(
        parser="pcap",
        source_tool="tshark",
        evidence=evidence,
        records=records,
        warnings=warnings,
        malformed_count=malformed,
    )


def _extract_fields(item: Any) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    source = item.get("_source")
    if isinstance(source, dict):
        layers = source.get("layers")
        if isinstance(layers, dict):
            return layers
    return item


def _first(values: dict[str, Any], *keys: str, default: str | None = None) -> Any:
    for key in keys:
        value = values.get(key)
        if isinstance(value, list) and value:
            return value[0]
        if value:
            return value
    return default
