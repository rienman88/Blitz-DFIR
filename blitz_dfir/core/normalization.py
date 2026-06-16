from __future__ import annotations

import ast
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from blitz_dfir.core.integrity import hash_text
from blitz_dfir.core.models import (
    EvidenceCategory,
    EvidenceRecord,
    NormalizedEvent,
    RawReference,
    SignalWarning,
    TrustTier,
)
from blitz_dfir.parsers.models import ParsedRecord, ParserResult
from blitz_dfir.sanitization.sanitizer import event_cap_warning, get_max_events

UNKNOWN_TIMESTAMP_UTC = "1970-01-01T00:00:00Z"

CATEGORY_ALIASES = {
    "4624": "authentication_logon",
    "4625": "authentication_failure",
    "4634": "authentication_logoff",
    "4648": "explicit_credential_logon",
    "4672": "privileged_logon",
    "4688": "process_execution",
    "4697": "service_install",
    "7045": "service_install",
    "network_flow": "network_flow",
    "string": "string_artifact",
    "yara_match": "yara_match",
    "timeline_event": "timeline_event",
    "windows.pslist": "memory_process",
    "windows.pstree": "memory_process_tree",
    "windows.psscan": "memory_process_scan",
    "windows.cmdline": "process_execution",
    "windows.netscan": "network_flow",
    "windows.malfind": "memory_injection_candidate",
}

HASH_FIELD_NAMES = {
    "md5": 32,
    "sha1": 40,
    "sha256": 64,
}

USERNAME_FIELD_NAMES = {
    "user",
    "username",
    "accountname",
    "targetusername",
    "subjectusername",
    "domainuser",
    "user_name",
}

PATH_FIELD_NAMES = {
    "path",
    "filepath",
    "file_name",
    "filename",
    "imagepath",
    "commandline",
    "target",
}


class NormalizationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: tuple[NormalizedEvent, ...]
    warnings: tuple[SignalWarning, ...] = ()
    processed_count: int = Field(ge=0)
    truncated: bool = False


def stable_event_id(*parts: str) -> str:
    canonical = "|".join(_canonical_id_part(part) for part in parts)
    digest = hash_text(canonical)[:12].upper()
    return f"EVT-{digest}"


def normalize_timestamp(value: datetime | str | int | float | None) -> str:
    parsed = _parse_timestamp(value)
    if parsed is None:
        return UNKNOWN_TIMESTAMP_UTC
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def normalize_path(value: Any) -> str:
    text = "" if value is None else str(value).strip()
    if not text:
        return ""
    text = text.replace("\\", "/")
    text = re.sub(r"/+", "/", text)
    if len(text) > 1 and text[1] == ":":
        text = text[0].upper() + text[1:]
    return text


def normalize_hash(value: Any) -> str:
    text = "" if value is None else str(value).strip().lower()
    return re.sub(r"\s+", "", text)


def normalize_username(value: Any) -> str:
    text = "" if value is None else str(value).strip()
    if not text:
        return ""
    text = text.replace("\\", "/")
    if text.startswith("./"):
        text = text[2:]
    return text.lower()


def normalize_category(event_type: Any, fields: Mapping[str, str] | None = None) -> str:
    text = _canonical_text(event_type)
    fields = fields or {}
    if text == "network_flow":
        return _pcap_category(fields)
    return CATEGORY_ALIASES.get(text, text or "unknown")


def sort_normalized_events(events: tuple[NormalizedEvent, ...] | list[NormalizedEvent]) -> tuple[NormalizedEvent, ...]:
    return tuple(sorted(events, key=lambda event: (event.timestamp_utc, event.event_id)))


def build_normalized_event(
    *,
    evidence: EvidenceRecord,
    timestamp: datetime | str | int | float | None,
    category: str,
    source_tool: str,
    source_parser: str,
    artifact: str | None = None,
    message: str = "",
    raw_path: str | None = None,
    raw_offset: int | None = None,
    raw_record_index: int | None = None,
    confidence: float = 1.0,
    warnings: tuple[SignalWarning, ...] = (),
    normalized_fields: dict[str, str] | None = None,
    provenance: dict[str, Any] | None = None,
) -> NormalizedEvent:
    timestamp_utc = normalize_timestamp(timestamp)
    safe_category = normalize_category(category, normalized_fields)
    safe_artifact = normalize_path(artifact or raw_path or evidence.path.name)
    safe_message = "" if message is None else str(message)
    fields = _sorted_fields(normalized_fields or {})
    event_id = stable_event_id(
        evidence.evidence_id,
        timestamp_utc,
        safe_category,
        source_tool,
        source_parser,
        safe_artifact,
        str(raw_offset or ""),
        str(raw_record_index or ""),
        hash_text(safe_message)[:12],
    )
    return NormalizedEvent(
        event_id=event_id,
        timestamp_utc=timestamp_utc,
        category=safe_category,
        artifact=safe_artifact,
        message=safe_message,
        source_tool=source_tool,
        source_parser=source_parser,
        evidence_id=evidence.evidence_id,
        evidence_type=evidence.category,
        trust_level=evidence.trust_tier,
        trust_tier=evidence.trust_tier,
        raw_reference=RawReference(
            evidence_id=evidence.evidence_id,
            path=normalize_path(raw_path),
            offset=raw_offset,
            record_index=raw_record_index,
            original_hash=normalize_hash(evidence.sha256),
        ),
        confidence=confidence,
        normalized_fields=fields,
        provenance=_sorted_provenance(provenance or {}),
        warnings=warnings,
    )


def normalize_parsed_record(
    record: ParsedRecord,
    *,
    evidence: EvidenceRecord | None = None,
) -> NormalizedEvent:
    timestamp_utc = normalize_timestamp(record.timestamp)
    timestamp_warnings = _timestamp_warnings(record, timestamp_utc)
    fields = normalize_fields(record)
    category = normalize_category(record.event_type, fields)
    raw_reference = _raw_reference(record.raw_reference)
    evidence_id = evidence.evidence_id if evidence else record.evidence_id
    evidence_category = _lowest_evidence_category(
        record.evidence_type,
        evidence.category if evidence else record.evidence_type,
    )
    trust_level = _lowest_trust(record.trust_tier, evidence.trust_tier if evidence else record.trust_tier)
    original_hash = normalize_hash(evidence.sha256) if evidence else None
    artifact = _normalized_artifact(record)
    message = str(record.message or "")
    event_id = stable_event_id(
        evidence_id,
        timestamp_utc,
        category,
        record.source_tool,
        record.parser,
        artifact,
        raw_reference.path or "",
        str(raw_reference.offset or ""),
        str(raw_reference.record_index or ""),
        hash_text(message)[:12],
    )
    return NormalizedEvent(
        event_id=event_id,
        timestamp_utc=timestamp_utc,
        category=category,
        artifact=artifact,
        message=message,
        source_tool=record.source_tool,
        source_parser=record.parser,
        evidence_id=evidence_id,
        evidence_type=evidence_category,
        trust_level=trust_level,
        trust_tier=trust_level,
        raw_reference=RawReference(
            evidence_id=evidence_id,
            path=raw_reference.path,
            offset=raw_reference.offset,
            record_index=raw_reference.record_index,
            original_hash=original_hash,
        ),
        confidence=_confidence_from_warnings(record.warnings),
        normalized_fields=fields,
        provenance={
            "parser": record.parser,
            "source_tool": record.source_tool,
            "source_event_type": str(record.event_type),
        },
        warnings=tuple(record.warnings + timestamp_warnings),
    )


def normalize_parser_result(
    result: ParserResult,
    *,
    evidence: EvidenceRecord | None = None,
) -> NormalizationResult:
    return _normalize_parser_result(result, evidence=evidence, sort_events=True)


def _normalize_parser_result(
    result: ParserResult,
    *,
    evidence: EvidenceRecord | None = None,
    sort_events: bool,
) -> NormalizationResult:
    max_events = get_max_events()
    warnings = list(result.warnings)
    source_count = len(result.records)
    source_records = result.records
    truncated = result.truncated or source_count > max_events
    if source_count > max_events:
        warnings.append(
            event_cap_warning(
                artifact=result.evidence_id,
                processed=max_events,
                total=source_count,
            )
        )
        source_records = source_records[:max_events]
    elif result.truncated and not any(w.warning_type == "EVENT_TRUNCATION" for w in warnings):
        warnings.append(
            event_cap_warning(
                artifact=result.evidence_id,
                processed=len(source_records),
                total=max(result.processed_count, len(source_records)),
            )
        )
    events = [normalize_parsed_record(record, evidence=evidence) for record in source_records]
    normalized_events = sort_normalized_events(events) if sort_events else tuple(events)
    return NormalizationResult(
        events=normalized_events,
        warnings=tuple(warnings),
        processed_count=len(normalized_events),
        truncated=truncated,
    )


def normalize_parser_results(
    results: list[ParserResult] | tuple[ParserResult, ...],
    *,
    evidence_by_id: Mapping[str, EvidenceRecord] | None = None,
) -> NormalizationResult:
    max_events = get_max_events()
    warnings: list[SignalWarning] = []
    events: list[NormalizedEvent] = []
    truncated = False
    for result in results:
        evidence = evidence_by_id.get(result.evidence_id) if evidence_by_id else None
        normalized = _normalize_parser_result(result, evidence=evidence, sort_events=False)
        warnings.extend(normalized.warnings)
        events.extend(normalized.events)
        truncated = truncated or normalized.truncated
    if len(events) > max_events:
        warnings.append(event_cap_warning(artifact="normalized_batch", processed=max_events, total=len(events)))
        events = events[:max_events]
        truncated = True
    return NormalizationResult(
        events=sort_normalized_events(events),
        warnings=tuple(warnings),
        processed_count=len(events),
        truncated=truncated,
    )


def normalize_fields(record: ParsedRecord) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key, value in record.fields.items():
        safe_key = _canonical_text(key)
        safe_value = _first_scalar(value)
        if safe_key in HASH_FIELD_NAMES:
            normalized[safe_key] = normalize_hash(safe_value)
        elif safe_key in USERNAME_FIELD_NAMES:
            normalized[safe_key] = normalize_username(safe_value)
        elif safe_key in PATH_FIELD_NAMES:
            normalized[safe_key] = normalize_path(safe_value)
        else:
            normalized[safe_key] = str(safe_value).strip()

    if record.parser == "pcap":
        normalized.update(_normalize_pcap_fields(record.fields))

    user = _first_existing(normalized, USERNAME_FIELD_NAMES)
    if user:
        normalized["user"] = normalize_username(user)

    return _sorted_fields(normalized)


def _parse_timestamp(value: datetime | str | int | float | None) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, int | float):
        return datetime.fromtimestamp(float(value), tz=UTC)
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return datetime.fromtimestamp(float(text), tz=UTC)
    except ValueError:
        pass
    candidate = text.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        return None


def _timestamp_warnings(record: ParsedRecord, timestamp_utc: str) -> tuple[SignalWarning, ...]:
    if timestamp_utc != UNKNOWN_TIMESTAMP_UTC:
        return ()
    if any(warning.warning_type == "INVALID_TIMESTAMP" for warning in record.warnings):
        return ()
    return (
        SignalWarning(
            warning_type="INVALID_TIMESTAMP",
            severity="MEDIUM",
            artifact=record.evidence_id,
            impact="timestamp normalized to deterministic unknown timestamp",
            metadata={"value": record.timestamp or ""},
        ),
    )


def _normalized_artifact(record: ParsedRecord) -> str:
    if record.parser == "pcap":
        src = _first_existing(record.fields, ("ip.src", "ipv6.src"))
        dst = _first_existing(record.fields, ("ip.dst", "ipv6.dst"))
        if src or dst:
            return f"{src or '?'}->{dst or '?'}"
    return normalize_path(record.artifact)


def _raw_reference(value: str | None) -> RawReference:
    if value is None:
        return RawReference(evidence_id="pending")
    text = str(value).strip()
    if not text:
        return RawReference(evidence_id="pending")
    if text.isdigit():
        return RawReference(evidence_id="pending", record_index=int(text))
    return RawReference(evidence_id="pending", path=normalize_path(text))


def _confidence_from_warnings(warnings: tuple[SignalWarning, ...]) -> float:
    penalty = min(sum(warning.confidence_penalty for warning in warnings), 1.0)
    return max(1.0 - penalty, 0.0)


def _lowest_evidence_category(left: EvidenceCategory, right: EvidenceCategory) -> EvidenceCategory:
    rank = {
        EvidenceCategory.RAW: 0,
        EvidenceCategory.DERIVED: 1,
        EvidenceCategory.INFERRED: 2,
    }
    return left if rank[left] >= rank[right] else right


def _lowest_trust(left: TrustTier, right: TrustTier) -> TrustTier:
    rank = {
        TrustTier.TIER_1_HIGH: 0,
        TrustTier.TIER_2_MEDIUM_HIGH: 1,
        TrustTier.TIER_3_LOW: 2,
        TrustTier.TIER_4_VERY_LOW: 3,
    }
    return left if rank[left] >= rank[right] else right


def _normalize_pcap_fields(fields: Mapping[str, Any]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    mapping = {
        "ip.src": "src_ip",
        "ipv6.src": "src_ip",
        "ip.dst": "dst_ip",
        "ipv6.dst": "dst_ip",
        "tcp.srcport": "src_port",
        "udp.srcport": "src_port",
        "tcp.dstport": "dst_port",
        "udp.dstport": "dst_port",
        "_ws.col.protocol": "protocol",
        "frame.protocols": "protocol_stack",
        "dns.qry.name": "dns_query",
        "http.host": "http_host",
        "http.request.uri": "http_uri",
        "tls.handshake.extensions_server_name": "tls_sni",
        "frame.len": "byte_count",
        "frame.time_epoch": "timestamp_epoch",
    }
    for source_key, target_key in mapping.items():
        value = _first_existing(fields, (source_key,))
        if value:
            normalized[target_key] = str(value).strip()

    dst_port = normalized.get("dst_port", "")
    src_port = normalized.get("src_port", "")
    if _is_unusual_port(dst_port):
        normalized["unusual_port"] = dst_port
    elif _is_unusual_port(src_port):
        normalized["unusual_port"] = src_port
    return normalized


def _pcap_category(fields: Mapping[str, str]) -> str:
    if fields.get("dns_query") or _first_existing(fields, ("dns.qry.name",)):
        return "network_dns"
    if fields.get("http_host") or fields.get("http_uri") or _first_existing(fields, ("http.host",)):
        return "network_http"
    if fields.get("tls_sni") or _first_existing(fields, ("tls.handshake.extensions_server_name",)):
        return "network_tls"
    if fields.get("unusual_port"):
        return "network_unusual_port"
    return "network_flow"


def _is_unusual_port(value: str) -> bool:
    if not value:
        return False
    try:
        port = int(value)
    except ValueError:
        return False
    common_ports = {20, 21, 22, 25, 53, 80, 110, 123, 135, 139, 143, 389, 443, 445, 587, 993, 995}
    return port not in common_ports and port > 0


def _first_existing(values: Mapping[str, Any], keys: set[str] | tuple[str, ...]) -> str:
    ordered_keys = tuple(sorted(keys)) if isinstance(keys, set) else keys
    for key in ordered_keys:
        if key in values:
            value = _first_scalar(values[key])
            if value != "":
                return str(value)
    return ""


def _first_scalar(value: Any) -> str:
    if isinstance(value, list | tuple):
        return "" if not value else _first_scalar(value[0])
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            try:
                parsed = ast.literal_eval(stripped)
            except (SyntaxError, ValueError):
                return stripped
            if isinstance(parsed, list | tuple):
                return _first_scalar(parsed)
        return stripped
    return "" if value is None else str(value).strip()


def _canonical_text(value: Any) -> str:
    text = _first_scalar(value).strip().lower()
    text = re.sub(r"[^a-z0-9_.-]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text


def _canonical_id_part(value: str) -> str:
    return str(value or "").strip().lower()


def _sorted_fields(values: Mapping[str, str]) -> dict[str, str]:
    return {key: values[key] for key in sorted(values)}


def _sorted_provenance(values: Mapping[str, Any]) -> dict[str, Any]:
    return {key: values[key] for key in sorted(values)}
