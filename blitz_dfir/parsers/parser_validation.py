from __future__ import annotations

from datetime import datetime

from blitz_dfir.core.models import EvidenceRecord, EvidenceType, SignalWarning
from blitz_dfir.exceptions import ValidationError
from blitz_dfir.parsers.models import ParserResult, ParsedRecord
from blitz_dfir.sanitization.sanitizer import event_cap_warning, get_max_events

PARSER_COMPATIBILITY: dict[str, frozenset[EvidenceType]] = {
    "plaso": frozenset({EvidenceType.PLASO, EvidenceType.CSV_TIMELINE}),
    "disk_triage": frozenset({EvidenceType.E01, EvidenceType.DD}),
    "evtx": frozenset({EvidenceType.EVTX, EvidenceType.PREPROCESSED_EVTX}),
    "volatility": frozenset({EvidenceType.MEMORY, EvidenceType.JSON_EXPORT, EvidenceType.VOLATILITY_JSON}),
    "pcap": frozenset({EvidenceType.PCAP}),
    "yara": frozenset(set(EvidenceType)),
    "strings": frozenset(set(EvidenceType)),
}


def validate_parser_compatibility(parser_name: str, evidence: EvidenceRecord) -> None:
    allowed = PARSER_COMPATIBILITY.get(parser_name)
    if allowed is None:
        raise ValidationError(f"unknown parser: {parser_name}")
    if evidence.evidence_type not in allowed:
        raise ValidationError(
            f"{parser_name} parser cannot parse evidence type {evidence.evidence_type.value}"
        )


def validate_processed_coverage_metadata(metadata: dict[str, object], evidence: EvidenceRecord) -> None:
    if evidence.evidence_type not in {
        EvidenceType.PLASO,
        EvidenceType.CSV_TIMELINE,
        EvidenceType.JSON_EXPORT,
        EvidenceType.VOLATILITY_JSON,
        EvidenceType.YARA_MATCHES,
        EvidenceType.STRINGS_OUTPUT,
        EvidenceType.PREPROCESSED_EVTX,
        EvidenceType.THIRD_PARTY_EXPORT,
    }:
        return
    coverage = metadata.get("coverage_estimate")
    if coverage is None:
        raise ValidationError("processed evidence requires coverage_estimate metadata")
    if not isinstance(coverage, int | float) or not 0 <= float(coverage) <= 1:
        raise ValidationError("coverage_estimate must be a number between 0 and 1")


def cap_records(
    records: list[ParsedRecord],
    warnings: list[SignalWarning],
    *,
    artifact: str,
) -> tuple[list[ParsedRecord], bool]:
    max_events = get_max_events()
    if len(records) <= max_events:
        return records, False
    warnings.append(event_cap_warning(artifact=artifact, processed=max_events, total=len(records)))
    return records[:max_events], True


def invalid_timestamp_warning(*, artifact: str, value: str) -> SignalWarning:
    return SignalWarning(
        warning_type="INVALID_TIMESTAMP",
        severity="MEDIUM",
        artifact=artifact,
        impact="timestamp could not be parsed reliably",
        confidence_penalty=0.05,
        metadata={"value": value},
    )


def malformed_record_warning(*, artifact: str, reason: str, index: int) -> SignalWarning:
    return SignalWarning(
        warning_type="MALFORMED_RECORD",
        severity="HIGH",
        artifact=artifact,
        impact=reason,
        confidence_penalty=0.15,
        metadata={"record_index": index},
    )


def parser_degradation_warning(*, artifact: str, reason: str) -> SignalWarning:
    return SignalWarning(
        warning_type="PARSER_DEGRADATION",
        severity="HIGH",
        artifact=artifact,
        impact=reason,
        confidence_penalty=0.20,
    )


def validate_timestamp(value: str | None, *, artifact: str, warnings: list[SignalWarning]) -> str | None:
    if not value:
        warnings.append(invalid_timestamp_warning(artifact=artifact, value=""))
        return None
    candidate = value.replace("Z", "+00:00")
    try:
        datetime.fromisoformat(candidate)
    except ValueError:
        warnings.append(invalid_timestamp_warning(artifact=artifact, value=value))
    return value


def build_parser_result(
    *,
    parser: str,
    source_tool: str,
    evidence: EvidenceRecord,
    records: list[ParsedRecord],
    warnings: list[SignalWarning],
    malformed_count: int,
) -> ParserResult:
    capped, truncated = cap_records(records, warnings, artifact=evidence.evidence_id)
    return ParserResult(
        parser=parser,
        source_tool=source_tool,
        evidence_id=evidence.evidence_id,
        records=tuple(capped),
        warnings=tuple(warnings),
        processed_count=len(capped),
        malformed_count=malformed_count,
        truncated=truncated,
    )
