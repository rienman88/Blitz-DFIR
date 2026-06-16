from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Literal

from blitz_dfir.core.models import EvidenceRecord, SignalWarning
from blitz_dfir.parsers.common import make_record
from blitz_dfir.parsers.models import ParsedRecord, ParserResult
from blitz_dfir.parsers.parser_validation import build_parser_result, parser_degradation_warning, validate_parser_compatibility
from blitz_dfir.sanitization.sanitizer import get_max_events


def parse_disk_triage_json(text: str, evidence: EvidenceRecord) -> ParserResult:
    validate_parser_compatibility("disk_triage", evidence)
    try:
        payload = json.loads(text or "{}")
    except json.JSONDecodeError:
        return build_parser_result(
            parser="disk_triage",
            source_tool="disk_triage",
            evidence=evidence,
            records=[],
            warnings=[
                parser_degradation_warning(artifact=evidence.evidence_id, reason="disk triage JSON was invalid")
            ],
            malformed_count=1,
        )
    return _parser_result_from_payload(payload, evidence=evidence, summary_path=None, record_limit=None)


def parse_disk_triage_file(path: Path, evidence: EvidenceRecord, *, record_limit: int | None = None) -> ParserResult:
    validate_parser_compatibility("disk_triage", evidence)
    try:
        payload = load_disk_triage_payload(path)
    except (OSError, json.JSONDecodeError):
        return build_parser_result(
            parser="disk_triage",
            source_tool="disk_triage",
            evidence=evidence,
            records=[],
            warnings=[
                parser_degradation_warning(
                    artifact=evidence.evidence_id,
                    reason="unable to read disk triage JSON output",
                )
            ],
            malformed_count=1,
        )
    return _parser_result_from_payload(payload, evidence=evidence, summary_path=path, record_limit=record_limit)


def load_disk_triage_payload(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8") or "{}")


def disk_triage_payload_warnings(
    payload: dict[str, Any],
    evidence: EvidenceRecord,
    *,
    summary_path: Path | None = None,
) -> tuple[SignalWarning, ...]:
    warnings: list[SignalWarning] = []
    for item in payload.get("warnings", []) or []:
        if isinstance(item, dict):
            warnings.append(
                SignalWarning(
                    warning_type="DISK_TRIAGE_WARNING",
                    severity=_severity(item.get("severity")),
                    artifact=evidence.evidence_id,
                    impact=str(item.get("reason") or "disk triage warning"),
                    tool="disk_triage",
                    confidence_penalty=0.15,
                    metadata=_metadata(item),
                )
            )

    partitions = payload.get("partitions", []) or []
    for partition in partitions:
        if not isinstance(partition, dict):
            continue
        for item in partition.get("warnings", []) or []:
            if isinstance(item, dict):
                warnings.append(
                    SignalWarning(
                        warning_type="DISK_TRIAGE_PARTITION_WARNING",
                        severity=_severity(item.get("severity")),
                        artifact=evidence.evidence_id,
                        impact=str(item.get("reason") or "partition triage warning"),
                        tool="disk_triage",
                        confidence_penalty=0.15,
                        metadata=_metadata(item),
                    )
                )

    if payload.get("truncated") or any(
        isinstance(partition, dict) and partition.get("truncated") for partition in partitions
    ):
        warnings.append(
            SignalWarning(
                warning_type="DISK_TRIAGE_TRUNCATED",
                severity="HIGH",
                artifact=evidence.evidence_id,
                impact=(
                    "Disk triage reached a configured entry/runtime limit. "
                    "Increase BLITZ_DISK_TRIAGE_MAX_ENTRIES or timeout if full filesystem enumeration is required."
                ),
                tool="disk_triage",
                confidence_penalty=0.2,
                metadata={
                    "entry_count": _payload_entry_count(payload),
                    "configured_max_entries": (payload.get("limits") or {}).get("max_entries"),
                    "entries_omitted_from_summary": payload.get("entries_omitted_from_summary", 0),
                },
            )
        )

    entries_path = _entries_output_path(payload, summary_path=summary_path)
    omitted = int(payload.get("entries_omitted_from_summary") or 0)
    if omitted and entries_path is not None and not entries_path.exists():
        warnings.append(
            SignalWarning(
                warning_type="DISK_TRIAGE_ENTRY_STREAM_MISSING",
                severity="CRITICAL",
                artifact=evidence.evidence_id,
                impact=(
                    "Disk triage summary omitted entries, but the JSONL entry stream was not found. "
                    "Only the summary sample can be parsed."
                ),
                tool="disk_triage",
                confidence_penalty=0.35,
                metadata={"entries_output": str(entries_path), "entries_omitted_from_summary": omitted},
            )
        )
    return tuple(warnings)


def iter_disk_triage_records(
    payload: dict[str, Any],
    evidence: EvidenceRecord,
    *,
    summary_path: Path | None = None,
) -> Iterator[ParsedRecord]:
    validate_parser_compatibility("disk_triage", evidence)
    for entry, partition in _iter_entry_payloads(payload, summary_path=summary_path):
        record_warnings: list[SignalWarning] = []
        yield _record(entry, evidence=evidence, partition=partition, record_warnings=record_warnings)


def _parser_result_from_payload(
    payload: dict[str, Any],
    *,
    evidence: EvidenceRecord,
    summary_path: Path | None,
    record_limit: int | None,
) -> ParserResult:
    warnings = list(disk_triage_payload_warnings(payload, evidence, summary_path=summary_path))
    max_events = get_max_events()
    max_records = max_events if record_limit is None else min(max(record_limit, 0), max_events)
    records: list[ParsedRecord] = []
    malformed_count = sum(1 for partition in payload.get("partitions", []) or [] if not isinstance(partition, dict))
    seen_records = 0
    reported_total = _payload_entry_count(payload)

    for entry, partition in _iter_entry_payloads(payload, summary_path=summary_path):
        if len(records) >= max_records and reported_total:
            break
        seen_records += 1
        if len(records) >= max_records:
            continue
        if not isinstance(entry, dict):
            malformed_count += 1
            continue
        record_warnings: list[SignalWarning] = []
        records.append(_record(entry, evidence=evidence, partition=partition, record_warnings=record_warnings))
        warnings.extend(record_warnings)

    total_records = max(reported_total, seen_records)
    truncated = bool(payload.get("truncated")) or total_records > len(records) or total_records > max_events
    return ParserResult(
        parser="disk_triage",
        source_tool="disk_triage",
        evidence_id=evidence.evidence_id,
        records=tuple(records),
        warnings=tuple(warnings),
        malformed_count=malformed_count,
        truncated=truncated,
        processed_count=min(total_records, max_events),
    )


def _iter_entry_payloads(
    payload: dict[str, Any],
    *,
    summary_path: Path | None,
) -> Iterator[tuple[dict[str, Any], dict[str, Any]]]:
    entries_path = _entries_output_path(payload, summary_path=summary_path)
    if entries_path is not None and entries_path.exists():
        with entries_path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(row, dict):
                    continue
                partition = row.get("partition") if isinstance(row.get("partition"), dict) else {}
                entry = row.get("entry") if isinstance(row.get("entry"), dict) else row
                yield entry, partition
        return

    for partition in payload.get("partitions", []) or []:
        if not isinstance(partition, dict):
            continue
        for entry in partition.get("entries", []) or []:
            if isinstance(entry, dict):
                yield entry, partition


def _record(
    entry: dict[str, Any],
    *,
    evidence: EvidenceRecord,
    partition: dict[str, Any],
    record_warnings: list[SignalWarning] | None = None,
) -> ParsedRecord:
    warnings = record_warnings if record_warnings is not None else []
    timestamp = entry.get("mtime") or entry.get("crtime") or entry.get("ctime") or entry.get("atime") or ""
    family = str(entry.get("artifact_family") or "")
    risk_tags = tuple(str(tag) for tag in entry.get("risk_tags", []) if tag)
    event_type = family or ("disk_suspicious_path" if risk_tags else "disk_file_entry")
    fields = {
        "path": entry.get("path", ""),
        "inode": entry.get("inode", ""),
        "mode": entry.get("mode", ""),
        "size": entry.get("size"),
        "atime": entry.get("atime"),
        "mtime": entry.get("mtime"),
        "ctime": entry.get("ctime"),
        "crtime": entry.get("crtime"),
        "partition_start": entry.get("partition_start"),
        "partition_description": partition.get("description", ""),
        "artifact_family": family,
        "risk_tags": ",".join(risk_tags),
    }
    return make_record(
        parser="disk_triage",
        source_tool="disk_triage",
        evidence=evidence,
        timestamp=timestamp,
        event_type=event_type,
        artifact=entry.get("path", evidence.evidence_id),
        message=_message(entry, family=family, risk_tags=risk_tags),
        raw_reference=f"partition_start={entry.get('partition_start')} inode={entry.get('inode')}",
        fields=fields,
        warnings=warnings,
    )


def _message(entry: dict[str, Any], *, family: str, risk_tags: tuple[str, ...]) -> str:
    parts = [str(entry.get("path") or "")]
    if family:
        parts.append(f"artifact_family={family}")
    if risk_tags:
        parts.append("risk_tags=" + ",".join(risk_tags))
    return " ".join(part for part in parts if part)


def _severity(value: object) -> Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
    if value in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return value  # type: ignore[return-value]
    return "MEDIUM"


def _metadata(item: dict[str, Any]) -> dict[str, Any]:
    return {str(key): value for key, value in item.items() if key not in {"severity", "reason"}}


def _payload_entry_count(payload: dict[str, Any]) -> int:
    try:
        return int(payload.get("entry_count") or 0)
    except (TypeError, ValueError):
        return 0


def _entries_output_path(payload: dict[str, Any], *, summary_path: Path | None) -> Path | None:
    value = payload.get("entries_output") or payload.get("entries_output_path")
    if not isinstance(value, str) or not value:
        return None
    path = Path(value)
    if path.is_absolute():
        return path
    if summary_path is None:
        return None
    return summary_path.parent / path
