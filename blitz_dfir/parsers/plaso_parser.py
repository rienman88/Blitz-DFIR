from __future__ import annotations

import csv
from io import StringIO
from pathlib import Path

from blitz_dfir.core.models import EvidenceRecord, SignalWarning
from blitz_dfir.parsers.common import make_record
from blitz_dfir.parsers.models import ParsedRecord, ParserResult
from blitz_dfir.parsers.parser_validation import (
    malformed_record_warning,
    parser_degradation_warning,
    validate_parser_compatibility,
)
from blitz_dfir.sanitization.sanitizer import event_cap_warning, get_max_events


def parse_plaso_csv(text: str, evidence: EvidenceRecord) -> ParserResult:
    validate_parser_compatibility("plaso", evidence)
    return _parse_plaso_rows(csv.DictReader(StringIO(text)), evidence)


def parse_plaso_csv_file(path: Path, evidence: EvidenceRecord, *, record_limit: int | None = None) -> ParserResult:
    validate_parser_compatibility("plaso", evidence)
    try:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
            return _parse_plaso_rows(csv.DictReader(handle), evidence, record_limit=record_limit)
    except OSError:
        return ParserResult(
            parser="plaso",
            source_tool="psort",
            evidence_id=evidence.evidence_id,
            records=(),
            warnings=(
                parser_degradation_warning(
                    artifact=evidence.evidence_id,
                    reason="unable to read psort CSV output",
                ),
            ),
            processed_count=0,
            malformed_count=1,
            truncated=False,
        )


def _parse_plaso_rows(
    reader: csv.DictReader,
    evidence: EvidenceRecord,
    *,
    record_limit: int | None = None,
) -> ParserResult:
    max_events = get_max_events()
    max_records = max_events if record_limit is None else min(max(record_limit, 0), max_events)
    warnings: list[SignalWarning] = []
    records: list[ParsedRecord] = []
    malformed = 0
    if not reader.fieldnames:
        warnings.append(parser_degradation_warning(artifact=evidence.evidence_id, reason="missing CSV header"))
        return ParserResult(
            parser="plaso",
            source_tool="psort",
            evidence_id=evidence.evidence_id,
            records=(),
            warnings=tuple(warnings),
            processed_count=0,
            malformed_count=1,
            truncated=False,
        )
    total_records = 0
    for index, row in enumerate(reader, 1):
        total_records = index
        timestamp = row.get("datetime") or row.get("timestamp") or row.get("date")
        if timestamp is None:
            malformed += 1
            if len(records) < max_records:
                warnings.append(
                    malformed_record_warning(
                        artifact=evidence.evidence_id,
                        reason="missing timestamp column",
                        index=index,
                    )
                )
        if len(records) >= max_records:
            continue
        message = row.get("message") or row.get("description") or ""
        event_type = row.get("source") or row.get("parser") or row.get("event_type") or "timeline_event"
        artifact = row.get("filename") or row.get("source_long") or row.get("source") or evidence.evidence_id
        record_warnings: list[SignalWarning] = []
        records.append(
            make_record(
                parser="plaso",
                source_tool="psort",
                evidence=evidence,
                timestamp=timestamp,
                event_type=event_type,
                artifact=artifact,
                message=message,
                raw_reference=row.get("inode") or row.get("display_name"),
                fields=row,
                warnings=record_warnings,
            )
        )
        warnings.extend(record_warnings)
    truncated = total_records > max_events
    if truncated:
        warnings.append(
            event_cap_warning(
                artifact=evidence.evidence_id,
                processed=max_events,
                total=total_records,
            )
        )
    return ParserResult(
        parser="plaso",
        source_tool="psort",
        evidence_id=evidence.evidence_id,
        records=tuple(records),
        warnings=tuple(warnings),
        processed_count=min(total_records, max_events),
        malformed_count=malformed,
        truncated=truncated,
    )
