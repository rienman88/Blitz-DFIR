from __future__ import annotations

from blitz_dfir.core.models import EvidenceRecord, SignalWarning
from blitz_dfir.parsers.common import make_record
from blitz_dfir.parsers.models import ParsedRecord, ParserResult
from blitz_dfir.parsers.parser_validation import build_parser_result, validate_parser_compatibility


def parse_yara_output(text: str, evidence: EvidenceRecord) -> ParserResult:
    validate_parser_compatibility("yara", evidence)
    warnings: list[SignalWarning] = []
    records: list[ParsedRecord] = []
    for index, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split(maxsplit=1)
        rule = parts[0]
        target = parts[1] if len(parts) > 1 else evidence.path.name
        record_warnings: list[SignalWarning] = []
        records.append(
            make_record(
                parser="yara",
                source_tool="yara",
                evidence=evidence,
                timestamp="",
                event_type="yara_match",
                artifact=target,
                message=rule,
                raw_reference=index,
                fields={"rule": rule, "target": target},
                warnings=record_warnings,
            )
        )
        warnings.extend(record_warnings)
    return build_parser_result(
        parser="yara",
        source_tool="yara",
        evidence=evidence,
        records=records,
        warnings=warnings,
        malformed_count=0,
    )
