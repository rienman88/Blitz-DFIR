from __future__ import annotations

from blitz_dfir.core.models import EvidenceRecord, SignalWarning
from blitz_dfir.parsers.common import make_record
from blitz_dfir.parsers.models import ParsedRecord, ParserResult
from blitz_dfir.parsers.parser_validation import build_parser_result, validate_parser_compatibility


def parse_strings_output(text: str, evidence: EvidenceRecord) -> ParserResult:
    validate_parser_compatibility("strings", evidence)
    warnings: list[SignalWarning] = []
    records: list[ParsedRecord] = []
    for index, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        record_warnings: list[SignalWarning] = []
        records.append(
            make_record(
                parser="strings",
                source_tool="strings",
                evidence=evidence,
                timestamp="",
                event_type="string",
                artifact=evidence.path.name,
                message=line,
                raw_reference=index,
                fields={"line_number": index, "value": line},
                warnings=record_warnings,
            )
        )
        warnings.extend(record_warnings)
    return build_parser_result(
        parser="strings",
        source_tool="strings",
        evidence=evidence,
        records=records,
        warnings=warnings,
        malformed_count=0,
    )
