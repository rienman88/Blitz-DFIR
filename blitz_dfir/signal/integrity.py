from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from blitz_dfir.core.models import SignalWarning
from blitz_dfir.parsers.models import ParserResult
from blitz_dfir.signal.coverage import AnalysisGap, CoverageReport
from blitz_dfir.signal.warnings import (
    abnormal_event_density_warning,
    encoding_corruption_warning,
    event_truncation_warning,
    hash_mismatch_warning,
    make_warning,
    parser_crash_warning,
    retry_exhaustion_warning,
    tool_timeout_warning,
)
from blitz_dfir.tools.base import ToolAdapterResult

WarningSeverity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class SignalIntegrityReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    warnings: tuple[SignalWarning, ...]
    confidence_penalty: float = Field(ge=0.0, le=1.0)
    critical_count: int = Field(ge=0)
    high_count: int = Field(ge=0)
    coverage_report: CoverageReport | None = None
    analysis_gaps: tuple[AnalysisGap, ...] = ()


def confidence_penalty_from_warnings(warnings: list[SignalWarning] | tuple[SignalWarning, ...]) -> float:
    return min(sum(warning.confidence_penalty for warning in warnings), 1.0)


def summarize_signal_integrity(
    *,
    tool_results: list[ToolAdapterResult] | None = None,
    parser_results: list[ParserResult] | None = None,
    coverage_report: CoverageReport | None = None,
    extra_warnings: list[SignalWarning] | None = None,
) -> SignalIntegrityReport:
    warnings: list[SignalWarning] = list(extra_warnings or [])
    analysis_gaps: list[AnalysisGap] = []
    for tool_result in tool_results or []:
        warnings.extend(_warnings_from_tool_result(tool_result))
    for parser_result in parser_results or []:
        warnings.extend(parser_result.warnings)
        for record in parser_result.records:
            warnings.extend(record.warnings)
    if coverage_report is not None:
        warnings.extend(coverage_report.warnings)
        analysis_gaps.extend(coverage_report.analysis_gaps)
    return SignalIntegrityReport(
        warnings=tuple(warnings),
        confidence_penalty=confidence_penalty_from_warnings(warnings),
        critical_count=sum(1 for warning in warnings if warning.severity == "CRITICAL"),
        high_count=sum(1 for warning in warnings if warning.severity == "HIGH"),
        coverage_report=coverage_report,
        analysis_gaps=tuple(analysis_gaps),
    )


def decode_with_signal(
    data: bytes,
    *,
    artifact: str,
    source: str,
    encoding: str = "utf-8",
) -> tuple[str, tuple[SignalWarning, ...]]:
    try:
        return data.decode(encoding), ()
    except UnicodeDecodeError:
        decoded = data.decode(encoding, errors="replace")
        errors = decoded.count("\ufffd")
        return decoded, (encoding_corruption_warning(artifact=artifact, source=source, errors=errors),)


def timeout_warning_from_tool(tool_result: ToolAdapterResult, *, timeout_seconds: int) -> SignalWarning | None:
    if not tool_result.timed_out:
        return None
    return tool_timeout_warning(
        artifact=tool_result.evidence_id,
        tool=tool_result.tool_name,
        timeout_seconds=timeout_seconds,
    )


def truncation_warning(*, artifact: str, processed: int, total: int, tool: str | None = None) -> SignalWarning:
    return event_truncation_warning(
        artifact=artifact,
        processed_events=processed,
        estimated_total=total,
        tool=tool,
    )


def parser_exit_warning(*, artifact: str, parser: str, exit_code: int) -> SignalWarning | None:
    if exit_code == 0:
        return None
    return parser_crash_warning(artifact=artifact, parser=parser, exit_code=exit_code)


def retry_limit_warning(*, artifact: str, attempts: int, max_attempts: int) -> SignalWarning | None:
    if attempts < max_attempts:
        return None
    return retry_exhaustion_warning(artifact=artifact, attempts=attempts)


def event_density_warning(
    *,
    artifact: str,
    observed: int,
    expected_minimum: int,
) -> SignalWarning | None:
    if observed >= expected_minimum:
        return None
    return abnormal_event_density_warning(
        artifact=artifact,
        observed=observed,
        expected_minimum=expected_minimum,
    )


def _warnings_from_tool_result(tool_result: ToolAdapterResult) -> list[SignalWarning]:
    warnings: list[SignalWarning] = []
    hash_mismatch_recorded = False
    provenance = tool_result.provenance
    if (
        not provenance.verified
        and provenance.expected_sha256 is not None
        and provenance.actual_sha256 is not None
    ):
        warnings.append(
            hash_mismatch_warning(
                artifact=tool_result.evidence_id,
                expected=provenance.expected_sha256,
                actual=provenance.actual_sha256,
                tool=tool_result.tool_name,
            )
        )
        hash_mismatch_recorded = True

    for warning in tool_result.warnings:
        if warning.warning_type == "TOOL_TIMEOUT":
            continue
        if warning.warning_type == "TOOL_PROVENANCE" and hash_mismatch_recorded:
            continue
        warnings.append(
            make_warning(
                warning.warning_type,
                artifact=tool_result.evidence_id,
                impact=warning.message,
                severity=_coerce_severity(warning.severity),
                tool=tool_result.tool_name,
            )
        )
    if tool_result.timed_out:
        warnings.append(
            tool_timeout_warning(
                artifact=tool_result.evidence_id,
                tool=tool_result.tool_name,
                timeout_seconds=300,
            )
        )
    return warnings


def _coerce_severity(severity: str) -> WarningSeverity:
    if severity == "LOW":
        return "LOW"
    if severity == "MEDIUM":
        return "MEDIUM"
    if severity == "HIGH":
        return "HIGH"
    if severity == "CRITICAL":
        return "CRITICAL"
    return "MEDIUM"
