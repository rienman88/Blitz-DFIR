from __future__ import annotations

from typing import Any, Literal

from blitz_dfir.core.models import SignalWarning

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

DEFAULT_PENALTIES: dict[str, float] = {
    "TOOL_PROVENANCE": 0.12,
    "TOOL_TIMEOUT": 0.15,
    "EVENT_TRUNCATION": 0.20,
    "PARSER_DEGRADATION": 0.20,
    "ENCODING_CORRUPTION": 0.10,
    "MISSING_ARTIFACT": 0.12,
    "PARTIAL_EXTRACTION": 0.15,
    "HASH_MISMATCH": 0.40,
    "RETRY_EXHAUSTION": 0.20,
    "PARSER_CRASH": 0.30,
    "ABNORMAL_EVENT_DENSITY": 0.18,
    "LOW_COVERAGE": 0.10,
}


def make_warning(
    warning_type: str,
    *,
    artifact: str,
    impact: str,
    severity: Severity,
    tool: str | None = None,
    confidence_penalty: float | None = None,
    metadata: dict[str, Any] | None = None,
) -> SignalWarning:
    penalty = DEFAULT_PENALTIES.get(warning_type, 0.0) if confidence_penalty is None else confidence_penalty
    return SignalWarning(
        warning_type=warning_type,
        severity=severity,
        artifact=artifact,
        impact=impact,
        tool=tool,
        confidence_penalty=min(max(penalty, 0.0), 1.0),
        metadata=metadata or {},
    )


def tool_timeout_warning(*, artifact: str, tool: str, timeout_seconds: int) -> SignalWarning:
    return make_warning(
        "TOOL_TIMEOUT",
        artifact=artifact,
        tool=tool,
        severity="HIGH",
        impact=f"{tool} exceeded {timeout_seconds}s timeout; output may be partial",
        metadata={"timeout_seconds": timeout_seconds},
    )


def event_truncation_warning(
    *,
    artifact: str,
    processed_events: int,
    estimated_total: int,
    tool: str | None = None,
) -> SignalWarning:
    return make_warning(
        "EVENT_TRUNCATION",
        artifact=artifact,
        tool=tool,
        severity="HIGH",
        impact="event cap reached; timeline or parser output may have gaps",
        metadata={"processed_events": processed_events, "estimated_total": estimated_total},
    )


def parser_degradation_warning(*, artifact: str, parser: str, reason: str) -> SignalWarning:
    return make_warning(
        "PARSER_DEGRADATION",
        artifact=artifact,
        tool=parser,
        severity="HIGH",
        impact=reason,
    )


def encoding_corruption_warning(*, artifact: str, source: str, errors: int) -> SignalWarning:
    return make_warning(
        "ENCODING_CORRUPTION",
        artifact=artifact,
        tool=source,
        severity="MEDIUM",
        impact="invalid bytes were replaced during decoding",
        metadata={"decode_errors": errors},
    )


def missing_artifact_warning(*, artifact: str, missing_source: str) -> SignalWarning:
    return make_warning(
        "MISSING_ARTIFACT",
        artifact=artifact,
        severity="MEDIUM",
        impact=f"expected source missing: {missing_source}",
        metadata={"missing_source": missing_source},
    )


def partial_extraction_warning(
    *,
    artifact: str,
    processed: int,
    expected: int,
    source: str,
) -> SignalWarning:
    return make_warning(
        "PARTIAL_EXTRACTION",
        artifact=artifact,
        tool=source,
        severity="HIGH",
        impact=f"processed {processed} of {expected} expected units",
        metadata={"processed": processed, "expected": expected},
    )


def hash_mismatch_warning(
    *,
    artifact: str,
    expected: str,
    actual: str,
    tool: str | None = None,
) -> SignalWarning:
    return make_warning(
        "HASH_MISMATCH",
        artifact=artifact,
        tool=tool,
        severity="CRITICAL",
        impact="artifact hash changed or tool provenance hash mismatch",
        metadata={"expected": expected, "actual": actual},
    )


def retry_exhaustion_warning(*, artifact: str, attempts: int) -> SignalWarning:
    return make_warning(
        "RETRY_EXHAUSTION",
        artifact=artifact,
        severity="HIGH",
        impact="bounded retry limit reached",
        metadata={"attempts": attempts},
    )


def parser_crash_warning(*, artifact: str, parser: str, exit_code: int) -> SignalWarning:
    return make_warning(
        "PARSER_CRASH",
        artifact=artifact,
        tool=parser,
        severity="CRITICAL",
        impact=f"{parser} exited abnormally",
        metadata={"exit_code": exit_code},
    )


def abnormal_event_density_warning(
    *,
    artifact: str,
    observed: int,
    expected_minimum: int,
) -> SignalWarning:
    return make_warning(
        "ABNORMAL_EVENT_DENSITY",
        artifact=artifact,
        severity="MEDIUM",
        impact="observed event count is unexpectedly low",
        metadata={"observed": observed, "expected_minimum": expected_minimum},
    )


def low_coverage_warning(*, artifact: str, coverage: float) -> SignalWarning:
    return make_warning(
        "LOW_COVERAGE",
        artifact=artifact,
        severity="MEDIUM",
        impact="coverage below expected threshold",
        metadata={"coverage": coverage},
    )
