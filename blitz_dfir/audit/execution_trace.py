from __future__ import annotations

from typing import Any

from blitz_dfir.audit.audit_log import AuditLogger
from blitz_dfir.core.integrity import hash_text
from blitz_dfir.correction.models import CorrectionAttempt, CorrectionHistory, CorrectionTrigger
from blitz_dfir.correction.validator import ValidationReport
from blitz_dfir.parsers.models import ParserResult
from blitz_dfir.reasoning.models import AnalystDecision, TokenUsage
from blitz_dfir.signal.coverage import CoverageReport
from blitz_dfir.tools.base import ToolAdapterResult


def correlation_id_for(*parts: str) -> str:
    digest = hash_text("|".join(str(part) for part in parts))[:12].upper()
    return f"CORR-{digest}"


def record_phase_event(
    audit: AuditLogger,
    *,
    phase: str,
    status: str,
    details: dict[str, Any] | None = None,
    correlation_id: str | None = None,
) -> None:
    audit.append(
        "phase_event",
        {"phase": phase, "status": status, "details": details or {}},
        correlation_id=correlation_id or correlation_id_for("phase", phase, status),
    )


def record_tool_execution(
    audit: AuditLogger,
    result: ToolAdapterResult,
    *,
    sanitized_args: dict[str, Any] | None = None,
    correlation_id: str | None = None,
) -> None:
    audit.append(
        "tool_execution",
        {
            "tool": result.tool_name,
            "tool_version": result.tool_version,
            "tool_hash": result.provenance.actual_sha256,
            "tool_hash_expected": result.provenance.expected_sha256,
            "tool_verified": result.provenance.verified,
            "evidence_id": result.evidence_id,
            "sanitized_args": sanitized_args or {"args_hash": result.args_hash},
            "duration_ms": result.duration_ms,
            "output_hash": result.output_hash,
            "stdout_hash": result.stdout_hash,
            "stderr_hash": result.stderr_hash,
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "warnings": [warning.__dict__ for warning in result.warnings],
        },
        correlation_id=correlation_id or correlation_id_for(result.evidence_id, result.tool_name, result.args_hash),
    )


def record_parser_result(
    audit: AuditLogger,
    result: ParserResult,
    *,
    correlation_id: str | None = None,
) -> None:
    audit.append(
        "parser_result",
        {
            "parser": result.parser,
            "source_tool": result.source_tool,
            "evidence_id": result.evidence_id,
            "processed_count": result.processed_count,
            "malformed_count": result.malformed_count,
            "truncated": result.truncated,
            "warnings": [warning.model_dump(mode="json") for warning in result.warnings],
            "record_warning_count": sum(len(record.warnings) for record in result.records),
        },
        correlation_id=correlation_id or correlation_id_for(result.evidence_id, result.parser),
    )


def record_agent_decision(
    audit: AuditLogger,
    decision: AnalystDecision,
    *,
    token_usage: TokenUsage | None = None,
    correlation_id: str | None = None,
) -> None:
    audit.append(
        "agent_decision",
        {
            "decision": decision.model_dump(mode="json"),
            "token_usage": token_usage.model_dump(mode="json") if token_usage else None,
        },
        correlation_id=correlation_id or decision.decision_id,
    )


def record_rerun_trigger(
    audit: AuditLogger,
    trigger: CorrectionTrigger,
    *,
    correlation_id: str | None = None,
) -> None:
    audit.append(
        "rerun_trigger",
        trigger.model_dump(mode="json"),
        correlation_id=correlation_id or trigger.trigger_id,
    )


def record_validation_report(
    audit: AuditLogger,
    report: ValidationReport,
    *,
    correlation_id: str | None = None,
) -> None:
    audit.append(
        "validation_report",
        report.model_dump(mode="json"),
        correlation_id=correlation_id or correlation_id_for("validation", str(len(report.issues))),
    )


def record_correction_attempt(
    audit: AuditLogger,
    attempt: CorrectionAttempt,
    *,
    correlation_id: str | None = None,
) -> None:
    audit.append(
        "correction_outcome",
        attempt.model_dump(mode="json"),
        correlation_id=correlation_id or attempt.correction_id,
    )


def record_correction_history(
    audit: AuditLogger,
    history: CorrectionHistory,
    *,
    correlation_id: str | None = None,
) -> None:
    audit.append(
        "correction_history",
        history.as_report_section(),
        correlation_id=correlation_id or correlation_id_for("correction_history", str(len(history.attempts))),
    )


def record_confidence_adjustment(
    audit: AuditLogger,
    *,
    subject_id: str,
    before: float,
    after: float,
    reason: str,
    correlation_id: str | None = None,
) -> None:
    audit.append(
        "confidence_adjustment",
        {
            "subject_id": subject_id,
            "confidence_before": before,
            "confidence_after": after,
            "confidence_delta": round(after - before, 6),
            "reason": reason,
        },
        correlation_id=correlation_id or correlation_id_for("confidence", subject_id),
    )


def record_coverage_scores(
    audit: AuditLogger,
    report: CoverageReport,
    *,
    correlation_id: str | None = None,
) -> None:
    audit.append(
        "coverage_scores",
        {
            "overall_case_coverage": report.overall_case_coverage,
            "per_artifact": {
                artifact: coverage.model_dump(mode="json")
                for artifact, coverage in sorted(report.per_artifact.items())
            },
        },
        correlation_id=correlation_id or correlation_id_for("coverage", str(report.overall_case_coverage)),
    )
