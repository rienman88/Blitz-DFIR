from __future__ import annotations

from blitz_dfir.accounting.models import FullAccountingSummary
from blitz_dfir.core.integrity import hash_text
from blitz_dfir.core.models import SignalWarning
from blitz_dfir.correction.models import ValidationReport
from blitz_dfir.signal.coverage import AnalysisGap, CoverageReport
from blitz_dfir.signal.integrity import SignalIntegrityReport
from blitz_dfir.unknowns.models import UnknownRecord, UnknownStatus, UnknownsReport

WARNING_STATUS: dict[str, UnknownStatus] = {
    "TOOL_TIMEOUT": "NEEDS_REVIEW",
    "EVENT_TRUNCATION": "NEEDS_REVIEW",
    "PARSER_CRASH": "NEEDS_REVIEW",
    "PARSER_DEGRADATION": "NEEDS_REVIEW",
    "PARTIAL_EXTRACTION": "NEEDS_REVIEW",
    "MISSING_ARTIFACT": "UNKNOWN",
    "LOW_COVERAGE": "UNKNOWN",
    "FIELD_TRUNCATION": "NEEDS_REVIEW",
    "FIELD_SANITIZED": "NEEDS_REVIEW",
    "HASH_MISMATCH": "UNSUPPORTED",
    "TOOL_PROVENANCE": "UNSUPPORTED",
}


def build_unknowns_report(
    *,
    coverage_report: CoverageReport | None = None,
    signal_report: SignalIntegrityReport | None = None,
    validation_report: ValidationReport | None = None,
    full_accounting: FullAccountingSummary | None = None,
) -> UnknownsReport:
    records: list[UnknownRecord] = []
    if coverage_report is not None:
        records.extend(_records_from_gaps(coverage_report.analysis_gaps, category="coverage_gap"))
    if signal_report is not None:
        records.extend(_records_from_gaps(signal_report.analysis_gaps, category="signal_gap"))
        records.extend(_records_from_warnings(signal_report.warnings))
    if validation_report is not None:
        records.extend(_records_from_validation(validation_report))
    if full_accounting is not None:
        records.extend(_records_from_accounting(full_accounting))
    deduplicated = _deduplicate(records)
    return UnknownsReport(
        unknown_count=len(deduplicated),
        critical_count=sum(1 for record in deduplicated if record.severity == "CRITICAL"),
        high_count=sum(1 for record in deduplicated if record.severity == "HIGH"),
        records=tuple(deduplicated),
    )


def _records_from_gaps(gaps: tuple[AnalysisGap, ...], *, category: str) -> list[UnknownRecord]:
    return [
        UnknownRecord(
            unknown_id=_unknown_id(category, gap.source, gap.reason, gap.impact),
            status="UNKNOWN",
            severity=gap.severity,
            category=category,
            source=gap.source,
            reason=gap.reason,
            impact=gap.impact,
            recommended_action="Acquire or route the missing source, then rerun the relevant typed tool.",
            metadata=gap.metadata,
        )
        for gap in gaps
    ]


def _records_from_warnings(warnings: tuple[SignalWarning, ...]) -> list[UnknownRecord]:
    records: list[UnknownRecord] = []
    for warning in warnings:
        status = WARNING_STATUS.get(warning.warning_type, "NEEDS_REVIEW")
        records.append(
            UnknownRecord(
                unknown_id=_unknown_id(
                    warning.warning_type,
                    warning.artifact,
                    warning.impact,
                    str(warning.metadata),
                ),
                status=status,
                severity=warning.severity,
                category=warning.warning_type,
                source=warning.tool or warning.artifact,
                reason=warning.warning_type.lower(),
                impact=warning.impact,
                evidence_id=warning.artifact,
                recommended_action=_warning_action(warning.warning_type),
                metadata=warning.metadata,
            )
        )
    return records


def _records_from_validation(report: ValidationReport) -> list[UnknownRecord]:
    records: list[UnknownRecord] = []
    for issue in report.issues:
        records.append(
            UnknownRecord(
                unknown_id=_unknown_id(issue.issue_type, issue.message, issue.finding_id or ""),
                status="NEEDS_REVIEW",
                severity=issue.severity,
                category=issue.issue_type,
                source=issue.finding_id or ",".join(issue.event_ids) or "case_validation",
                reason=issue.issue_type.lower(),
                impact=issue.message,
                evidence_id=issue.finding_id,
                recommended_action="Review supporting evidence, run a narrower typed rerun, or downgrade the claim.",
                metadata=issue.metadata,
            )
        )
    return records


def _records_from_accounting(summary: FullAccountingSummary) -> list[UnknownRecord]:
    records: list[UnknownRecord] = []
    for artifact in summary.artifacts:
        if artifact.row_count == 0:
            records.append(
                UnknownRecord(
                    unknown_id=_unknown_id("empty_accounting_artifact", artifact.artifact_id),
                    status="UNKNOWN",
                    severity="HIGH",
                    category="empty_accounting_artifact",
                    source=artifact.source_path,
                    reason="no rows accounted",
                    impact="Full accounting found no rows in an expected event artifact.",
                    evidence_id=artifact.evidence_id,
                    recommended_action="Inspect tool stdout/stderr and rerun with a narrower filter or slice.",
                    metadata={"artifact_id": artifact.artifact_id},
                )
            )
        if artifact.partial or artifact.timed_out:
            records.append(
                UnknownRecord(
                    unknown_id=_unknown_id("partial_accounting_artifact", artifact.artifact_id),
                    status="NEEDS_REVIEW",
                    severity="HIGH",
                    category="partial_accounting_artifact",
                    source=artifact.source_path,
                    reason="source tool output was partial",
                    impact="The event store preserves all exported rows, but the source tool timed out before full export.",
                    evidence_id=artifact.evidence_id,
                    recommended_action="Rerun with a time slice, narrower data source, or longer controlled timeout.",
                    metadata={"artifact_id": artifact.artifact_id, "row_count": artifact.row_count},
                )
            )
    return records


def _warning_action(warning_type: str) -> str:
    if warning_type in {"TOOL_TIMEOUT", "EVENT_TRUNCATION", "PARTIAL_EXTRACTION"}:
        return "Run a narrower typed rerun or full-accounting export before making final accuracy claims."
    if warning_type in {"MISSING_ARTIFACT", "LOW_COVERAGE"}:
        return "Acquire the missing artifact or document the scope boundary explicitly."
    if warning_type in {"HASH_MISMATCH", "TOOL_PROVENANCE"}:
        return "Do not trust the affected output until tool/evidence integrity is revalidated."
    return "Review the affected artifact and document whether the signal can support a claim."


def _deduplicate(records: list[UnknownRecord]) -> list[UnknownRecord]:
    output: list[UnknownRecord] = []
    seen: set[str] = set()
    for record in records:
        if record.unknown_id in seen:
            continue
        seen.add(record.unknown_id)
        output.append(record)
    return sorted(output, key=lambda record: (record.severity, record.category, record.unknown_id))


def _unknown_id(*parts: str) -> str:
    digest = hash_text("|".join(parts))[:12].upper()
    return f"UNK-{digest}"
