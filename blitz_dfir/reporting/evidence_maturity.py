from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from blitz_dfir.accounting.models import FullAccountingSummary
from blitz_dfir.core.integrity import sha256_file
from blitz_dfir.core.models import EvidenceManifest, EvidenceRecord, NormalizedEvent
from blitz_dfir.correction.validator import ValidationReport
from blitz_dfir.correlation.models import CorrelatedFinding
from blitz_dfir.parsers.models import ParserResult
from blitz_dfir.reporting.findings import scrub_report_text
from blitz_dfir.signal.coverage import CoverageReport
from blitz_dfir.signal.integrity import SignalIntegrityReport
from blitz_dfir.unknowns.models import UnknownsReport
from blitz_dfir.validation.truth_report import (
    TruthValidationReport,
)
from blitz_dfir.reasoning.truth_alignment import (
    TruthAlignment,
)


class AuditReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sequence: int
    event_type: str
    timestamp_utc: str
    correlation_id: str | None = None
    entry_hash: str


class EvidenceHashCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    evidence_type: str
    expected_sha256: str
    observed_sha256: str | None = None
    preserved: bool
    status: str


class ToolExecutionLink(BaseModel):
    model_config = ConfigDict(extra="forbid")

    typed_tool: str
    tool_name: str
    evidence_id: str
    exit_code: int | None = None
    duration_ms: int | None = None
    timed_out: bool = False
    primary_output: str | None = None
    output_hash: str | None = None
    tool_verified: bool | None = None
    audit_entries: tuple[AuditReference, ...] = ()


class ParserLink(BaseModel):
    model_config = ConfigDict(extra="forbid")

    parser: str
    source_tool: str
    evidence_id: str
    processed_count: int
    malformed_count: int
    truncated: bool
    warning_count: int
    audit_entries: tuple[AuditReference, ...] = ()


class NormalizedRecordLink(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    timestamp_utc: str
    category: str
    evidence_id: str
    source_tool: str
    parser: str
    raw_reference: dict[str, object]
    confidence: float = Field(ge=0.0, le=1.0)


class EvidenceChainLink(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    evidence_id: str
    traceability_status: str
    normalized_record: NormalizedRecordLink | None = None
    parser_result: ParserLink | None = None
    tool_execution: ToolExecutionLink | None = None
    audit_entries: tuple[AuditReference, ...] = ()
    gaps: tuple[str, ...] = ()


class FindingTrace(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    title: str
    confidence: float = Field(ge=0.0, le=1.0)
    triage_score: float = Field(ge=0.0, le=1.0)
    why_flagged: tuple[str, ...]
    confidence_modifiers: tuple[str, ...]
    attack_stages: tuple[str, ...] = ()
    evidence_chain: tuple[EvidenceChainLink, ...]
    complete: bool
    gaps: tuple[str, ...] = ()


class CoverageMaturity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    overall_case_coverage: float = Field(ge=0.0, le=1.0)
    artifact_count: int = Field(ge=0)
    gap_count: int = Field(ge=0)
    high_or_critical_gap_count: int = Field(ge=0)
    unanalyzed_or_degraded_zones: tuple[dict[str, object], ...] = ()


class SpoliationProtectionSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    evidence_hashes_preserved: bool
    mutation_attempt_observed: bool
    architectural_controls: tuple[str, ...]
    demo_command: str


class EvidencePackageReadiness(BaseModel):
    model_config = ConfigDict(extra="forbid")

    real_case_validation: str
    accuracy_report: str
    dataset_documentation: str
    repeatability_matrix: str
    agent_execution_logs: str
    demo_video: str

    truth_validation: str = "not_run"

    truth_precision: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    truth_recall: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    truth_f1: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    truth_matched_findings: int = Field(
        default=0,
        ge=0,
    )

    truth_missed_findings: int = Field(
        default=0,
        ge=0,
    )

    truth_unexpected_findings: int = Field(
        default=0,
        ge=0,
    )


class EvidenceMaturityReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "evidence-maturity.v1"
    case_id: str
    session_id: str
    generated_at_utc: str
    summary: dict[str, object]
    evidence_hash_checks: tuple[EvidenceHashCheck, ...]
    finding_traces: tuple[FindingTrace, ...]
    coverage_maturity: CoverageMaturity
    spoliation_protection: SpoliationProtectionSummary
    evidence_package_readiness: EvidencePackageReadiness
    truth_alignment: TruthAlignment | None = None

def build_evidence_maturity_report(
    *,
    case_id: str,
    session_id: str,
    manifest: EvidenceManifest,
    events: tuple[NormalizedEvent, ...],
    findings: tuple[CorrelatedFinding, ...],
    parser_results: Iterable[ParserResult],
    tool_results: Iterable[dict[str, Any]],
    coverage_report: CoverageReport,
    signal_report: SignalIntegrityReport,
    validation_report: ValidationReport,
    truth_validation_report: TruthValidationReport | None = None,
    unknowns_report: UnknownsReport,
    full_accounting: FullAccountingSummary,
    audit_log_path: Path,
) -> EvidenceMaturityReport:
    audit_entries = _load_audit_entries(audit_log_path)
    events_by_id = {event.event_id: event for event in events}
    evidence_by_id = {record.evidence_id: record for record in manifest.evidence}
    parser_index = _parser_index(parser_results, audit_entries)
    tool_index = _tool_index(tool_results, audit_entries)
    evidence_hash_checks = tuple(_hash_check(record) for record in manifest.evidence)
    finding_traces = tuple(
        _finding_trace(
            finding,
            events_by_id=events_by_id,
            evidence_by_id=evidence_by_id,
            parser_index=parser_index,
            tool_index=tool_index,
            audit_entries=audit_entries,
        )
        for finding in findings
    )
    traceable_count = sum(1 for trace in finding_traces if trace.complete)
    evidence_hashes_preserved = all(check.preserved for check in evidence_hash_checks)
    generated_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    return EvidenceMaturityReport(
        case_id=scrub_report_text(case_id),
        session_id=scrub_report_text(session_id),
        generated_at_utc=generated_at,
        summary={
            "finding_count": len(finding_traces),
            "traceable_finding_count": traceable_count,
            "all_findings_traceable": traceable_count == len(finding_traces),
            "evidence_hashes_preserved": evidence_hashes_preserved,
            "validation_passed": validation_report.passed,
            "validation_issue_count": len(validation_report.issues),
            "signal_warning_count": len(signal_report.warnings),
            "unknown_count": unknowns_report.unknown_count,
            "full_accounting_total_rows": full_accounting.total_rows,
        },
        evidence_hash_checks=evidence_hash_checks,
        finding_traces=finding_traces,
        coverage_maturity=_coverage_maturity(coverage_report, signal_report),
        spoliation_protection=SpoliationProtectionSummary(
            status="hashes_preserved" if evidence_hashes_preserved else "hash_mismatch_detected",
            evidence_hashes_preserved=evidence_hashes_preserved,
            mutation_attempt_observed=_mutation_attempt_observed(audit_entries),
            architectural_controls=(
                "manifest-registered evidence IDs",
                "typed MCP allowlist",
                "no generic shell tool exposed",
                "session-scoped output directory",
                "before/after evidence SHA256 checks",
                "tamper-evident audit chain",
            ),
            demo_command="python scripts/blitz_spoliation_demo.py",
        ),
        evidence_package_readiness=EvidencePackageReadiness(
            real_case_validation="requires documented real dataset run",
            accuracy_report="requires docs/ACCURACY_REPORT.md update after dataset run",
            dataset_documentation="requires docs/DATASETS.md update with source, license, hashes, and results",
            repeatability_matrix="requires repeated run entries in docs/REPEATABILITY_MATRIX.md",
            agent_execution_logs="requires OpenClaw or Claude Code run logs with timestamps and token usage",
            demo_video="requires 5-minute live terminal recording against real evidence",
            truth_validation=("completed" if truth_validation_report else "not_run"),
            truth_precision=(truth_validation_report.precision if truth_validation_report else 0.0),
            truth_recall=(truth_validation_report.recall if truth_validation_report else 0.0),
            truth_f1=(truth_validation_report.f1 if truth_validation_report else 0.0),
            truth_matched_findings=(truth_validation_report.matched_findings if truth_validation_report else 0),
            truth_missed_findings=(truth_validation_report.missed_findings if truth_validation_report else 0),
            truth_unexpected_findings=(
                truth_validation_report.unexpected_findings if truth_validation_report else 0
            ),
        ),
        truth_alignment=(
            TruthAlignment(
                verdict_matches_truth=truth_validation_report.passed,
                precision=truth_validation_report.precision,
                recall=truth_validation_report.recall,
                f1=truth_validation_report.f1,
                matched_findings=truth_validation_report.matched_findings,
                missed_findings=truth_validation_report.missed_findings,
                unexpected_findings=truth_validation_report.unexpected_findings,
            )
            if truth_validation_report
            else None
        ),
    )


def export_evidence_maturity_report(report: EvidenceMaturityReport, path: Path | None = None) -> str:
    text = json.dumps(report.model_dump(mode="json"), sort_keys=True, indent=2, ensure_ascii=True)
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
    return text


def render_evidence_maturity_markdown(report: EvidenceMaturityReport, path: Path | None = None) -> str:
    lines = [
        "# Blitz DFIR Evidence Maturity Report",
        "",
        f"- Case: `{report.case_id}`",
        f"- Session: `{report.session_id}`",
        f"- Generated: `{report.generated_at_utc}`",
        f"- Findings traceable: `{report.summary['traceable_finding_count']}/{report.summary['finding_count']}`",
        f"- Evidence hashes preserved: `{report.summary['evidence_hashes_preserved']}`",
        f"- Validation passed: `{report.summary['validation_passed']}`",
        f"- Unknown count: `{report.summary['unknown_count']}`",
        f"- Full accounting rows: `{report.summary['full_accounting_total_rows']}`",
        "",
        "## Finding Traceability",
        "",
    ]
    for trace in report.finding_traces:
        lines.extend(
            [
                f"### {trace.finding_id}",
                "",
                f"- Title: {trace.title}",
                f"- Complete: `{trace.complete}`",
                f"- Confidence: `{trace.confidence:.2f}`",
                f"- Why flagged: {'; '.join(trace.why_flagged)}",
                f"- Gaps: {'; '.join(trace.gaps) if trace.gaps else 'none'}",
                "",
            ]
        )
        for link in trace.evidence_chain:
            parser = link.parser_result.parser if link.parser_result else "missing"
            tool = link.tool_execution.typed_tool if link.tool_execution else "direct/unknown"
            lines.append(
                f"- `{link.event_id}` evidence `{link.evidence_id}` status `{link.traceability_status}` "
                f"parser `{parser}` tool `{tool}`"
            )
        lines.append("")

    lines.extend(
        [
            "## Coverage And Unknown Zones",
            "",
            f"- Overall coverage: `{report.coverage_maturity.overall_case_coverage:.2f}`",
            f"- Gap count: `{report.coverage_maturity.gap_count}`",
            f"- High or critical gaps: `{report.coverage_maturity.high_or_critical_gap_count}`",
            "",
            "## Evidence Hash Checks",
            "",
        ]
    )
    for check in report.evidence_hash_checks:
        lines.append(
            f"- `{check.evidence_id}` `{check.evidence_type}` preserved `{check.preserved}` status `{check.status}`"
        )

    lines.extend(
        [
            "",
            "## Spoliation Protection",
            "",
            f"- Status: `{report.spoliation_protection.status}`",
            f"- Mutation attempt observed in this run: `{report.spoliation_protection.mutation_attempt_observed}`",
            f"- Demo command: `{report.spoliation_protection.demo_command}`",
        ]
    )
    text = "\n".join(lines).rstrip() + "\n"
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return text


def _finding_trace(
    finding: CorrelatedFinding,
    *,
    events_by_id: Mapping[str, NormalizedEvent],
    evidence_by_id: Mapping[str, EvidenceRecord],
    parser_index: Mapping[tuple[str, str, str], ParserLink],
    tool_index: Mapping[tuple[str, str], ToolExecutionLink],
    audit_entries: tuple[dict[str, Any], ...],
) -> FindingTrace:
    links: list[EvidenceChainLink] = []
    gaps: list[str] = []
    for event_id in finding.supporting_event_ids:
        event = events_by_id.get(event_id)
        if event is None:
            gap = f"supporting event not available in analysis set: {event_id}"
            gaps.append(gap)
            links.append(
                EvidenceChainLink(
                    event_id=event_id,
                    evidence_id="unknown",
                    traceability_status="missing-normalized-event",
                    gaps=(gap,),
                )
            )
            continue
        parser = parser_index.get((event.evidence_id, event.source_parser, event.source_tool))
        tool = tool_index.get((event.evidence_id, event.source_tool))
        evidence = evidence_by_id.get(event.evidence_id)
        link_gaps: list[str] = []
        if parser is None:
            link_gaps.append("parser result summary not found")
        if tool is None and evidence is not None and evidence.pipeline.value != "processed":
            link_gaps.append("tool execution summary not found")
        event_audit = _audit_for_event(event, audit_entries)
        links.append(
            EvidenceChainLink(
                event_id=event.event_id,
                evidence_id=event.evidence_id,
                traceability_status="complete" if not link_gaps else "partial",
                normalized_record=NormalizedRecordLink(
                    event_id=event.event_id,
                    timestamp_utc=event.timestamp_utc,
                    category=scrub_report_text(event.category),
                    evidence_id=event.evidence_id,
                    source_tool=scrub_report_text(event.source_tool),
                    parser=scrub_report_text(event.source_parser),
                    raw_reference=event.raw_reference.model_dump(mode="json"),
                    confidence=event.confidence,
                ),
                parser_result=parser,
                tool_execution=tool,
                audit_entries=event_audit,
                gaps=tuple(link_gaps),
            )
        )
        gaps.extend(link_gaps)
    return FindingTrace(
        finding_id=finding.finding_id,
        title=scrub_report_text(finding.title),
        confidence=finding.confidence,
        triage_score=finding.triage_score,
        why_flagged=tuple(scrub_report_text(reason) for reason in finding.suspicion_reasons),
        confidence_modifiers=tuple(scrub_report_text(modifier) for modifier in finding.confidence_modifiers),
        attack_stages=tuple(scrub_report_text(stage) for stage in finding.attack_stages),
        evidence_chain=tuple(links),
        complete=bool(links) and not gaps,
        gaps=tuple(gaps),
    )


def _parser_index(
    parser_results: Iterable[ParserResult],
    audit_entries: tuple[dict[str, Any], ...],
) -> dict[tuple[str, str, str], ParserLink]:
    output: dict[tuple[str, str, str], ParserLink] = {}
    for result in parser_results:
        key = (result.evidence_id, result.parser, result.source_tool)
        output[key] = ParserLink(
            parser=result.parser,
            source_tool=result.source_tool,
            evidence_id=result.evidence_id,
            processed_count=result.processed_count,
            malformed_count=result.malformed_count,
            truncated=result.truncated,
            warning_count=len(result.warnings),
            audit_entries=_audit_refs(
                _matching_audit_entries(
                    audit_entries,
                    event_types={"parser_completed", "parser_result"},
                    evidence_id=result.evidence_id,
                    parser=result.parser,
                    source_tool=result.source_tool,
                )
            ),
        )
    return output


def _tool_index(
    tool_results: Iterable[dict[str, Any]],
    audit_entries: tuple[dict[str, Any], ...],
) -> dict[tuple[str, str], ToolExecutionLink]:
    output: dict[tuple[str, str], ToolExecutionLink] = {}
    for result in tool_results:
        evidence_id = str(result.get("evidence_id") or "")
        typed_tool = str(result.get("typed_tool") or result.get("tool_name") or "unknown")
        tool_name = str(result.get("tool_name") or typed_tool)
        execution = _dict_value(result, "execution")
        outputs = _dict_value(result, "outputs")
        integrity = _dict_value(result, "tool_integrity")
        output[(evidence_id, tool_name)] = ToolExecutionLink(
            typed_tool=typed_tool,
            tool_name=tool_name,
            evidence_id=evidence_id,
            exit_code=_optional_int(execution.get("exit_code")),
            duration_ms=_optional_int(execution.get("duration_ms")),
            timed_out=bool(execution.get("timed_out")),
            primary_output=_optional_str(outputs.get("primary_output")),
            output_hash=_optional_str(outputs.get("output_hash")),
            tool_verified=integrity.get("verified") if isinstance(integrity.get("verified"), bool) else None,
            audit_entries=_audit_refs(
                _matching_audit_entries(
                    audit_entries,
                    event_types={
                        "analysis_tool_result",
                        "tool_request_validated",
                        "tool_request_completed",
                        "tool_execution",
                    },
                    evidence_id=evidence_id,
                    tool=typed_tool,
                    tool_name=tool_name,
                )
            ),
        )
        output.setdefault((evidence_id, typed_tool), output[(evidence_id, tool_name)])
    return output


def _coverage_maturity(
    coverage_report: CoverageReport,
    signal_report: SignalIntegrityReport,
) -> CoverageMaturity:
    gaps = (*coverage_report.analysis_gaps, *signal_report.analysis_gaps)
    zones: list[dict[str, object]] = []
    for gap in gaps:
        zones.append(
            {
                "source": scrub_report_text(gap.source),
                "reason": scrub_report_text(gap.reason),
                "impact": scrub_report_text(gap.impact),
                "severity": gap.severity,
                "metadata": gap.metadata,
            }
        )
    high_or_critical = sum(1 for gap in gaps if gap.severity in {"HIGH", "CRITICAL"})
    return CoverageMaturity(
        overall_case_coverage=coverage_report.overall_case_coverage,
        artifact_count=len(coverage_report.per_artifact),
        gap_count=len(zones),
        high_or_critical_gap_count=high_or_critical,
        unanalyzed_or_degraded_zones=tuple(zones),
    )


def _hash_check(record: EvidenceRecord) -> EvidenceHashCheck:
    try:
        observed = sha256_file(record.path)
    except OSError:
        return EvidenceHashCheck(
            evidence_id=record.evidence_id,
            evidence_type=record.evidence_type.value,
            expected_sha256=record.sha256,
            observed_sha256=None,
            preserved=False,
            status="evidence_unreadable_after_analysis",
        )
    preserved = observed.lower() == record.sha256.lower()
    return EvidenceHashCheck(
        evidence_id=record.evidence_id,
        evidence_type=record.evidence_type.value,
        expected_sha256=record.sha256,
        observed_sha256=observed,
        preserved=preserved,
        status="preserved" if preserved else "hash_mismatch_after_analysis",
    )


def _load_audit_entries(path: Path) -> tuple[dict[str, Any], ...]:
    if not path.exists():
        return ()
    entries: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            entries.append(payload)
    return tuple(entries)


def _audit_for_event(
    event: NormalizedEvent,
    audit_entries: tuple[dict[str, Any], ...],
) -> tuple[AuditReference, ...]:
    return _audit_refs(
        _matching_audit_entries(
            audit_entries,
            event_types={
                "evidence_verified",
                "analysis_tool_result",
                "parser_completed",
                "correlation_completed",
                "validation_completed",
            },
            evidence_id=event.evidence_id,
            parser=event.source_parser,
            source_tool=event.source_tool,
            tool=event.source_tool,
        )
    )


def _matching_audit_entries(
    audit_entries: tuple[dict[str, Any], ...],
    *,
    event_types: set[str],
    evidence_id: str,
    parser: str | None = None,
    source_tool: str | None = None,
    tool: str | None = None,
    tool_name: str | None = None,
) -> tuple[dict[str, Any], ...]:
    matches: list[dict[str, Any]] = []
    for entry in audit_entries:
        if entry.get("event_type") not in event_types:
            continue
        data = entry.get("data")
        if not isinstance(data, dict):
            continue
        if data.get("evidence_id") not in {evidence_id, None} and entry.get("event_type") != "correlation_completed":
            continue
        if parser and data.get("parser") not in {parser, None}:
            continue
        if source_tool and data.get("source_tool") not in {source_tool, None}:
            continue
        data_tools = {str(data.get("tool") or ""), str(data.get("typed_tool") or ""), str(data.get("tool_name") or "")}
        expected_tools = {value for value in (tool, tool_name) if value}
        if expected_tools and data_tools.isdisjoint(expected_tools) and entry.get("event_type") not in {
            "evidence_verified",
            "parser_completed",
            "correlation_completed",
            "validation_completed",
        }:
            continue
        matches.append(entry)
    return tuple(matches)


def _audit_refs(entries: tuple[dict[str, Any], ...]) -> tuple[AuditReference, ...]:
    refs: list[AuditReference] = []
    for entry in entries:
        refs.append(
            AuditReference(
                sequence=_optional_int(entry.get("sequence")) or 0,
                event_type=scrub_report_text(entry.get("event_type")),
                timestamp_utc=scrub_report_text(entry.get("timestamp_utc")),
                correlation_id=_optional_str(entry.get("correlation_id")),
                entry_hash=scrub_report_text(entry.get("entry_hash")),
            )
        )
    return tuple(refs)


def _mutation_attempt_observed(audit_entries: tuple[dict[str, Any], ...]) -> bool:
    for entry in audit_entries:
        if entry.get("event_type") == "tool_request_rejected":
            data = entry.get("data")
            if isinstance(data, dict) and data.get("reason") == "tool_not_allowlisted":
                return True
    return False


def _dict_value(value: dict[str, Any], key: str) -> dict[str, Any]:
    item = value.get(key)
    return item if isinstance(item, dict) else {}


def _optional_int(value: object) -> int | None:
    return value if isinstance(value, int) else None


def _optional_str(value: object) -> str | None:
    return scrub_report_text(value) if isinstance(value, str) and value else None
