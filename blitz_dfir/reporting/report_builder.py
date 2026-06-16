from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from blitz_dfir.core.models import NormalizedEvent
from blitz_dfir.correction.models import CorrectionHistory
from blitz_dfir.correction.validator import ValidationReport
from blitz_dfir.correlation.models import Contradiction, CorrelatedFinding
from blitz_dfir.reasoning.models import ReasoningResult
from blitz_dfir.reasoning.narrative import scrub_forbidden_language
from blitz_dfir.reporting.findings import FindingRecord, build_finding_records, scrub_report_text
from blitz_dfir.signal.coverage import AnalysisGap, CoverageReport
from blitz_dfir.signal.integrity import SignalIntegrityReport
from blitz_dfir.validation.truth_report import TruthValidationReport

APPROVED_LANGUAGE = (
    "Evidence strongly supports",
    "High-confidence reconstruction suggests",
    "Coverage X percent; analysis gaps documented",
    "Tool output is evidence candidate",
)


@dataclass
class EvidenceCredibilityAccumulator:
    evidence_id: str
    evidence_type: str
    trust_level: str
    event_count: int = 0
    source_tools: set[str] = field(default_factory=set)
    parsers: set[str] = field(default_factory=set)


class TimelineRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    timestamp_utc: str
    category: str
    source_tool: str
    parser: str
    evidence_id: str
    trust_level: str


class ReportDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    generated_at_utc: str
    language_policy: tuple[str, ...]
    case_objective: dict[str, object] = Field(default_factory=dict)
    investigation_plan: dict[str, object] = Field(default_factory=dict)
    investigation_guidance: dict[str, object] = Field(default_factory=dict)
    temporal_gap_analysis: dict[str, object] = Field(default_factory=dict)
    attack_stage_timeline: dict[str, object] = Field(default_factory=dict)
    evidence_triage: dict[str, object] = Field(default_factory=dict)
    correlation_scope: dict[str, object] = Field(default_factory=dict)
    findings: tuple[FindingRecord, ...]
    timeline: tuple[TimelineRecord, ...]
    contradictions: tuple[dict[str, object], ...] = ()
    self_correction: dict[str, object] = Field(default_factory=dict)
    audit_trail_reference: str
    coverage: dict[str, object] = Field(default_factory=dict)
    unknown_zones: tuple[dict[str, object], ...] = ()
    evidence_credibility: tuple[dict[str, object], ...] = ()
    tool_integrity_status: str
    cross_validation: dict[str, object] = Field(default_factory=dict)
    parser_consensus_score: float = Field(ge=0.0, le=1.0)
    global_case_trust_score: float = Field(ge=0.0, le=1.0)
    confirmed_evidence: tuple[dict[str, object], ...] = ()
    evidence_supported_findings: tuple[FindingRecord, ...] = ()
    inferred_analyst_reasoning: dict[str, object] = Field(default_factory=dict)
    llm_report_verification: dict[str, object] = Field(default_factory=dict)
    truth_validation: dict[str, object] = Field(default_factory=dict)


def build_report_document(
    *,
    case_id: str,
    events: tuple[NormalizedEvent, ...] = (),
    findings: tuple[CorrelatedFinding, ...] = (),
    contradictions: tuple[Contradiction, ...] = (),
    coverage_report: CoverageReport | None = None,
    signal_report: SignalIntegrityReport | None = None,
    validation_report: ValidationReport | None = None,
    correction_history: CorrectionHistory | None = None,
    reasoning: ReasoningResult | None = None,
    audit_trail_path: str = "",
    parser_versions: dict[str, str] | None = None,
    case_objective: dict[str, object] | None = None,
    investigation_plan: dict[str, object] | None = None,
    investigation_guidance: dict[str, object] | None = None,
    temporal_gap_analysis: dict[str, object] | None = None,
    attack_stage_timeline: dict[str, object] | None = None,
    evidence_triage: dict[str, object] | None = None,
    correlation_scope: dict[str, object] | None = None,
    llm_report_verification: dict[str, object] | None = None,
    truth_validation_report: TruthValidationReport | None = None,
) -> ReportDocument:
    events_by_id = {event.event_id: event for event in events}
    correction_notes = _correction_notes(correction_history)
    report_findings = _bounded_report_findings(findings)
    finding_records = build_finding_records(
        report_findings,
        events_by_id=events_by_id,
        parser_versions=parser_versions,
        recovery_notes=correction_notes,
    )
    coverage = _coverage_summary(coverage_report)
    generated_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    report = ReportDocument(
        case_id=scrub_report_text(case_id),
        generated_at_utc=generated_at,
        language_policy=APPROVED_LANGUAGE,
        case_objective=_safe_section(case_objective),
        investigation_plan=_safe_section(investigation_plan),
        investigation_guidance=_safe_section(investigation_guidance),
        temporal_gap_analysis=_safe_section(temporal_gap_analysis),
        attack_stage_timeline=_safe_section(attack_stage_timeline),
        evidence_triage=_safe_section(evidence_triage),
        correlation_scope=_safe_section(correlation_scope),
        findings=finding_records,
        timeline=tuple(_timeline_record(event) for event in _bounded_report_events(events)),
        contradictions=tuple(_contradiction_record(contradiction) for contradiction in contradictions),
        self_correction=correction_history.as_report_section() if correction_history else {},
        audit_trail_reference=scrub_report_text(audit_trail_path),
        coverage=coverage,
        unknown_zones=_unknown_zones(coverage_report, signal_report),
        evidence_credibility=_evidence_credibility(events),
        tool_integrity_status=_tool_integrity_status(signal_report),
        cross_validation=_cross_validation(validation_report, contradictions),
        parser_consensus_score=_parser_consensus(events),
        global_case_trust_score=_global_case_trust(finding_records, coverage_report, signal_report),
        confirmed_evidence=_confirmed_evidence(events),
        evidence_supported_findings=finding_records,
        inferred_analyst_reasoning=_reasoning_section(reasoning),
        llm_report_verification=_safe_section(llm_report_verification),
        truth_validation=_truth_validation_section(truth_validation_report),
    )
    return _scrub_report(report)


def export_json_report(report: ReportDocument, path: Path | None = None) -> str:
    text = json.dumps(report.model_dump(mode="json"), sort_keys=True, indent=2, ensure_ascii=True)
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
    return text


def _timeline_record(event: NormalizedEvent) -> TimelineRecord:
    return TimelineRecord(
        event_id=event.event_id,
        timestamp_utc=event.timestamp_utc,
        category=scrub_report_text(event.category),
        source_tool=scrub_report_text(event.source_tool),
        parser=scrub_report_text(event.source_parser),
        evidence_id=scrub_report_text(event.evidence_id),
        trust_level=event.trust_level.value,
    )


def _contradiction_record(contradiction: Contradiction) -> dict[str, object]:
    return {
        "contradiction_id": contradiction.contradiction_id,
        "subject": scrub_report_text(contradiction.subject),
        "field": scrub_report_text(contradiction.field),
        "left_value": scrub_report_text(contradiction.left_value),
        "right_value": scrub_report_text(contradiction.right_value),
        "severity": contradiction.severity,
        "reason": scrub_report_text(contradiction.reason),
        "event_ids": tuple(anchor.event_id for anchor in contradiction.evidence),
    }


def _coverage_summary(report: CoverageReport | None) -> dict[str, object]:
    if report is None:
        return {"overall_case_coverage": 0.0, "per_artifact": {}}
    return {
        "overall_case_coverage": report.overall_case_coverage,
        "per_artifact": {
            artifact: {
                "observed": coverage.observed,
                "expected": coverage.expected,
                "coverage": coverage.coverage,
                "missing_sources": coverage.missing_sources,
            }
            for artifact, coverage in sorted(report.per_artifact.items())
        },
    }


def _unknown_zones(
    coverage_report: CoverageReport | None,
    signal_report: SignalIntegrityReport | None,
) -> tuple[dict[str, object], ...]:
    gaps: list[AnalysisGap] = []
    if coverage_report is not None:
        gaps.extend(coverage_report.analysis_gaps)
    if signal_report is not None:
        gaps.extend(signal_report.analysis_gaps)
    return tuple(
        {
            "source": scrub_report_text(gap.source),
            "reason": scrub_report_text(gap.reason),
            "impact": scrub_report_text(gap.impact),
            "severity": gap.severity,
        }
        for gap in gaps
    )


def _evidence_credibility(events: tuple[NormalizedEvent, ...]) -> tuple[dict[str, object], ...]:
    by_evidence: dict[str, EvidenceCredibilityAccumulator] = {}
    for event in events:
        record = by_evidence.setdefault(
            event.evidence_id,
            EvidenceCredibilityAccumulator(
                evidence_id=event.evidence_id,
                evidence_type=event.evidence_type.value,
                trust_level=event.trust_level.value,
            ),
        )
        record.event_count += 1
        record.source_tools.add(event.source_tool)
        record.parsers.add(event.source_parser)
    output: list[dict[str, object]] = []
    for record in by_evidence.values():
        output.append(
            {
                "evidence_id": record.evidence_id,
                "evidence_type": record.evidence_type,
                "trust_level": record.trust_level,
                "event_count": record.event_count,
                "source_tools": tuple(sorted(record.source_tools)),
                "parsers": tuple(sorted(record.parsers)),
            }
        )
    return tuple(sorted(output, key=lambda item: str(item["evidence_id"])))


def _tool_integrity_status(signal_report: SignalIntegrityReport | None) -> str:
    if signal_report is None:
        return "unknown"
    warning_types = {warning.warning_type for warning in signal_report.warnings}
    if "HASH_MISMATCH" in warning_types or "TOOL_PROVENANCE" in warning_types:
        return "unverified"
    if signal_report.high_count or signal_report.critical_count:
        return "degraded"
    return "verified"


def _cross_validation(
    validation_report: ValidationReport | None,
    contradictions: tuple[Contradiction, ...],
) -> dict[str, object]:
    if validation_report is None:
        return {"status": "not_run", "contradiction_count": len(contradictions)}
    return {
        "status": "passed" if validation_report.passed else "issues_found",
        "issue_count": len(validation_report.issues),
        "contradiction_count": validation_report.contradiction_count,
        "parser_integrity_ok": validation_report.parser_integrity_ok,
        "issues": [issue.model_dump() for issue in validation_report.issues],
    }


def _safe_section(value: dict[str, object] | None) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    scrubbed = json.loads(json.dumps(value, sort_keys=True, default=str, ensure_ascii=True))
    return _scrub_object(scrubbed)


def _scrub_object(value: object) -> object:
    if isinstance(value, dict):
        return {scrub_report_text(key): _scrub_object(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_scrub_object(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_scrub_object(item) for item in value)
    if isinstance(value, str):
        return scrub_report_text(value)
    return value


def _parser_consensus(events: tuple[NormalizedEvent, ...]) -> float:
    if not events:
        return 0.0
    parser_count = len({(event.source_tool, event.source_parser) for event in events})
    return min(parser_count / 2, 1.0)


def _global_case_trust(
    findings: tuple[FindingRecord, ...],
    coverage_report: CoverageReport | None,
    signal_report: SignalIntegrityReport | None,
) -> float:
    finding_score = sum(finding.confidence for finding in findings) / len(findings) if findings else 0.0
    coverage_score = coverage_report.overall_case_coverage if coverage_report is not None else 0.0
    signal_penalty = signal_report.confidence_penalty if signal_report is not None else 0.0
    return min(max((finding_score * 0.55) + (coverage_score * 0.35) + (1 - signal_penalty) * 0.10, 0.0), 1.0)


def _bounded_report_events(events: tuple[NormalizedEvent, ...]) -> tuple[NormalizedEvent, ...]:
    ordered = tuple(sorted(events, key=lambda item: (item.timestamp_utc, item.event_id)))
    limit = _report_event_limit()
    if limit == 0:
        return ()
    return ordered[:limit]


def _bounded_report_findings(findings: tuple[CorrelatedFinding, ...]) -> tuple[CorrelatedFinding, ...]:
    limit = _report_finding_limit()
    if limit == 0:
        return ()
    deduped = _dedupe_report_findings(findings)
    ordered = tuple(
        sorted(
            deduped,
            key=lambda item: (
                item.triage_score,
                item.confidence,
                len(item.supporting_event_ids),
                item.finding_id,
            ),
            reverse=True,
        )
    )
    return ordered[:limit]


def _dedupe_report_findings(findings: tuple[CorrelatedFinding, ...]) -> tuple[CorrelatedFinding, ...]:
    deduped: list[CorrelatedFinding] = []
    seen: set[str] = set()
    for finding in findings:
        if finding.finding_id in seen:
            continue
        seen.add(finding.finding_id)
        deduped.append(finding)
    return tuple(deduped)


def _report_finding_limit() -> int:
    raw = os.environ.get("BLITZ_REPORT_FINDING_LIMIT")
    if raw is None or raw == "":
        return 500
    try:
        value = int(raw)
    except ValueError:
        return 500
    return min(max(value, 0), 2_000_000)


def _report_event_limit() -> int:
    raw = os.environ.get("BLITZ_REPORT_EVENT_LIMIT")
    if raw is None or raw == "":
        return 10_000
    try:
        value = int(raw)
    except ValueError:
        return 10_000
    return min(max(value, 0), 2_000_000)


def _confirmed_evidence(events: tuple[NormalizedEvent, ...]) -> tuple[dict[str, object], ...]:
    return tuple(
        {
            "event_id": event.event_id,
            "evidence_id": event.evidence_id,
            "timestamp_utc": event.timestamp_utc,
            "trust_level": event.trust_level.value,
            "raw_reference": event.raw_reference.model_dump(),
        }
        for event in _bounded_report_events(events)
    )


def _reasoning_section(reasoning: ReasoningResult | None) -> dict[str, object]:
    if reasoning is None:
        return {}
    return {
        "evidence_type": reasoning.evidence_type.value,
        "hypotheses": [hypothesis.model_dump() for hypothesis in reasoning.hypotheses],
        "analysis_limits": reasoning.uncertainty,
        "contradiction_notes": reasoning.contradiction_notes,
        "narrative": scrub_report_text(reasoning.narrative),
        "decisions": [decision.model_dump() for decision in reasoning.decisions],
        "prompt_hash": reasoning.prompt_hash,
        "provider_metadata": reasoning.provider_metadata.model_dump() if reasoning.provider_metadata else None,
        "token_usage": reasoning.token_usage.model_dump() if reasoning.token_usage else None,
    }


def _truth_validation_section(report: TruthValidationReport | None) -> dict[str, object]:
    if report is None:
        return {
            "status": "not_run",
            "dataset_name": None,
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
            "matched_findings": 0,
            "missed_findings": 0,
            "unexpected_findings": 0,
            "passed": False,
        }
    payload = report.model_dump(mode="json")
    payload["status"] = "passed" if report.passed else "failed"
    return _scrub_object(payload)


def _correction_notes(history: CorrectionHistory | None) -> tuple[str, ...]:
    if history is None:
        return ()
    return tuple(
        scrub_report_text(f"{attempt.correction_id}: {attempt.status}; {attempt.result}")
        for attempt in history.attempts
    )


def _scrub_report(report: ReportDocument) -> ReportDocument:
    text = report.model_dump_json()
    scrubbed = scrub_forbidden_language(text)
    if scrubbed == text:
        return report
    return ReportDocument.model_validate_json(scrubbed)
