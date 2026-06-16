from __future__ import annotations

from collections.abc import Mapping

from pydantic import BaseModel, ConfigDict, Field

from blitz_dfir.core.models import NormalizedEvent, RawReference
from blitz_dfir.correlation.models import CorrelatedFinding, EvidenceAnchor
from blitz_dfir.reasoning.narrative import scrub_forbidden_language


class ReportEvidenceReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    evidence_id: str
    source_tool: str
    parser: str
    raw_reference: RawReference
    trust_level: str


class FindingExplainability(BaseModel):
    model_config = ConfigDict(extra="forbid")

    why_flagged: tuple[str, ...]
    supporting_artifacts: tuple[str, ...]
    producing_tools: tuple[str, ...]
    confidence_basis: tuple[str, ...]
    limitations: tuple[str, ...] = ()


class FindingRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    finding: str
    evidence_source: tuple[str, ...]
    source_tool: tuple[str, ...]
    parser: tuple[str, ...]
    parser_version: str
    timestamp: str
    confidence: float = Field(ge=0.0, le=1.0)
    confidence_modifiers: tuple[str, ...]
    triage_score: float = Field(ge=0.0, le=1.0)
    suspicion_reasons: tuple[str, ...] = ()
    correlation_path: tuple[str, ...]
    evidence_type: str
    recovery_notes: tuple[str, ...] = ()
    evidence_references: tuple[ReportEvidenceReference, ...]
    summary: str
    attack_stages: tuple[str, ...] = ()
    explainability: FindingExplainability
    traceability_status: str = "evidence-referenced"


def build_finding_records(
    findings: tuple[CorrelatedFinding, ...],
    *,
    events_by_id: Mapping[str, NormalizedEvent] | None = None,
    parser_versions: Mapping[str, str] | None = None,
    recovery_notes: tuple[str, ...] = (),
) -> tuple[FindingRecord, ...]:
    records: list[FindingRecord] = []
    for finding in findings:
        references = tuple(_reference_from_anchor(anchor) for anchor in finding.evidence)
        timestamps = _timestamps_for_finding(finding, events_by_id or {})
        source_tools = tuple(sorted({reference.source_tool for reference in references}))
        parsers = tuple(sorted({reference.parser for reference in references}))
        evidence_sources = tuple(sorted({reference.evidence_id for reference in references}))
        confidence_modifiers = tuple(scrub_report_text(value) for value in finding.confidence_modifiers)
        suspicion_reasons = tuple(scrub_report_text(value) for value in finding.suspicion_reasons)
        recovery = tuple(scrub_report_text(note) for note in recovery_notes)
        records.append(
            FindingRecord(
                finding_id=finding.finding_id,
                finding=scrub_report_text(finding.title),
                evidence_source=evidence_sources,
                source_tool=source_tools,
                parser=parsers,
                parser_version=_parser_version(parsers, parser_versions or {}),
                timestamp=timestamps[0] if timestamps else "unknown",
                confidence=finding.confidence,
                confidence_modifiers=confidence_modifiers,
                triage_score=finding.triage_score,
                suspicion_reasons=suspicion_reasons,
                correlation_path=finding.supporting_event_ids,
                evidence_type="evidence-supported",
                recovery_notes=recovery,
                evidence_references=references,
                summary=scrub_report_text(finding.summary),
                attack_stages=tuple(scrub_report_text(stage) for stage in finding.attack_stages),
                explainability=FindingExplainability(
                    why_flagged=suspicion_reasons
                    or ("no deterministic suspicious condition matched; retained as low-priority context",),
                    supporting_artifacts=evidence_sources,
                    producing_tools=tuple(
                        sorted(f"{reference.source_tool}/{reference.parser}" for reference in references)
                    ),
                    confidence_basis=_confidence_basis(finding.confidence, confidence_modifiers),
                    limitations=_limitations(confidence_modifiers, recovery, references),
                ),
                traceability_status="traceable-to-normalized-events" if references else "missing-evidence-reference",
            )
        )
    return tuple(records)


def scrub_report_text(value: object) -> str:
    text = "" if value is None else str(value)
    return scrub_forbidden_language(" ".join(text.split()))


def _reference_from_anchor(anchor: EvidenceAnchor) -> ReportEvidenceReference:
    return ReportEvidenceReference(
        event_id=anchor.event_id,
        evidence_id=anchor.evidence_id,
        source_tool=anchor.source_tool,
        parser=anchor.source_parser,
        raw_reference=anchor.raw_reference,
        trust_level=anchor.trust_level.value,
    )


def _timestamps_for_finding(
    finding: CorrelatedFinding,
    events_by_id: Mapping[str, NormalizedEvent],
) -> tuple[str, ...]:
    timestamps = [
        events_by_id[event_id].timestamp_utc
        for event_id in finding.supporting_event_ids
        if event_id in events_by_id
    ]
    return tuple(sorted(timestamps))


def _parser_version(parsers: tuple[str, ...], parser_versions: Mapping[str, str]) -> str:
    if not parsers:
        return "unknown"
    versions = [f"{parser}:{parser_versions.get(parser, 'unknown')}" for parser in parsers]
    return ",".join(versions)


def _confidence_basis(confidence: float, modifiers: tuple[str, ...]) -> tuple[str, ...]:
    basis = [f"deterministic confidence score {confidence:.2f}"]
    basis.extend(modifiers or ("no confidence modifiers recorded",))
    return tuple(basis)


def _limitations(
    confidence_modifiers: tuple[str, ...],
    recovery_notes: tuple[str, ...],
    references: tuple[ReportEvidenceReference, ...],
) -> tuple[str, ...]:
    limitations: list[str] = []
    if any("SINGLE_SOURCE" in modifier for modifier in confidence_modifiers):
        limitations.append("finding currently has single-source support")
    if not references:
        limitations.append("no report evidence reference was attached")
    if recovery_notes:
        limitations.append("bounded recovery or correction notes are attached")
    return tuple(limitations)
