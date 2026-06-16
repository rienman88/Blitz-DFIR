from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from blitz_dfir.core.models import NormalizedEvent, SignalWarning
from blitz_dfir.correlation.confidence import TRUST_WEIGHTS
from blitz_dfir.correlation.models import Contradiction, CorrelatedFinding, EvidenceAnchor
from blitz_dfir.reporting.findings import scrub_report_text


class EvidenceSourceWeight(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    source_tool: str
    source_parser: str
    trust_tier: str
    base_weight: float = Field(ge=0.0, le=1.0)
    warning_penalty: float = Field(ge=0.0, le=1.0)
    contradiction_penalty: float = Field(ge=0.0, le=1.0)
    effective_weight: float = Field(ge=0.0, le=1.0)
    event_ids: tuple[str, ...]
    reasons: tuple[str, ...] = ()


class FindingEvidenceWeight(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    title: str
    finding_confidence: float = Field(ge=0.0, le=1.0)
    evidence_weight: float = Field(ge=0.0, le=1.0)
    weight_label: str
    source_count: int = Field(ge=0)
    confidence_modifiers: tuple[str, ...]
    sources: tuple[EvidenceSourceWeight, ...]
    explanation: str


class EvidentiaryWeightingReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "evidentiary-weighting.v1"
    generated_at_utc: str
    finding_count: int = Field(ge=0)
    average_evidence_weight: float = Field(ge=0.0, le=1.0)
    findings: tuple[FindingEvidenceWeight, ...]


def build_evidentiary_weighting_report(
    *,
    findings: tuple[CorrelatedFinding, ...],
    events: tuple[NormalizedEvent, ...],
    contradictions: tuple[Contradiction, ...] = (),
) -> EvidentiaryWeightingReport:
    events_by_id = {event.event_id: event for event in events}
    contradictions_by_event = _contradictions_by_event(contradictions)
    weighted_findings = tuple(
        _finding_weight(
            finding,
            events_by_id=events_by_id,
            contradictions_by_event=contradictions_by_event,
        )
        for finding in findings
    )
    average = (
        round(sum(item.evidence_weight for item in weighted_findings) / len(weighted_findings), 4)
        if weighted_findings
        else 0.0
    )
    return EvidentiaryWeightingReport(
        generated_at_utc=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        finding_count=len(weighted_findings),
        average_evidence_weight=average,
        findings=weighted_findings,
    )


def export_evidentiary_weighting_report(
    report: EvidentiaryWeightingReport,
    path: Path | None = None,
) -> str:
    text = json.dumps(report.model_dump(mode="json"), sort_keys=True, indent=2, ensure_ascii=True)
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
    return text


def render_evidentiary_weighting_markdown(
    report: EvidentiaryWeightingReport,
    path: Path | None = None,
    *,
    finding_limit: int = 25,
) -> str:
    lines = [
        "# Evidentiary Weighting Report",
        "",
        f"- Findings scored: `{report.finding_count}`",
        f"- Average evidence weight: `{report.average_evidence_weight:.2f}`",
        "",
        "Weights are deterministic evidence scores derived from source trust tier, parser/tool warnings, contradiction penalties, and source diversity. They explain why a finding exists; they do not replace the finding confidence score.",
        "",
    ]
    for finding in report.findings[: max(finding_limit, 0)]:
        lines.extend(
            [
                f"## `{finding.finding_id}`",
                "",
                f"- Title: {finding.title}",
                f"- Evidence weight: `{finding.evidence_weight:.2f}` ({finding.weight_label})",
                f"- Finding confidence: `{finding.finding_confidence:.2f}`",
                f"- Source count: `{finding.source_count}`",
                f"- Confidence modifiers: `{', '.join(finding.confidence_modifiers) if finding.confidence_modifiers else 'none'}`",
                f"- Explanation: {finding.explanation}",
                "",
                "| Evidence | Tool | Parser | Base | Warning Penalty | Contradiction Penalty | Effective |",
                "| --- | --- | --- | ---: | ---: | ---: | ---: |",
            ]
        )
        for source in finding.sources:
            lines.append(
                "| "
                f"`{source.evidence_id}` | `{source.source_tool}` | `{source.source_parser}` | "
                f"`{source.base_weight:.2f}` | `{source.warning_penalty:.2f}` | "
                f"`{source.contradiction_penalty:.2f}` | `{source.effective_weight:.2f}` |"
            )
        lines.append("")
    text = "\n".join(lines).rstrip() + "\n"
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return text


def _finding_weight(
    finding: CorrelatedFinding,
    *,
    events_by_id: Mapping[str, NormalizedEvent],
    contradictions_by_event: Mapping[str, tuple[Contradiction, ...]],
) -> FindingEvidenceWeight:
    grouped: dict[tuple[str, str, str], list[EvidenceAnchor]] = {}
    for anchor in finding.evidence:
        grouped.setdefault((anchor.evidence_id, anchor.source_tool, anchor.source_parser), []).append(anchor)
    sources = tuple(
        _source_weight(anchors, events_by_id=events_by_id, contradictions_by_event=contradictions_by_event)
        for _, anchors in sorted(grouped.items())
    )
    if sources:
        raw = sum(source.effective_weight for source in sources) / len(sources)
        diversity_bonus = min((len(sources) - 1) * 0.05, 0.10)
        evidence_weight = _clamp(raw + diversity_bonus)
    else:
        evidence_weight = 0.0
    label = _weight_label(evidence_weight)
    explanation = (
        f"{label} evidentiary support from {len(sources)} source(s); "
        f"finding confidence remains {finding.confidence:.2f} after correlation modifiers."
    )
    return FindingEvidenceWeight(
        finding_id=finding.finding_id,
        title=scrub_report_text(finding.title),
        finding_confidence=finding.confidence,
        evidence_weight=round(evidence_weight, 4),
        weight_label=label,
        source_count=len(sources),
        confidence_modifiers=tuple(scrub_report_text(modifier) for modifier in finding.confidence_modifiers),
        sources=sources,
        explanation=scrub_report_text(explanation),
    )


def _source_weight(
    anchors: list[EvidenceAnchor],
    *,
    events_by_id: Mapping[str, NormalizedEvent],
    contradictions_by_event: Mapping[str, tuple[Contradiction, ...]],
) -> EvidenceSourceWeight:
    first = anchors[0]
    event_ids = tuple(sorted({anchor.event_id for anchor in anchors}))
    warnings: list[SignalWarning] = []
    contradiction_ids: set[str] = set()
    for event_id in event_ids:
        event = events_by_id.get(event_id)
        if event is not None:
            warnings.extend(event.warnings)
        contradiction_ids.update(item.contradiction_id for item in contradictions_by_event.get(event_id, ()))
    base = TRUST_WEIGHTS[first.trust_level]
    warning_penalty = min(sum(warning.confidence_penalty for warning in warnings), 0.35)
    contradiction_penalty = min(0.15 * len(contradiction_ids), 0.40)
    effective = _clamp(base - warning_penalty - contradiction_penalty)
    reasons = [f"trust_tier={first.trust_level.value}"]
    if warning_penalty:
        reasons.append("parser_or_signal_warning_penalty")
    if contradiction_penalty:
        reasons.append("contradiction_penalty")
    return EvidenceSourceWeight(
        evidence_id=first.evidence_id,
        source_tool=first.source_tool,
        source_parser=first.source_parser,
        trust_tier=first.trust_level.value,
        base_weight=round(base, 4),
        warning_penalty=round(warning_penalty, 4),
        contradiction_penalty=round(contradiction_penalty, 4),
        effective_weight=round(effective, 4),
        event_ids=event_ids,
        reasons=tuple(reasons),
    )


def _contradictions_by_event(contradictions: Iterable[Contradiction]) -> dict[str, tuple[Contradiction, ...]]:
    output: dict[str, list[Contradiction]] = {}
    for contradiction in contradictions:
        for anchor in contradiction.evidence:
            output.setdefault(anchor.event_id, []).append(contradiction)
    return {event_id: tuple(items) for event_id, items in output.items()}


def _weight_label(value: float) -> str:
    if value >= 0.80:
        return "High"
    if value >= 0.55:
        return "Medium"
    if value > 0.0:
        return "Low"
    return "No Evidence"


def _clamp(value: float) -> float:
    return min(max(value, 0.0), 1.0)
