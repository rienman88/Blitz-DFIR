from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from blitz_dfir.correlation.models import Contradiction, CorrelatedFinding
from blitz_dfir.reporting.findings import scrub_report_text


class FindingContradictionImpact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    confidence_before: float = Field(ge=0.0, le=1.0)
    confidence_after: float = Field(ge=0.0, le=1.0)
    contradiction_score: float = Field(ge=0.0, le=1.0)
    contradiction_ids: tuple[str, ...]
    impacted_event_ids: tuple[str, ...]


class EvidenceContradictionAnalysisReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "evidence-contradiction-analysis.v1"
    generated_at_utc: str
    contradiction_count: int = Field(ge=0)
    contradiction_score: float = Field(ge=0.0, le=1.0)
    severity_counts: dict[str, int]
    contradictions: tuple[dict[str, object], ...]
    finding_impacts: tuple[FindingContradictionImpact, ...]


def apply_contradiction_penalties(
    findings: tuple[CorrelatedFinding, ...],
    contradictions: tuple[Contradiction, ...],
) -> tuple[CorrelatedFinding, ...]:
    if not contradictions:
        return findings
    contradictions_by_finding = _contradictions_by_finding(findings, contradictions)
    adjusted: list[CorrelatedFinding] = []
    for finding in findings:
        related = contradictions_by_finding.get(finding.finding_id, ())
        if not related:
            adjusted.append(finding)
            continue
        penalty = _finding_contradiction_score(related)
        modifiers = list(finding.confidence_modifiers)
        if "CONTRADICTION_PENALTY" not in modifiers:
            modifiers.append("CONTRADICTION_PENALTY")
        adjusted.append(
            finding.model_copy(
                update={
                    "confidence": round(max(finding.confidence - penalty, 0.0), 4),
                    "confidence_modifiers": tuple(modifiers),
                }
            )
        )
    return tuple(adjusted)


def build_contradiction_analysis_report(
    *,
    findings_before: tuple[CorrelatedFinding, ...],
    findings_after: tuple[CorrelatedFinding, ...],
    contradictions: tuple[Contradiction, ...],
) -> EvidenceContradictionAnalysisReport:
    before_by_id = {finding.finding_id: finding for finding in findings_before}
    after_by_id = {finding.finding_id: finding for finding in findings_after}
    contradictions_by_finding = _contradictions_by_finding(findings_before, contradictions)
    impacts: list[FindingContradictionImpact] = []
    for finding_id, related in sorted(contradictions_by_finding.items()):
        before = before_by_id.get(finding_id)
        after = after_by_id.get(finding_id)
        if before is None or after is None:
            continue
        impacted_event_ids = sorted(
            {
                anchor.event_id
                for contradiction in related
                for anchor in contradiction.evidence
                if anchor.event_id in set(before.supporting_event_ids)
            }
        )
        impacts.append(
            FindingContradictionImpact(
                finding_id=finding_id,
                confidence_before=before.confidence,
                confidence_after=after.confidence,
                contradiction_score=_finding_contradiction_score(related),
                contradiction_ids=tuple(item.contradiction_id for item in related),
                impacted_event_ids=tuple(impacted_event_ids),
            )
        )
    severity_counts = dict(Counter(contradiction.severity for contradiction in contradictions))
    return EvidenceContradictionAnalysisReport(
        generated_at_utc=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        contradiction_count=len(contradictions),
        contradiction_score=_case_contradiction_score(contradictions),
        severity_counts=severity_counts,
        contradictions=tuple(_contradiction_payload(item) for item in contradictions),
        finding_impacts=tuple(impacts),
    )


def export_contradiction_analysis_report(
    report: EvidenceContradictionAnalysisReport,
    path: Path | None = None,
) -> str:
    text = json.dumps(report.model_dump(mode="json"), sort_keys=True, indent=2, ensure_ascii=True)
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
    return text


def render_contradiction_analysis_markdown(
    report: EvidenceContradictionAnalysisReport,
    path: Path | None = None,
) -> str:
    lines = [
        "# Evidence Contradiction Analysis",
        "",
        f"- Contradictions: `{report.contradiction_count}`",
        f"- Case contradiction score: `{report.contradiction_score:.2f}`",
        f"- Severity counts: `{json.dumps(report.severity_counts, sort_keys=True)}`",
        "",
    ]
    if report.finding_impacts:
        lines.extend(
            [
                "## Finding Confidence Impact",
                "",
                "| Finding | Before | After | Score | Contradictions |",
                "| --- | ---: | ---: | ---: | ---: |",
            ]
        )
        for impact in report.finding_impacts:
            lines.append(
                f"| `{impact.finding_id}` | `{impact.confidence_before:.2f}` | "
                f"`{impact.confidence_after:.2f}` | `{impact.contradiction_score:.2f}` | "
                f"`{len(impact.contradiction_ids)}` |"
            )
        lines.append("")
    if report.contradictions:
        lines.extend(["## Contradictions", ""])
        for item in report.contradictions[:25]:
            lines.append(
                "- "
                f"`{item['contradiction_id']}` subject `{item['subject']}` field `{item['field']}` "
                f"severity `{item['severity']}`: {item['reason']}"
            )
        lines.append("")
    text = "\n".join(lines).rstrip() + "\n"
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return text


def _contradictions_by_finding(
    findings: tuple[CorrelatedFinding, ...],
    contradictions: tuple[Contradiction, ...],
) -> dict[str, tuple[Contradiction, ...]]:
    output: dict[str, list[Contradiction]] = {}
    for finding in findings:
        event_ids = set(finding.supporting_event_ids)
        for contradiction in contradictions:
            contradiction_event_ids = {anchor.event_id for anchor in contradiction.evidence}
            if event_ids.intersection(contradiction_event_ids):
                output.setdefault(finding.finding_id, []).append(contradiction)
    return {finding_id: tuple(items) for finding_id, items in output.items()}


def _finding_contradiction_score(contradictions: tuple[Contradiction, ...]) -> float:
    severity_weight = {"LOW": 0.05, "MEDIUM": 0.10, "HIGH": 0.15, "CRITICAL": 0.25}
    return round(min(sum(severity_weight[item.severity] for item in contradictions), 0.40), 4)


def _case_contradiction_score(contradictions: tuple[Contradiction, ...]) -> float:
    if not contradictions:
        return 0.0
    severity_weight = {"LOW": 0.03, "MEDIUM": 0.06, "HIGH": 0.10, "CRITICAL": 0.18}
    return round(min(sum(severity_weight[item.severity] for item in contradictions), 1.0), 4)


def _contradiction_payload(contradiction: Contradiction) -> dict[str, object]:
    return {
        "contradiction_id": contradiction.contradiction_id,
        "subject": scrub_report_text(contradiction.subject),
        "field": scrub_report_text(contradiction.field),
        "left_value": scrub_report_text(contradiction.left_value),
        "right_value": scrub_report_text(contradiction.right_value),
        "severity": contradiction.severity,
        "reason": scrub_report_text(contradiction.reason),
        "event_ids": tuple(anchor.event_id for anchor in contradiction.evidence),
        "evidence_ids": tuple(sorted({anchor.evidence_id for anchor in contradiction.evidence})),
    }
