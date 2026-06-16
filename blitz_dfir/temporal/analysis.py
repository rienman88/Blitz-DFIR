from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from blitz_dfir.core.integrity import hash_text
from blitz_dfir.core.models import NormalizedEvent
from blitz_dfir.correlation.models import AttackStage, CorrelatedFinding
from blitz_dfir.reporting.findings import scrub_report_text

DEFAULT_GAP_THRESHOLD_SECONDS = 3600
MAX_GAPS = 100


class TemporalGap(BaseModel):
    model_config = ConfigDict(extra="forbid")

    gap_id: str
    start_timestamp_utc: str
    end_timestamp_utc: str
    duration_seconds: int = Field(ge=0)
    preceding_event_id: str
    following_event_id: str
    preceding_evidence_id: str
    following_evidence_id: str


class TemporalGapAnalysisReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "temporal-gap-analysis.v1"
    event_count: int = Field(ge=0)
    valid_timestamp_count: int = Field(ge=0)
    invalid_or_placeholder_timestamp_count: int = Field(ge=0)
    first_seen_utc: str | None = None
    last_seen_utc: str | None = None
    largest_gap_seconds: int = Field(default=0, ge=0)
    gap_threshold_seconds: int = Field(default=DEFAULT_GAP_THRESHOLD_SECONDS, ge=1)
    gaps: tuple[TemporalGap, ...] = ()
    event_counts_by_evidence: dict[str, int] = Field(default_factory=dict)
    event_counts_by_category: dict[str, int] = Field(default_factory=dict)
    timestamp_quality: Literal["none", "partial", "complete"] = "none"
    interpretation: str


class AttackStageTimelineEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    stage: str
    stage_id: str
    first_seen_utc: str | None = None
    last_seen_utc: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    finding_ids: tuple[str, ...] = ()
    event_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    timestamp_quality: Literal["no_valid_timestamp", "partial", "complete"] = "no_valid_timestamp"
    interpretation: str


class AttackStageTimelineReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "attack-stage-timeline.v1"
    stage_count: int = Field(ge=0)
    finding_count: int = Field(ge=0)
    event_count: int = Field(ge=0)
    stages: tuple[AttackStageTimelineEntry, ...] = ()
    ordering_basis: str = "first_valid_stage_timestamp_then_stage_name"
    limitation: str


def build_temporal_gap_analysis(
    events: tuple[NormalizedEvent, ...],
    *,
    gap_threshold_seconds: int = DEFAULT_GAP_THRESHOLD_SECONDS,
) -> TemporalGapAnalysisReport:
    threshold = max(int(gap_threshold_seconds), 1)
    event_counts_by_evidence = Counter(event.evidence_id for event in events)
    event_counts_by_category = Counter(scrub_report_text(event.category) for event in events)
    timed_events = sorted(
        (
            (parsed, event)
            for event in events
            if (parsed := _parse_valid_timestamp(event.timestamp_utc)) is not None
        ),
        key=lambda item: (item[0], item[1].event_id),
    )
    valid_count = len(timed_events)
    invalid_count = max(len(events) - valid_count, 0)
    gaps: list[TemporalGap] = []
    largest_gap_seconds = 0
    for (left_time, left_event), (right_time, right_event) in zip(timed_events, timed_events[1:], strict=False):
        delta = int((right_time - left_time).total_seconds())
        largest_gap_seconds = max(largest_gap_seconds, delta)
        if delta < threshold:
            continue
        gaps.append(
            TemporalGap(
                gap_id=_stable_gap_id(left_event.event_id, right_event.event_id, str(delta)),
                start_timestamp_utc=_format_timestamp(left_time),
                end_timestamp_utc=_format_timestamp(right_time),
                duration_seconds=delta,
                preceding_event_id=left_event.event_id,
                following_event_id=right_event.event_id,
                preceding_evidence_id=left_event.evidence_id,
                following_evidence_id=right_event.evidence_id,
            )
        )
    first_seen = _format_timestamp(timed_events[0][0]) if timed_events else None
    last_seen = _format_timestamp(timed_events[-1][0]) if timed_events else None
    timestamp_quality = _timestamp_quality(valid_count=valid_count, total=len(events))
    return TemporalGapAnalysisReport(
        event_count=len(events),
        valid_timestamp_count=valid_count,
        invalid_or_placeholder_timestamp_count=invalid_count,
        first_seen_utc=first_seen,
        last_seen_utc=last_seen,
        largest_gap_seconds=largest_gap_seconds,
        gap_threshold_seconds=threshold,
        gaps=tuple(gaps[:MAX_GAPS]),
        event_counts_by_evidence=dict(sorted(event_counts_by_evidence.items())),
        event_counts_by_category=dict(sorted(event_counts_by_category.items())),
        timestamp_quality=timestamp_quality,
        interpretation=_gap_interpretation(
            event_count=len(events),
            valid_count=valid_count,
            invalid_count=invalid_count,
            gap_count=len(gaps),
            threshold=threshold,
        ),
    )


def build_attack_stage_timeline(
    *,
    events: tuple[NormalizedEvent, ...],
    findings: tuple[CorrelatedFinding, ...],
    stages: tuple[AttackStage, ...],
) -> AttackStageTimelineReport:
    events_by_id = {event.event_id: event for event in events}
    stage_event_ids: dict[str, set[str]] = defaultdict(set)
    stage_finding_ids: dict[str, set[str]] = defaultdict(set)
    stage_confidences: dict[str, list[float]] = defaultdict(list)

    for stage in stages:
        stage_name = scrub_report_text(stage.stage)
        stage_event_ids[stage_name].update(stage.supporting_event_ids)
        stage_confidences[stage_name].append(stage.confidence)

    for finding in findings:
        for stage_name_raw in finding.attack_stages:
            stage_name = scrub_report_text(stage_name_raw)
            stage_finding_ids[stage_name].add(finding.finding_id)
            stage_event_ids[stage_name].update(finding.supporting_event_ids)
            stage_confidences[stage_name].append(finding.confidence)

    entries: list[AttackStageTimelineEntry] = []
    for stage_name in sorted(set(stage_event_ids) | set(stage_finding_ids)):
        event_ids = tuple(sorted(stage_event_ids[stage_name]))
        stage_events = tuple(events_by_id[event_id] for event_id in event_ids if event_id in events_by_id)
        timed_events = sorted(
            (
                (parsed, event)
                for event in stage_events
                if (parsed := _parse_valid_timestamp(event.timestamp_utc)) is not None
            ),
            key=lambda item: (item[0], item[1].event_id),
        )
        valid_count = len(timed_events)
        quality = _stage_timestamp_quality(valid_count=valid_count, total=len(stage_events))
        confidence_values = stage_confidences.get(stage_name) or [0.35]
        confidence = max(min(sum(confidence_values) / len(confidence_values), 1.0), 0.0)
        entries.append(
            AttackStageTimelineEntry(
                stage=stage_name,
                stage_id=_stable_stage_id(stage_name, event_ids, tuple(sorted(stage_finding_ids[stage_name]))),
                first_seen_utc=_format_timestamp(timed_events[0][0]) if timed_events else None,
                last_seen_utc=_format_timestamp(timed_events[-1][0]) if timed_events else None,
                confidence=confidence,
                finding_ids=tuple(sorted(stage_finding_ids[stage_name])),
                event_ids=event_ids,
                evidence_ids=tuple(sorted({event.evidence_id for event in stage_events})),
                categories=tuple(sorted({scrub_report_text(event.category) for event in stage_events})),
                timestamp_quality=quality,
                interpretation=_stage_interpretation(
                    stage=stage_name,
                    finding_count=len(stage_finding_ids[stage_name]),
                    event_count=len(stage_events),
                    valid_timestamp_count=valid_count,
                ),
            )
        )

    entries.sort(key=lambda item: (item.first_seen_utc is None, item.first_seen_utc or "", item.stage))
    return AttackStageTimelineReport(
        stage_count=len(entries),
        finding_count=len(findings),
        event_count=len(events),
        stages=tuple(entries),
        limitation=(
            "This timeline orders deterministic attack-stage evidence only. It is not a campaign reconstruction "
            "and does not claim actor intent, victimology, or full intrusion scope without additional corroboration."
        ),
    )


def export_temporal_gap_analysis(report: TemporalGapAnalysisReport, path: Path) -> None:
    _write_json(path, report.model_dump(mode="json"))


def export_attack_stage_timeline(report: AttackStageTimelineReport, path: Path) -> None:
    _write_json(path, report.model_dump(mode="json"))


def render_temporal_gap_markdown(report: TemporalGapAnalysisReport, path: Path | None = None) -> str:
    lines = [
        "# Temporal Gap Analysis",
        "",
        f"- Events evaluated: `{report.event_count}`",
        f"- Valid timestamps: `{report.valid_timestamp_count}`",
        f"- Invalid or placeholder timestamps: `{report.invalid_or_placeholder_timestamp_count}`",
        f"- First seen UTC: `{report.first_seen_utc or 'none'}`",
        f"- Last seen UTC: `{report.last_seen_utc or 'none'}`",
        f"- Largest gap seconds: `{report.largest_gap_seconds}`",
        f"- Gap threshold seconds: `{report.gap_threshold_seconds}`",
        f"- Timestamp quality: `{report.timestamp_quality}`",
        "",
        report.interpretation,
        "",
        "## Gaps",
        "",
    ]
    if report.gaps:
        for gap in report.gaps:
            lines.append(
                f"- `{gap.duration_seconds}` seconds from `{gap.start_timestamp_utc}` "
                f"to `{gap.end_timestamp_utc}` between `{gap.preceding_event_id}` and `{gap.following_event_id}`"
            )
    else:
        lines.append("No gap crossed the configured threshold in the normalized event timeline.")
    text = "\n".join(lines).rstrip() + "\n"
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return text


def render_attack_stage_timeline_markdown(report: AttackStageTimelineReport, path: Path | None = None) -> str:
    lines = [
        "# Attack-Stage Timeline",
        "",
        f"- Stages: `{report.stage_count}`",
        f"- Findings evaluated: `{report.finding_count}`",
        f"- Events evaluated: `{report.event_count}`",
        f"- Ordering basis: `{report.ordering_basis}`",
        "",
        report.limitation,
        "",
        "## Stages",
        "",
    ]
    if report.stages:
        for stage in report.stages:
            lines.extend(
                [
                    f"### {stage.stage}",
                    "",
                    f"- First seen UTC: `{stage.first_seen_utc or 'none'}`",
                    f"- Last seen UTC: `{stage.last_seen_utc or 'none'}`",
                    f"- Confidence: `{stage.confidence:.2f}`",
                    f"- Timestamp quality: `{stage.timestamp_quality}`",
                    f"- Findings: `{', '.join(stage.finding_ids) or 'none'}`",
                    f"- Events: `{len(stage.event_ids)}`",
                    f"- Evidence: `{', '.join(stage.evidence_ids) or 'none'}`",
                    "",
                    stage.interpretation,
                    "",
                ]
            )
    else:
        lines.append("No deterministic attack stage was inferred from the current evidence set.")
    text = "\n".join(lines).rstrip() + "\n"
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return text


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def _parse_valid_timestamp(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text or text.startswith("1970-01-01"):
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _timestamp_quality(*, valid_count: int, total: int) -> Literal["none", "partial", "complete"]:
    if total == 0 or valid_count == 0:
        return "none"
    if valid_count == total:
        return "complete"
    return "partial"


def _stage_timestamp_quality(*, valid_count: int, total: int) -> Literal["no_valid_timestamp", "partial", "complete"]:
    if total == 0 or valid_count == 0:
        return "no_valid_timestamp"
    if valid_count == total:
        return "complete"
    return "partial"


def _stable_gap_id(left_event_id: str, right_event_id: str, duration: str) -> str:
    return f"GAP-{hash_text('|'.join((left_event_id, right_event_id, duration)))[:12].upper()}"


def _stable_stage_id(stage: str, event_ids: tuple[str, ...], finding_ids: tuple[str, ...]) -> str:
    parts = (stage, *event_ids, *finding_ids)
    return f"ASTAGE-{hash_text('|'.join(parts))[:12].upper()}"


def _gap_interpretation(
    *,
    event_count: int,
    valid_count: int,
    invalid_count: int,
    gap_count: int,
    threshold: int,
) -> str:
    if event_count == 0:
        return "No normalized events were available, so temporal coverage cannot be assessed."
    if valid_count == 0:
        return (
            "No valid event timestamps were available. This usually means the source produces state records "
            "or placeholder timestamps, so the absence of gaps is not meaningful."
        )
    if invalid_count:
        return (
            f"{invalid_count} event(s) had invalid or placeholder timestamps. Review those records before "
            f"using the {gap_count} detected gap(s) as investigative boundaries."
        )
    if gap_count:
        return f"{gap_count} gap(s) crossed the configured {threshold}-second threshold and need analyst review."
    return "No temporal gap crossed the configured threshold across valid normalized event timestamps."


def _stage_interpretation(
    *,
    stage: str,
    finding_count: int,
    event_count: int,
    valid_timestamp_count: int,
) -> str:
    if finding_count == 0 and event_count:
        return f"The `{stage}` stage is inferred from deterministic event categories, but no finding currently anchors it."
    if event_count == 0:
        return f"The `{stage}` stage is present from finding metadata only; no normalized event timestamp anchors it."
    if valid_timestamp_count == 0:
        return f"The `{stage}` stage has supporting events, but their timestamps are invalid or placeholders."
    return f"The `{stage}` stage is anchored by {event_count} event(s) and {finding_count} finding(s)."

