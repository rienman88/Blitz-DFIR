from __future__ import annotations

from datetime import datetime
from itertools import combinations

from blitz_dfir.core.models import NormalizedEvent, SignalWarning, TrustTier
from blitz_dfir.correlation.models import (
    ConfidenceAssessment,
    Contradiction,
    EvidenceAnchor,
    anchor_from_event,
    stable_correlation_id,
)
from blitz_dfir.correlation.timeline import correlation_subject

TRUST_WEIGHTS = {
    TrustTier.TIER_1_HIGH: 0.90,
    TrustTier.TIER_2_MEDIUM_HIGH: 0.75,
    TrustTier.TIER_3_LOW: 0.55,
    TrustTier.TIER_4_VERY_LOW: 0.35,
}

CONTRADICTION_FIELDS = (
    "sha256",
    "md5",
    "path",
    "filename",
    "commandline",
    "user",
    "dst_ip",
    "dns_query",
)
MAX_CROSS_SOURCE_TIMESTAMP_SKEW_SECONDS = 3600


def assess_confidence(
    anchors: tuple[EvidenceAnchor, ...],
    *,
    warnings: tuple[SignalWarning, ...] = (),
    contradictions: tuple[Contradiction, ...] = (),
) -> ConfidenceAssessment:
    if not anchors:
        return ConfidenceAssessment(
            score=0.0,
            source_count=0,
            agreement_score=0.0,
            modifiers=("NO_EVIDENCE",),
        )

    source_count = len({_source_key(anchor) for anchor in anchors})
    base = sum(TRUST_WEIGHTS[anchor.trust_level] for anchor in anchors) / len(anchors)
    agreement_score = min(source_count / 2, 1.0)
    modifiers: list[str] = []
    score = base

    if source_count < 2:
        score -= 0.20
        modifiers.append("SINGLE_SOURCE_PENALTY")
    else:
        score += min((source_count - 1) * 0.10, 0.20)
        modifiers.append("MULTI_SOURCE_AGREEMENT")

    warning_penalty = min(sum(warning.confidence_penalty for warning in warnings), 0.35)
    if warning_penalty:
        score -= warning_penalty
        modifiers.append("SIGNAL_WARNING_PENALTY")

    if contradictions:
        score -= min(0.15 * len(contradictions), 0.40)
        modifiers.append("CONTRADICTION_PENALTY")

    return ConfidenceAssessment(
        score=_clamp(score),
        source_count=source_count,
        agreement_score=agreement_score,
        modifiers=tuple(modifiers),
    )


def detect_contradictions(
    events: list[NormalizedEvent] | tuple[NormalizedEvent, ...],
) -> tuple[Contradiction, ...]:
    by_subject: dict[str, list[NormalizedEvent]] = {}
    for event in events:
        by_subject.setdefault(correlation_subject(event), []).append(event)

    contradictions: list[Contradiction] = []
    for subject, subject_events in sorted(by_subject.items()):
        for field in CONTRADICTION_FIELDS:
            value_events: dict[str, list[NormalizedEvent]] = {}
            for event in subject_events:
                value = event.normalized_fields.get(field)
                if value:
                    value_events.setdefault(value, []).append(event)
            if len(value_events) < 2:
                continue
            values = sorted(value_events)
            for left_value, right_value in combinations(values, 2):
                left = value_events[left_value][0]
                right = value_events[right_value][0]
                if _event_source_key(left) == _event_source_key(right):
                    continue
                contradictions.append(
                    Contradiction(
                        contradiction_id=stable_correlation_id(
                            "CONTRA",
                            subject,
                            field,
                            left_value,
                            right_value,
                            left.event_id,
                            right.event_id,
                        ),
                        subject=subject,
                        field=field,
                        left_value=left_value,
                        right_value=right_value,
                        severity="HIGH",
                        reason="cross-source disagreement for same correlation subject",
                        evidence=(anchor_from_event(left), anchor_from_event(right)),
                    )
                )
        contradictions.extend(_timestamp_contradictions(subject, subject_events))
    return tuple(contradictions)


def _source_key(anchor: EvidenceAnchor) -> tuple[str, str, str]:
    return (anchor.evidence_id, anchor.source_tool, anchor.source_parser)


def _event_source_key(event: NormalizedEvent) -> tuple[str, str, str]:
    return (event.evidence_id, event.source_tool, event.source_parser)


def _timestamp_contradictions(subject: str, events: list[NormalizedEvent]) -> list[Contradiction]:
    dated: list[tuple[datetime, NormalizedEvent]] = []
    for event in events:
        parsed = _parse_timestamp(event.timestamp_utc)
        if parsed is not None:
            dated.append((parsed, event))
    if len(dated) < 2:
        return []
    sources = {_event_source_key(event) for _, event in dated}
    if len(sources) < 2:
        return []
    dated.sort(key=lambda item: item[0])
    first_time, first_event = dated[0]
    last_time, last_event = dated[-1]
    if _event_source_key(first_event) == _event_source_key(last_event):
        return []
    span = abs(int((last_time - first_time).total_seconds()))
    if span <= MAX_CROSS_SOURCE_TIMESTAMP_SKEW_SECONDS:
        return []
    return [
        Contradiction(
            contradiction_id=stable_correlation_id(
                "CONTRA",
                subject,
                "timestamp_utc",
                first_event.timestamp_utc,
                last_event.timestamp_utc,
                first_event.event_id,
                last_event.event_id,
            ),
            subject=subject,
            field="timestamp_utc",
            left_value=first_event.timestamp_utc,
            right_value=last_event.timestamp_utc,
            severity="MEDIUM",
            reason=(
                "cross-source timestamp skew for same correlation subject exceeds "
                f"{MAX_CROSS_SOURCE_TIMESTAMP_SKEW_SECONDS} seconds"
            ),
            evidence=(anchor_from_event(first_event), anchor_from_event(last_event)),
        )
    ]


def _parse_timestamp(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _clamp(value: float) -> float:
    return min(max(value, 0.0), 1.0)
