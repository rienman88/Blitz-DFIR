from __future__ import annotations

from collections import defaultdict

from blitz_dfir.core.models import NormalizedEvent
from blitz_dfir.correlation.models import (
    CorrelatedEventGroup,
    anchor_from_event,
    stable_correlation_id,
)


def order_events(events: list[NormalizedEvent] | tuple[NormalizedEvent, ...]) -> tuple[NormalizedEvent, ...]:
    return tuple(sorted(events, key=lambda event: (event.timestamp_utc, event.event_id)))


def stitch_events(events: list[NormalizedEvent] | tuple[NormalizedEvent, ...]) -> tuple[CorrelatedEventGroup, ...]:
    grouped: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
    for event in order_events(events):
        grouped[(correlation_subject(event), event.category)].append(event)

    stitched: list[CorrelatedEventGroup] = []
    for (subject, category), group_events in sorted(grouped.items(), key=lambda item: item[0]):
        ordered = order_events(group_events)
        event_ids = tuple(event.event_id for event in ordered)
        stitched.append(
            CorrelatedEventGroup(
                group_id=stable_correlation_id("GRP", subject, category, *event_ids),
                subject=subject,
                category=category,
                start_timestamp_utc=ordered[0].timestamp_utc,
                end_timestamp_utc=ordered[-1].timestamp_utc,
                event_ids=event_ids,
                evidence=tuple(anchor_from_event(event) for event in ordered),
            )
        )
    return tuple(stitched)


def correlation_subject(event: NormalizedEvent) -> str:
    fields = event.normalized_fields
    if event.category.startswith("network_"):
        src = fields.get("src_ip", "?")
        dst = fields.get("dst_ip", "?")
        dst_port = fields.get("dst_port", "")
        protocol = fields.get("protocol", "")
        return _clean_subject(f"{src}->{dst}:{dst_port}/{protocol}")

    for key in (
        "process_guid",
        "processguid",
        "newprocessid",
        "processid",
        "pid",
        "sha256",
        "md5",
        "filename",
        "image",
        "path",
    ):
        value = fields.get(key)
        if value:
            return _clean_subject(value)

    return _clean_subject(event.artifact or event.evidence_id)


def _clean_subject(value: str) -> str:
    return " ".join(str(value).strip().lower().split()) or "unknown"
