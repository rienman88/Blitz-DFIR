from __future__ import annotations

from blitz_dfir.core.models import NormalizedEvent
from blitz_dfir.correlation.models import ProcessLineageLink, anchor_from_event, stable_correlation_id
from blitz_dfir.correlation.timeline import order_events


def build_process_lineage(
    events: list[NormalizedEvent] | tuple[NormalizedEvent, ...],
) -> tuple[ProcessLineageLink, ...]:
    ordered = order_events(events)
    process_events = [event for event in ordered if _process_id(event)]
    by_pid: dict[str, list[NormalizedEvent]] = {}
    for event in process_events:
        by_pid.setdefault(_process_id(event), []).append(event)

    links: list[ProcessLineageLink] = []
    for child in process_events:
        child_pid = _process_id(child)
        parent_pid = _parent_process_id(child)
        if not child_pid or not parent_pid:
            continue
        parent = _latest_parent_before_child(by_pid.get(parent_pid, ()), child)
        evidence = [anchor_from_event(child)]
        parent_event_id = None
        if parent is not None:
            parent_event_id = parent.event_id
            evidence.append(anchor_from_event(parent))
        links.append(
            ProcessLineageLink(
                link_id=stable_correlation_id(
                    "LIN",
                    child.event_id,
                    parent_event_id or parent_pid,
                    child_pid,
                    parent_pid,
                ),
                child_process_id=child_pid,
                parent_process_id=parent_pid,
                child_event_id=child.event_id,
                parent_event_id=parent_event_id,
                evidence=tuple(evidence),
            )
        )
    return tuple(sorted(links, key=lambda link: (link.child_event_id, link.link_id)))


def _process_id(event: NormalizedEvent) -> str:
    for key in ("newprocessid", "processid", "pid"):
        value = event.normalized_fields.get(key)
        if value:
            return _clean_pid(value)
    return ""


def _parent_process_id(event: NormalizedEvent) -> str:
    for key in ("parentprocessid", "creatorprocessid", "ppid", "parent_pid"):
        value = event.normalized_fields.get(key)
        if value:
            return _clean_pid(value)
    return ""


def _latest_parent_before_child(
    candidates: list[NormalizedEvent] | tuple[NormalizedEvent, ...],
    child: NormalizedEvent,
) -> NormalizedEvent | None:
    possible = [
        event
        for event in candidates
        if event.timestamp_utc <= child.timestamp_utc and event.event_id != child.event_id
    ]
    if not possible:
        return None
    return sorted(possible, key=lambda event: (event.timestamp_utc, event.event_id))[-1]


def _clean_pid(value: str) -> str:
    return str(value).strip().lower()
