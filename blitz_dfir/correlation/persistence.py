from __future__ import annotations

from blitz_dfir.core.models import NormalizedEvent
from blitz_dfir.correlation.confidence import assess_confidence
from blitz_dfir.correlation.models import (
    CorrelatedFinding,
    anchor_from_event,
    stable_correlation_id,
)
from blitz_dfir.correlation.timeline import order_events
from blitz_dfir.correlation.triage import assess_event_suspicion

PERSISTENCE_KEYWORDS = (
    "currentversion/run",
    "currentversion/runonce",
    "services/",
    "scheduled task",
    "schtasks",
    "startup",
    "winlogon",
)


def detect_persistence(
    events: list[NormalizedEvent] | tuple[NormalizedEvent, ...],
) -> tuple[CorrelatedFinding, ...]:
    findings: list[CorrelatedFinding] = []
    for event in order_events(events):
        persistence_type = _persistence_type(event)
        if persistence_type is None or not _has_evidence_reference(event):
            continue
        anchors = (anchor_from_event(event),)
        confidence = assess_confidence(anchors, warnings=event.warnings)
        triage_score, suspicion_reasons = assess_event_suspicion(event)
        findings.append(
            CorrelatedFinding(
                finding_id=stable_correlation_id("FIND", "persistence", event.event_id, persistence_type),
                finding_type="persistence",
                title=f"Persistence candidate: {persistence_type}",
                summary=f"{event.category} event suggests {persistence_type}",
                category=event.category,
                supporting_event_ids=(event.event_id,),
                evidence=anchors,
                confidence=confidence.score,
                confidence_modifiers=confidence.modifiers,
                triage_score=triage_score,
                suspicion_reasons=suspicion_reasons,
                warnings=event.warnings,
                attack_stages=("persistence",),
            )
        )
    return tuple(findings)


def _persistence_type(event: NormalizedEvent) -> str | None:
    if event.category == "service_install":
        return "service installation"
    if event.category in {"scheduled_task", "registry_persistence", "autorun"}:
        return event.category.replace("_", " ")
    haystack = " ".join(
        [
            event.artifact,
            event.message,
            " ".join(f"{key}={value}" for key, value in event.normalized_fields.items()),
        ]
    ).replace("\\", "/").lower()
    for keyword in PERSISTENCE_KEYWORDS:
        if keyword in haystack:
            if "task" in keyword or "schtasks" in keyword:
                return "scheduled task"
            if "run" in keyword or "startup" in keyword or "winlogon" in keyword:
                return "autorun registry/startup location"
            if "services" in keyword:
                return "service registry entry"
    return None


def _has_evidence_reference(event: NormalizedEvent) -> bool:
    reference = event.raw_reference
    return bool(
        reference.evidence_id
        and (
            reference.path
            or reference.offset is not None
            or reference.record_index is not None
            or reference.original_hash
        )
    )
