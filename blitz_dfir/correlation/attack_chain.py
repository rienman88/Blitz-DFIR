from __future__ import annotations

from blitz_dfir.core.models import NormalizedEvent
from blitz_dfir.correlation.confidence import assess_confidence
from blitz_dfir.correlation.models import AttackStage, CorrelatedFinding, anchor_from_event, stable_correlation_id
from blitz_dfir.correlation.timeline import order_events


def infer_attack_stages(
    events: list[NormalizedEvent] | tuple[NormalizedEvent, ...],
    *,
    findings: tuple[CorrelatedFinding, ...] = (),
) -> tuple[AttackStage, ...]:
    stage_events: dict[str, list[NormalizedEvent]] = {}
    for event in order_events(events):
        stage = _stage_for_event(event)
        if stage:
            stage_events.setdefault(stage, []).append(event)

    for finding in findings:
        for stage in finding.attack_stages:
            stage_events.setdefault(stage, [])

    stages: list[AttackStage] = []
    for stage, supporting_events in sorted(stage_events.items()):
        anchors = tuple(anchor_from_event(event) for event in supporting_events)
        confidence = assess_confidence(anchors) if anchors else None
        stages.append(
            AttackStage(
                stage_id=stable_correlation_id(
                    "STAGE",
                    stage,
                    *(event.event_id for event in supporting_events),
                ),
                stage=stage,
                reason=_reason_for_stage(stage),
                supporting_event_ids=tuple(event.event_id for event in supporting_events),
                evidence=anchors,
                confidence=confidence.score if confidence else 0.35,
            )
        )
    return tuple(stages)


def _stage_for_event(event: NormalizedEvent) -> str | None:
    if event.category in {"network_dns", "network_http", "network_tls", "network_flow"}:
        return "command_and_control_or_discovery"
    if event.category in {
        "process_execution",
        "yara_match",
        "string_artifact",
        "memory_process",
        "memory_process_tree",
        "memory_process_scan",
    }:
        return "execution"
    if event.category == "memory_injection_candidate":
        return "defense_evasion_or_injection"
    if event.category in {"service_install", "scheduled_task", "registry_persistence", "autorun"}:
        return "persistence"
    if event.category in {"privileged_logon", "explicit_credential_logon"}:
        return "privilege_or_credential_use"
    if event.category in {"authentication_logon", "authentication_failure"}:
        return "initial_access_or_lateral_movement"
    return None


def _reason_for_stage(stage: str) -> str:
    reasons = {
        "command_and_control_or_discovery": "network activity appears in normalized triage records",
        "execution": "execution-oriented artifacts are present",
        "persistence": "persistence-oriented artifacts are present",
        "privilege_or_credential_use": "credential or privileged logon artifacts are present",
        "initial_access_or_lateral_movement": "authentication artifacts are present",
        "defense_evasion_or_injection": "memory analysis identified injected or suspicious memory-region artifacts",
    }
    return reasons.get(stage, "stage inferred from deterministic event category mapping")
