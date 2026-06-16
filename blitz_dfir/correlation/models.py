from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from blitz_dfir.core.integrity import hash_text
from blitz_dfir.core.models import NormalizedEvent, RawReference, SignalWarning, TrustTier

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class EvidenceAnchor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    evidence_id: str
    source_tool: str
    source_parser: str
    raw_reference: RawReference
    trust_level: TrustTier


class CorrelatedEventGroup(BaseModel):
    model_config = ConfigDict(extra="forbid")

    group_id: str
    subject: str
    category: str
    start_timestamp_utc: str
    end_timestamp_utc: str
    event_ids: tuple[str, ...]
    evidence: tuple[EvidenceAnchor, ...]


class ProcessLineageLink(BaseModel):
    model_config = ConfigDict(extra="forbid")

    link_id: str
    child_process_id: str
    parent_process_id: str
    child_event_id: str
    parent_event_id: str | None = None
    evidence: tuple[EvidenceAnchor, ...]


class ConfidenceAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    score: float = Field(ge=0.0, le=1.0)
    source_count: int = Field(ge=0)
    agreement_score: float = Field(ge=0.0, le=1.0)
    modifiers: tuple[str, ...] = ()


class Contradiction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contradiction_id: str
    subject: str
    field: str
    left_value: str
    right_value: str
    severity: Severity
    reason: str
    evidence: tuple[EvidenceAnchor, ...]


class CorrelatedFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    finding_type: str
    title: str
    summary: str
    category: str
    supporting_event_ids: tuple[str, ...]
    evidence: tuple[EvidenceAnchor, ...]
    confidence: float = Field(ge=0.0, le=1.0)
    confidence_modifiers: tuple[str, ...] = ()
    triage_score: float = Field(default=0.0, ge=0.0, le=1.0)
    suspicion_reasons: tuple[str, ...] = ()
    warnings: tuple[SignalWarning, ...] = ()
    attack_stages: tuple[str, ...] = ()


class AttackStage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    stage_id: str
    stage: str
    reason: str
    supporting_event_ids: tuple[str, ...]
    evidence: tuple[EvidenceAnchor, ...]
    confidence: float = Field(ge=0.0, le=1.0)


def anchor_from_event(event: NormalizedEvent) -> EvidenceAnchor:
    return EvidenceAnchor(
        event_id=event.event_id,
        evidence_id=event.evidence_id,
        source_tool=event.source_tool,
        source_parser=event.source_parser,
        raw_reference=event.raw_reference,
        trust_level=event.trust_level,
    )


def stable_correlation_id(prefix: str, *parts: str) -> str:
    digest = hash_text("|".join(str(part).lower() for part in parts))[:12].upper()
    return f"{prefix}-{digest}"
