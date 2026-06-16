from __future__ import annotations

from typing import Any, Literal

from blitz_dfir.core.models import EvidenceCategory
from blitz_dfir.reasoning.models import Hypothesis

HypothesisStatus = Literal["supported", "unsupported", "needs_validation"]


def hypotheses_from_payload(
    value: object,
    *,
    known_event_ids: set[str],
) -> tuple[Hypothesis, ...]:
    if not isinstance(value, list):
        return ()
    hypotheses: list[Hypothesis] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        event_ids = _valid_event_ids(item.get("evidence_event_ids"), known_event_ids)
        confidence = _confidence(item.get("confidence"))
        status = _status(item.get("status"), event_ids, confidence)
        hypotheses.append(
            Hypothesis(
                hypothesis=_bounded(item.get("hypothesis", "")),
                status=status,
                evidence_event_ids=event_ids,
                rationale=_bounded(item.get("rationale", "")),
                confidence=confidence if status != "unsupported" else min(confidence, 0.20),
                evidence_type=EvidenceCategory.INFERRED,
            )
        )
    return tuple(hypothesis for hypothesis in hypotheses if hypothesis.hypothesis)


def _valid_event_ids(value: Any, known_event_ids: set[str]) -> tuple[str, ...]:
    if not isinstance(value, list | tuple):
        return ()
    return tuple(str(event_id) for event_id in value if str(event_id) in known_event_ids)


def _status(value: object, event_ids: tuple[str, ...], confidence: float) -> HypothesisStatus:
    if not event_ids:
        return "unsupported"
    text = str(value or "").lower()
    if text == "supported":
        return "supported"
    if text == "needs_validation":
        return "needs_validation"
    if text == "unsupported":
        return "unsupported"
    return "supported" if confidence >= 0.65 else "needs_validation"


def _confidence(value: object) -> float:
    try:
        return min(max(float(str(value)), 0.0), 1.0)
    except (TypeError, ValueError):
        return 0.35


def _bounded(value: object, limit: int = 240) -> str:
    text = "" if value is None else str(value)
    return " ".join(text.split())[:limit]
