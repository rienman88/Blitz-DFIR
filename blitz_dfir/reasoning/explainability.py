from __future__ import annotations

from blitz_dfir.correlation.models import CorrelatedFinding


def explain_findings(
    findings: tuple[CorrelatedFinding, ...],
) -> dict[str, object]:

    output = {}

    for finding in findings:

        output[finding.finding_id] = {
            "title": finding.title,
            "confidence": finding.confidence,
            "supported_by_events": finding.supporting_event_ids,
            "confidence_modifiers": finding.confidence_modifiers,
            "attack_stages": finding.attack_stages,
        }

    return output