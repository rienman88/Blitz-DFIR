from __future__ import annotations

from blitz_dfir.core.integrity import hash_text
from blitz_dfir.correction.models import (
    APPROVED_TRIGGER_REASONS,
    CorrectionTrigger,
    ValidationIssue,
    ValidationReport,
)

ISSUE_TO_TRIGGER_REASON = {
    "MISSING_EVIDENCE": "MISSING_EVIDENCE_OR_BROKEN_LINEAGE",
    "BROKEN_LINEAGE": "MISSING_EVIDENCE_OR_BROKEN_LINEAGE",
    "LOW_CONFIDENCE": "LOW_CONFIDENCE",
    "PARSER_DEGRADATION_OR_SIGNAL_LOSS": "PARSER_DEGRADATION_OR_SIGNAL_LOSS",
    "TIMELINE_GAP_OR_CONTRADICTION": "TIMELINE_GAP_OR_CONTRADICTION",
    "CONTRADICTION_LIMIT_EXCEEDED": "CONTRADICTION_LIMIT_EXCEEDED",
    "TOOL_INTEGRITY_MISMATCH": "TOOL_INTEGRITY_MISMATCH",
}


def triggers_from_validation(report: ValidationReport) -> tuple[CorrectionTrigger, ...]:
    triggers: list[CorrectionTrigger] = []
    seen: set[tuple[str, str]] = set()
    for issue in report.issues:
        trigger = trigger_from_issue(issue)
        if trigger is None:
            continue
        key = (trigger.reason, trigger.source_issue_id)
        if key in seen:
            continue
        triggers.append(trigger)
        seen.add(key)
    return tuple(triggers)


def trigger_from_issue(issue: ValidationIssue) -> CorrectionTrigger | None:
    reason = ISSUE_TO_TRIGGER_REASON.get(issue.issue_type)
    if reason not in APPROVED_TRIGGER_REASONS:
        return None
    trigger_id = f"TRIG-{hash_text('|'.join([reason, issue.issue_id]))[:12].upper()}"
    return CorrectionTrigger(
        trigger_id=trigger_id,
        reason=reason,
        severity=issue.severity,
        source_issue_id=issue.issue_id,
        message=issue.message,
        metadata=issue.metadata,
    )


def is_approved_trigger(trigger: CorrectionTrigger) -> bool:
    return trigger.reason in APPROVED_TRIGGER_REASONS

