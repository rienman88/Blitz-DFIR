from __future__ import annotations

from collections.abc import Callable

from blitz_dfir.audit.audit_log import AuditLogger
from blitz_dfir.core.integrity import hash_text
from blitz_dfir.correction.models import (
    MAX_CORRECTIONS,
    MAX_PERSISTENT_ITERATIONS,
    MAX_RETRIES,
    CorrectionAttempt,
    CorrectionHistory,
    CorrectionStatus,
    CorrectionTrigger,
    RecoveryAction,
)
from blitz_dfir.correction.rerun_engine import recovery_action_for_trigger, validate_recovery_action

CorrectionExecutor = Callable[[RecoveryAction], tuple[CorrectionStatus, str, float]]


def execute_bounded_corrections(
    triggers: tuple[CorrectionTrigger, ...],
    *,
    confidence_before: float,
    executor: CorrectionExecutor | None = None,
    max_retries: int = MAX_RETRIES,
    max_corrections: int = MAX_CORRECTIONS,
    max_iterations: int = MAX_PERSISTENT_ITERATIONS,
    audit_logger: AuditLogger | None = None,
) -> CorrectionHistory:
    if max_retries > MAX_RETRIES:
        raise ValueError("max_retries cannot exceed 2")
    if max_corrections > MAX_CORRECTIONS:
        raise ValueError("max_corrections cannot exceed 2")
    if max_iterations > MAX_PERSISTENT_ITERATIONS:
        raise ValueError("persistent loop max_iterations cannot exceed configured hard cap")

    attempts: list[CorrectionAttempt] = []
    current_confidence = confidence_before
    last_action_type = "none"
    bounded_triggers = triggers[:max_corrections]
    for iteration, trigger in enumerate(bounded_triggers, 1):
        action = recovery_action_for_trigger(trigger)
        validate_recovery_action(action)
        status, result, confidence_after = _execute(action, executor, current_confidence)
        confidence_after = _bounded_confidence(confidence_after)
        if status == "FAILED":
            status = "FAILED_LOW_CONFIDENCE"
            confidence_after = min(confidence_after, current_confidence, 0.40)
        attempt = CorrectionAttempt(
            correction_id=_correction_id(trigger, action, iteration),
            iteration=iteration,
            trigger=trigger,
            action=action,
            status=status,
            result=result,
            confidence_before=current_confidence,
            confidence_after=confidence_after,
            confidence_delta=round(confidence_after - current_confidence, 6),
            changed_from_prior=f"{last_action_type} -> {action.action_type}",
            why=trigger.message,
        )
        attempts.append(attempt)
        current_confidence = confidence_after
        last_action_type = action.action_type
        if audit_logger is not None:
            audit_logger.append("correction_attempt", attempt.model_dump())

    final_status = _final_status(tuple(attempts), bool(triggers))
    history = CorrectionHistory(
        attempts=tuple(attempts),
        final_confidence=current_confidence if attempts else confidence_before,
        status=final_status,
        max_retries=max_retries,
        max_corrections=max_corrections,
        max_iterations=max_iterations,
    )
    if audit_logger is not None:
        audit_logger.append("correction_history", history.as_report_section())
    return history


def _execute(
    action: RecoveryAction,
    executor: CorrectionExecutor | None,
    current_confidence: float,
) -> tuple[CorrectionStatus, str, float]:
    if executor is None:
        if action.action_type == "DOWNGRADE_CONFIDENCE_FLAG_UNVERIFIED":
            return "SUCCESS", "confidence downgraded and tool output marked unverified", current_confidence - 0.30
        return "SKIPPED", "correction action recorded but no executor was provided", current_confidence
    return executor(action)


def _final_status(attempts: tuple[CorrectionAttempt, ...], had_triggers: bool) -> CorrectionStatus:
    if not had_triggers:
        return "SKIPPED"
    if any(attempt.status == "SUCCESS" for attempt in attempts):
        return "SUCCESS"
    if any(attempt.status == "FAILED_LOW_CONFIDENCE" for attempt in attempts):
        return "FAILED_LOW_CONFIDENCE"
    if attempts:
        return attempts[-1].status
    return "SKIPPED"


def _correction_id(trigger: CorrectionTrigger, action: RecoveryAction, iteration: int) -> str:
    return f"CORR-{hash_text('|'.join([trigger.trigger_id, action.action_id, str(iteration)]))[:12].upper()}"


def _bounded_confidence(value: float) -> float:
    return min(max(value, 0.0), 1.0)

