from __future__ import annotations

from blitz_dfir.core.integrity import hash_text
from blitz_dfir.correction.models import (
    APPROVED_ACTION_TYPES,
    CorrectionTrigger,
    RecoveryAction,
)
from blitz_dfir.correction.triggers import is_approved_trigger

ACTION_ALLOWED_TOOLS = {
    "NARROW_EVTX_TIME_RANGE": ("events", "timeline"),
    "FILTER_STRINGS_EXECUTABLE_REGIONS": ("strings",),
    "RUN_SPECIFIC_VOLATILITY_PLUGIN": ("memory",),
    "SCOPED_PSORT_FILTER": ("psort", "timeline"),
    "CHUNK_MEMORY_EXTRACTION": ("memory",),
    "ALTERNATE_PARSER_FALLBACK": ("events", "pcap", "timeline"),
    "FALLBACK_CORRELATION_AVAILABLE_SOURCES": (),
    "DOWNGRADE_CONFIDENCE_FLAG_UNVERIFIED": (),
    "SCOPED_CORRELATION_REVIEW": (),
}

TRIGGER_ACTION_MAP = {
    "MISSING_EVIDENCE_OR_BROKEN_LINEAGE": "FALLBACK_CORRELATION_AVAILABLE_SOURCES",
    "LOW_CONFIDENCE": "SCOPED_CORRELATION_REVIEW",
    "PARSER_DEGRADATION_OR_SIGNAL_LOSS": "ALTERNATE_PARSER_FALLBACK",
    "TIMELINE_GAP_OR_CONTRADICTION": "SCOPED_CORRELATION_REVIEW",
    "CONTRADICTION_LIMIT_EXCEEDED": "SCOPED_CORRELATION_REVIEW",
    "TOOL_INTEGRITY_MISMATCH": "DOWNGRADE_CONFIDENCE_FLAG_UNVERIFIED",
}


def recovery_action_for_trigger(trigger: CorrectionTrigger) -> RecoveryAction:
    if not is_approved_trigger(trigger):
        raise ValueError(f"unapproved correction trigger: {trigger.reason}")
    action_type = _action_type_from_trigger(trigger)
    return _build_action(action_type, trigger)


def validate_recovery_action(action: RecoveryAction) -> None:
    if action.action_type not in APPROVED_ACTION_TYPES:
        raise ValueError(f"unapproved recovery action: {action.action_type}")
    allowed = ACTION_ALLOWED_TOOLS[action.action_type]
    if tuple(action.allowed_tools) != allowed:
        raise ValueError("recovery action tool allowlist does not match policy")


def _action_type_from_trigger(trigger: CorrectionTrigger) -> str:
    warning_type = str(trigger.metadata.get("warning_type", ""))
    message = trigger.message.lower()
    if warning_type == "EVENT_TRUNCATION" and "evtx" in str(trigger.metadata).lower():
        return "NARROW_EVTX_TIME_RANGE"
    if warning_type == "EVENT_TRUNCATION" and "plaso" in str(trigger.metadata).lower():
        return "SCOPED_PSORT_FILTER"
    if warning_type == "TOOL_TIMEOUT" and "volatility" in message:
        return "RUN_SPECIFIC_VOLATILITY_PLUGIN"
    if warning_type == "PARSER_CRASH":
        return "ALTERNATE_PARSER_FALLBACK"
    if warning_type == "HASH_MISMATCH":
        return "DOWNGRADE_CONFIDENCE_FLAG_UNVERIFIED"
    if "strings" in message and ("huge" in message or "truncat" in message):
        return "FILTER_STRINGS_EXECUTABLE_REGIONS"
    if "memory" in message and ("exhaust" in message or "partial" in message):
        return "CHUNK_MEMORY_EXTRACTION"
    return TRIGGER_ACTION_MAP[trigger.reason]


def _build_action(action_type: str, trigger: CorrectionTrigger) -> RecoveryAction:
    action_id = f"ACT-{hash_text('|'.join([action_type, trigger.trigger_id]))[:12].upper()}"
    scope = _scope_for_action(action_type)
    action = RecoveryAction(
        action_id=action_id,
        action_type=action_type,
        scope=scope,
        rationale=trigger.message,
        allowed_tools=ACTION_ALLOWED_TOOLS[action_type],
        params=_params_for_action(action_type, trigger),
    )
    validate_recovery_action(action)
    return action


def _scope_for_action(action_type: str) -> str:
    scopes = {
        "NARROW_EVTX_TIME_RANGE": "rerun EVTX extraction only for narrowed time range",
        "FILTER_STRINGS_EXECUTABLE_REGIONS": "rerun strings scan only against executable regions",
        "RUN_SPECIFIC_VOLATILITY_PLUGIN": "rerun only the specific Volatility plugin that timed out",
        "SCOPED_PSORT_FILTER": "rerun psort only with bounded filters",
        "CHUNK_MEMORY_EXTRACTION": "rerun memory extraction in bounded chunks",
        "ALTERNATE_PARSER_FALLBACK": "parse existing tool output with approved fallback parser",
        "FALLBACK_CORRELATION_AVAILABLE_SOURCES": "correlate only from available normalized sources",
        "DOWNGRADE_CONFIDENCE_FLAG_UNVERIFIED": "do not rerun; mark tool output unverified and lower confidence",
        "SCOPED_CORRELATION_REVIEW": "re-evaluate existing normalized correlations only",
    }
    return scopes[action_type]


def _params_for_action(action_type: str, trigger: CorrectionTrigger) -> dict[str, object]:
    params: dict[str, object] = {"trigger_id": trigger.trigger_id}
    if action_type == "NARROW_EVTX_TIME_RANGE":
        params["time_window"] = "bounded_around_existing_events"
    if action_type == "RUN_SPECIFIC_VOLATILITY_PLUGIN":
        params["plugin_scope"] = "specific_plugin_only"
    if action_type == "SCOPED_PSORT_FILTER":
        params["filter"] = "bounded_time_or_source_filter"
    if action_type == "CHUNK_MEMORY_EXTRACTION":
        params["chunking"] = "bounded_memory_regions"
    if action_type == "ALTERNATE_PARSER_FALLBACK":
        params["fallback"] = "approved_parser_only"
    return params

