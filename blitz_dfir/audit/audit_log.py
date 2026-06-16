from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from blitz_dfir.core.integrity import hash_text

TAMPER_EVIDENT_NOTE = (
    "Audit entries are hash chained to make later modification visible; "
    "this is not a tamper-proof storage control."
)


@dataclass(frozen=True)
class AuditEntry:
    schema_version: str
    sequence: int
    timestamp_utc: str
    event_type: str
    data: dict[str, Any]
    previous_hash: str | None
    entry_hash: str
    session_id: str | None = None
    case_id: str | None = None
    correlation_id: str | None = None


class AuditLogger:
    def __init__(self, path: Path, *, session_id: str | None = None, case_id: str | None = None):
        self.path = path
        self.session_id = session_id
        self.case_id = case_id
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(
        self,
        event_type: str,
        data: dict[str, Any],
        *,
        correlation_id: str | None = None,
        timestamp_utc: str | None = None,
    ) -> AuditEntry:
        sequence, previous_hash = self._current_state()
        timestamp = timestamp_utc or datetime.now(UTC).isoformat().replace("+00:00", "Z")
        sanitized = _enrich_audit_data(event_type, sanitize_audit_data(data))
        payload = {
            "schema_version": "audit.v1",
            "sequence": sequence,
            "timestamp_utc": timestamp,
            "event_type": event_type,
            "session_id": self.session_id,
            "case_id": self.case_id,
            "correlation_id": correlation_id,
            "data": sanitized,
            "previous_hash": previous_hash,
        }
        entry_hash = hash_text(_canonical_json(payload))
        payload["entry_hash"] = entry_hash
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(_canonical_json(payload) + "\n")
        return AuditEntry(
            schema_version="audit.v1",
            sequence=sequence,
            timestamp_utc=timestamp,
            event_type=event_type,
            data=sanitized,
            previous_hash=previous_hash,
            entry_hash=entry_hash,
            session_id=self.session_id,
            case_id=self.case_id,
            correlation_id=correlation_id,
        )

    def verify_chain(self) -> bool:
        previous_hash: str | None = None
        expected_sequence = 1
        for line in self.path.read_text(encoding="utf-8").splitlines():
            payload = json.loads(line)
            entry_hash = payload.pop("entry_hash")
            if payload["sequence"] != expected_sequence:
                return False
            if payload["previous_hash"] != previous_hash:
                return False
            if hash_text(_canonical_json(payload)) != entry_hash:
                return False
            previous_hash = entry_hash
            expected_sequence += 1
        return True

    def _current_state(self) -> tuple[int, str | None]:
        if not self.path.exists():
            return 1, None
        lines = [line for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not lines:
            return 1, None
        last_payload = json.loads(lines[-1])
        return int(last_payload["sequence"]) + 1, str(last_payload["entry_hash"])


def _canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def tamper_evident_note() -> str:
    return TAMPER_EVIDENT_NOTE


def _enrich_audit_data(event_type: str, data: dict[str, Any]) -> dict[str, Any]:
    enriched = dict(data)
    enriched.setdefault("initiated_by", _initiated_by(event_type, enriched))
    enriched.setdefault("component", _component(event_type, enriched))
    enriched.setdefault("trust_boundary", _trust_boundary(event_type, enriched))
    enriched.setdefault("behavior", _behavior(event_type, enriched))
    return enriched


def _initiated_by(event_type: str, data: dict[str, Any]) -> str:
    tool = str(data.get("typed_tool") or data.get("tool") or data.get("tool_name") or "")
    parser = str(data.get("parser") or "")
    provider = str(data.get("provider") or os.getenv("LLM_PROVIDER") or "")
    model = str(data.get("model") or os.getenv("LLM_MODEL") or "")
    agent = str(os.getenv("BLITZ_AGENT_FRAMEWORK") or os.getenv("AGENT_FRAMEWORK") or "")
    llm = "/".join(part for part in (provider, model) if part)

    if event_type in {"manifest_loaded", "evidence_verified"}:
        return "Blitz DFIR manifest/integrity gate"
    if event_type == "analysis_started":
        if agent and llm:
            return f"{agent} -> Blitz DFIR (LLM configured: {llm})"
        if agent:
            return f"{agent} -> Blitz DFIR"
        if llm:
            return f"Blitz launcher/app.py (LLM configured: {llm})"
        return "Blitz launcher/app.py"
    if event_type == "protocol_sift_workflow_recorded":
        return "Protocol SIFT-compatible workflow context"
    if event_type == "case_objective_defined":
        return "Blitz case objective layer"
    if event_type == "investigation_plan_completed":
        return "Blitz investigation planner"
    if event_type == "evidence_triage_completed":
        return "Blitz evidence triage layer"
    if event_type in {"investigation_guidance_generated", "investigation_guidance_completed"}:
        return "Blitz investigation guidance layer"
    if event_type == "hypothesis_formed":
        return "Blitz deterministic hypothesis layer"
    if event_type == "plan_change":
        return "Blitz adaptive investigation planner"
    if event_type == "tool_discovery_completed":
        return "Blitz tool discovery -> SIFT tool inventory"
    if event_type == "batch_plan_created":
        return "Blitz DFIR batch planner"
    if event_type == "evidence_inventory_completed":
        return "Blitz evidence inventory layer"
    if event_type == "recovery_plan_created":
        return "Blitz recovery planner"
    if event_type == "object_inventory_completed":
        return "Blitz object inventory layer"
    if event_type == "full_accounting_completed":
        return "Blitz full accounting layer"
    if event_type == "analysis_scope_limited":
        return "Blitz scope governor"
    if event_type in {"correlation_completed", "sql_correlation_completed"}:
        return "Blitz correlation engine"
    if event_type in {"validation_completed", "validation_report"}:
        return "Blitz validation engine"
    if event_type in {"unknowns_completed", "coverage_scores"}:
        return "Blitz unknowns and coverage engine"
    if event_type == "evidence_maturity_written":
        return "Blitz evidence maturity traceability layer"
    if event_type == "agent_trace_written":
        return "Blitz agent trace and investigative journal layer"
    if event_type in {"artifact_manifest_written", "reports_written", "report_generation_completed"}:
        return "Blitz reporting/audit finalizer"
    if event_type == "analysis_completed":
        return "Blitz DFIR orchestrator"
    if event_type in {"batch_started", "batch_completed", "batch_task_skipped"}:
        return "Blitz DFIR batch planner"
    if event_type in {"tool_request_validated", "tool_request_completed", "tool_request_rejected"}:
        return f"Blitz MCP dispatcher -> {tool or 'typed tool'}"
    if event_type in {"analysis_tool_result", "tool_execution"}:
        return f"SIFT tool adapter: {tool or 'unknown'}"
    if event_type in {"analysis_tool_failed"}:
        return f"SIFT tool adapter failure: {tool or 'unknown'}"
    if event_type in {"parser_completed", "parser_result"}:
        return f"Blitz parser: {parser or 'unknown'}"
    if event_type in {"normalization_completed", "sqlite_normalization_completed"}:
        return "Blitz normalization engine"
    if event_type == "sql_correlation_completed":
        return "Blitz SQLite correlation engine"
    if event_type in {"reasoning_completed", "agent_decision"}:
        return f"Bounded LLM reasoning: {llm or 'configured provider'}"
    if event_type == "reasoning_skipped":
        return "Blitz DFIR policy: bounded LLM reasoning disabled for this run"
    if event_type in {"correction_attempt", "correction_history", "correction_outcome", "rerun_trigger"}:
        return "Blitz bounded self-correction engine"
    if event_type == "confidence_adjustment":
        return "Blitz confidence engine"
    if event_type in {"analysis_resumed", "resume_tool_results_loaded", "resume_tool_result_skipped"}:
        return "Blitz resume controller"
    if event_type == "integrity_check":
        check_type = str(data.get("check_type") or "")
        if check_type == "evidence_sha256":
            return "Blitz evidence integrity checker"
        if check_type == "tool_provenance":
            return "Blitz tool integrity checker"
        if check_type == "generated_report_sha256":
            return "Blitz report integrity checker"
    return "Blitz DFIR"


def _component(event_type: str, data: dict[str, Any]) -> str:
    if event_type == "tool_request_rejected" and data.get("reason") == "tool_not_allowlisted":
        return "security_boundary"
    if event_type.startswith("tool_") or event_type.startswith("analysis_tool"):
        return "typed_tool_boundary"
    if event_type == "protocol_sift_workflow_recorded":
        return "protocol_sift_workflow_layer"
    if event_type == "case_objective_defined":
        return "case_objective_layer"
    if event_type == "investigation_plan_completed":
        return "investigation_planning_layer"
    if event_type == "evidence_triage_completed":
        return "evidence_triage_layer"
    if event_type in {"investigation_guidance_generated", "investigation_guidance_completed"}:
        return "investigation_guidance_layer"
    if event_type in {"hypothesis_formed", "plan_change"}:
        return "adaptive_investigation_layer"
    if event_type in {"batch_plan_created", "batch_started", "batch_completed", "batch_task_skipped"}:
        return "batch_planning_layer"
    if event_type in {"tool_discovery_completed", "recovery_plan_created", "investigation_plan_completed"}:
        return "planning_layer"
    if "parser" in event_type:
        return "parser_layer"
    if "normalization" in event_type:
        return "normalization_layer"
    if event_type in {"object_inventory_completed", "evidence_inventory_completed"}:
        return "inventory_layer"
    if event_type == "full_accounting_completed":
        return "full_accounting_layer"
    if event_type == "analysis_scope_limited":
        return "scope_control_layer"
    if "correlation" in event_type:
        return "correlation_layer"
    if event_type.startswith("reasoning") or event_type == "agent_decision":
        return "bounded_llm_reasoning_layer"
    if event_type in {"evidence_maturity_written", "reports_written", "report_generation_completed", "artifact_manifest_written"}:
        return "reporting_audit_layer"
    if event_type == "agent_trace_written":
        return "agent_trace_layer"
    if event_type == "integrity_check":
        check_type = str(data.get("check_type") or "")
        if check_type == "tool_provenance":
            return "tool_integrity_layer"
        if check_type == "generated_report_sha256":
            return "reporting_audit_layer"
        return "evidence_integrity_layer"
    if event_type in {"manifest_loaded", "evidence_verified"}:
        return "evidence_integrity_layer"
    if event_type in {"validation_completed", "validation_report", "unknowns_completed", "coverage_scores"}:
        return "validation_unknowns_layer"
    if event_type in {"correction_attempt", "correction_history", "correction_outcome", "rerun_trigger"}:
        return "self_correction_layer"
    if event_type == "confidence_adjustment":
        return "confidence_layer"
    if event_type in {"analysis_resumed", "resume_tool_results_loaded", "resume_tool_result_skipped"}:
        return "resume_layer"
    return "pipeline_orchestrator"


def _trust_boundary(event_type: str, data: dict[str, Any]) -> str:
    if event_type == "protocol_sift_workflow_recorded":
        return "Protocol SIFT-compatible workflow context; Blitz remains typed evidence boundary"
    if event_type in {"tool_request_validated", "tool_request_completed", "tool_request_rejected"}:
        return "MCP typed allowlist"
    if event_type in {"analysis_tool_result", "tool_execution", "analysis_tool_failed"}:
        return "SIFT tool subprocess sandbox"
    if event_type in {"reasoning_completed", "agent_decision"}:
        return "bounded summaries only; no raw evidence"
    if event_type == "agent_trace_written":
        return "deterministic audit/report reconstruction; no raw evidence or raw tool output"
    if event_type in {"hypothesis_formed", "plan_change", "investigation_guidance_completed"}:
        return "derived investigation metadata; no raw evidence or raw tool output"
    if event_type in {"manifest_loaded", "evidence_verified"}:
        return "manifest-registered read-only evidence"
    if event_type == "analysis_scope_limited":
        return "bounded analysis/report caps"
    if event_type == "integrity_check":
        check_type = str(data.get("check_type") or "")
        if check_type == "tool_provenance":
            return "configured SIFT tool baseline"
        if check_type == "generated_report_sha256":
            return "generated artifact hash receipt"
        return "manifest-registered read-only evidence"
    if event_type in {"analysis_resumed", "resume_tool_results_loaded", "resume_tool_result_skipped"}:
        return "session-scoped checkpoint reuse"
    return "Blitz deterministic control plane"


def _behavior(event_type: str, data: dict[str, Any]) -> str:
    if event_type in {"tool_request_rejected"}:
        return "security_relevant_rejection"
    if event_type in {"analysis_tool_failed", "resume_tool_result_skipped"}:
        return "unexpected_or_degraded"
    if data.get("timed_out") is True:
        return "degraded_timeout"
    if not _is_success_exit_code(data.get("exit_code")):
        return "degraded_nonzero_exit"
    if event_type == "tool_discovery_completed" and (
        _int_value(data.get("missing_count")) > 0 or _int_value(data.get("hash_mismatch_count")) > 0
    ):
        return "environment_degraded"
    if event_type == "evidence_inventory_completed" and (
        _int_value(data.get("high_or_critical_risk_count")) > 0
        or _int_value(data.get("unavailable_tool_count")) > 0
    ):
        return "analyst_review_required"
    if event_type == "recovery_plan_created" and _int_value(data.get("blocked_candidate_count")) > 0:
        return "manual_review_required"
    if event_type in {"batch_task_skipped", "reasoning_skipped"}:
        return "expected_skip_or_disabled"
    if event_type in {"hypothesis_formed", "plan_change"}:
        return "investigative_adaptation_recorded"
    if event_type == "analysis_scope_limited":
        return "bounded_scope_limit"
    if event_type in {"validation_completed", "validation_report"} and (
        data.get("passed") is False or _int_value(data.get("issue_count")) > 0
    ):
        return "validation_issues_detected"
    if event_type == "unknowns_completed" and (
        _int_value(data.get("critical_count")) > 0 or _int_value(data.get("high_count")) > 0
    ):
        return "analyst_review_required"
    if event_type == "coverage_scores" and _float_value(data.get("overall_case_coverage")) < 1.0:
        return "coverage_gap"
    if event_type == "integrity_check" and data.get("verified") is False:
        return "integrity_warning"
    if event_type in {"correction_attempt", "correction_history", "correction_outcome", "rerun_trigger"}:
        return "self_correction_or_recovery"
    if event_type == "agent_trace_written":
        return "judge_traceability_artifact_written"
    return "expected"


def _is_success_exit_code(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, bool):
        return False
    try:
        return int(str(value)) == 0
    except (TypeError, ValueError):
        return False


def _int_value(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def _float_value(value: Any) -> float:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return 1.0


SENSITIVE_KEY_RE = re.compile(r"(api[_-]?key|token|secret|password|authorization)", re.I)
WINDOWS_PATH_RE = re.compile(r"[A-Za-z]:[\\/][^\s\"'<>|]+")
POSIX_PATH_RE = re.compile(r"(?<!\w)/(?:Users|home|mnt|media|tmp|var/tmp)/[^\s\"'<>|]+")
UNC_PATH_RE = re.compile(r"\\\\[^\\\s]+\\[^\s\"'<>|]+")


def sanitize_audit_data(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            safe_key = str(key)
            if SENSITIVE_KEY_RE.search(safe_key):
                sanitized[safe_key] = "[redacted]"
            else:
                sanitized[safe_key] = sanitize_audit_data(item)
        return sanitized
    if isinstance(value, list | tuple | set):
        return [sanitize_audit_data(item) for item in value]
    if isinstance(value, Path):
        return _redact_paths(str(value))
    if isinstance(value, str):
        return _redact_paths(value)
    if value is None or isinstance(value, bool | int | float):
        return value
    return _redact_paths(str(value))


def _redact_paths(value: str) -> str:
    redacted = WINDOWS_PATH_RE.sub(_path_replacement, value)
    redacted = POSIX_PATH_RE.sub(_path_replacement, redacted)
    return UNC_PATH_RE.sub("[path-redacted]", redacted)


def _path_replacement(match: re.Match[str]) -> str:
    text = match.group(0).replace("\\", "/").rstrip(".,;)")
    filename = text.rsplit("/", 1)[-1]
    if filename and "." in filename:
        return f"[path-redacted]/{filename}"
    return "[path-redacted]"
