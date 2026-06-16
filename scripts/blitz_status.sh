#!/usr/bin/env bash
set -euo pipefail

CASE="${CASE:-BLITZ-RD01-PLASO}"
EXPLICIT_SESSION="${1:-}"
ENV_SESSION="${SESSION:-}"
SUPPRESS_OPERATOR_RESULT="${BLITZ_STATUS_SUPPRESS_OPERATOR_RESULT:-0}"
RUN_SELECTION=0
LATEST_RUN_WITHOUT_SESSION=0
PROCESS_PATTERN='app.py analyze|psort.py|log2timeline.py|psteal.py|case.plaso|tsk_e01_triage.py|(^|[[:space:]/])fls([[:space:]]|$)|(^|[[:space:]/])mmls([[:space:]]|$)'
ACTIVE_PROCESSES="$(
  ps -eo pid,ppid,stat,etime,%mem,%cpu,rss,vsz,cmd \
    | egrep "$PROCESS_PATTERN" \
    | grep -v grep || true
)"
ACTIVE_PROCESS_PRESENT=0
if [ -n "$ACTIVE_PROCESSES" ]; then
  ACTIVE_PROCESS_PRESENT=1
fi

if [ -n "$EXPLICIT_SESSION" ]; then
  SESSION="$EXPLICIT_SESSION"
elif [ -n "$ENV_SESSION" ]; then
  SESSION="$ENV_SESSION"
else
  SESSION="$(python - "$CASE" "$ACTIVE_PROCESS_PRESENT" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

case = sys.argv[1]
active_process_present = sys.argv[2] == "1"
root = Path(f"/cases/{case}/output")
sessions = sorted(root.glob("sess-*"), key=lambda path: path.stat().st_mtime, reverse=True)


def state(path: Path) -> dict:
    state_path = path / "audit" / "session_state.json"
    if not state_path.exists():
        return {}
    try:
        return json.loads(state_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def progress(path: Path) -> dict:
    progress_path = path / "audit" / "progress.json"
    if not progress_path.exists():
        return {}
    try:
        return json.loads(progress_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


if active_process_present:
    for candidate in sessions:
        if progress(candidate).get("status") == "RUNNING":
            print(candidate)
            raise SystemExit
    for candidate in sessions:
        if state(candidate).get("status") == "RUNNING":
            print(candidate)
            raise SystemExit
if sessions:
    print(sessions[0])
PY
)"
fi

echo "[time]"
date -u

echo
echo "[active Blitz/SIFT processes]"
if [ -n "$ACTIVE_PROCESSES" ]; then
  ACTIVE_PROCESSES="$ACTIVE_PROCESSES" python - <<'PY'
from __future__ import annotations

import os
import re


def mb(kilobytes: str) -> str:
    try:
        return f"{int(kilobytes) / 1024:.1f}"
    except ValueError:
        return "?"


def option(cmd: str, name: str) -> str | None:
    match = re.search(rf"{re.escape(name)}(?:=|\s+)(\"[^\"]+\"|'[^']+'|\S+)", cmd)
    if not match:
        return None
    return match.group(1).strip("'\"")


def command_label(cmd: str) -> str:
    if "app.py analyze" in cmd:
        return "Blitz analysis"
    if "psort.py" in cmd:
        return "SIFT psort timeline export"
    if "log2timeline.py" in cmd:
        return "SIFT log2timeline parser"
    if "tsk_e01_triage.py" in cmd:
        return "Blitz disk triage fallback"
    if re.search(r"(^|[ /])fls([ ]|$)", cmd):
        return "Sleuth Kit filesystem enumeration"
    if re.search(r"(^|[ /])mmls([ ]|$)", cmd):
        return "Sleuth Kit partition scan"
    if "psteal.py" in cmd:
        return "SIFT psteal parser/export"
    if "sha256sum" in cmd and "case.plaso" in cmd:
        return "Evidence SHA256 verification"
    if "bash -lc" in cmd:
        return "Blitz supervised launcher"
    return cmd.split()[0] if cmd.split() else "unknown"


def command_details(cmd: str) -> str:
    details: list[str] = []
    if "app.py analyze" in cmd:
        for flag, label in (
            ("--max-normalized-events", "max_norm"),
            ("--max-analysis-events", "max_analysis"),
            ("--report-event-limit", "report_events"),
            ("--report-finding-limit", "report_findings"),
            ("--psort-profile", "psort_profile"),
        ):
            value = option(cmd, flag)
            if value:
                details.append(f"{label}={value}")
        if "--enable-reasoning" in cmd:
            details.append("bounded_llm=enabled")
        psort_filter = option(cmd, "--psort-filter")
        if psort_filter:
            details.append(f"psort_filter={psort_filter[:42]}")
    elif "psort.py" in cmd:
        for flag, label in (("-o", "output"),):
            value = option(cmd, flag)
            if value:
                details.append(f"{label}={value}")
        if "case.plaso" in cmd:
            details.append("source=case.plaso")
    elif "bash -lc" in cmd:
        details.append("wrapper=waiting on child process")
    return "; ".join(details) if details else "no parsed details"


rows = []
for line in os.environ.get("ACTIVE_PROCESSES", "").splitlines():
    fields = line.split(None, 8)
    if len(fields) < 9:
        continue
    pid, ppid, stat, elapsed, mem, cpu, rss, _vsz, cmd = fields
    rows.append(
        {
            "pid": pid,
            "ppid": ppid,
            "stat": stat,
            "elapsed": elapsed,
            "cpu": cpu,
            "mem": mem,
            "rss_mb": mb(rss),
            "label": command_label(cmd),
            "details": command_details(cmd),
        }
    )

if not rows:
    print("active processes matched, but no rows could be parsed")
else:
    print(f"{'PID':>7} {'PPID':>7} {'STAT':<6} {'ELAPSED':>11} {'CPU%':>6} {'MEM%':>6} {'RSS_MB':>8}  PROCESS")
    for row in rows:
        print(
            f"{row['pid']:>7} {row['ppid']:>7} {row['stat']:<6} {row['elapsed']:>11} "
            f"{row['cpu']:>6} {row['mem']:>6} {row['rss_mb']:>8}  {row['label']}"
        )
        print(f"{'':>58}  {row['details']}")
PY
else
  echo "no active Blitz/SIFT analysis process matched"
fi

echo
echo "[latest run bundle]"
RUN_ROOT="$(ls -td "/cases/${CASE}/analysis/runs"/* 2>/dev/null | head -n 1 || true)"
if [ -z "$RUN_ROOT" ] || [ ! -d "$RUN_ROOT" ]; then
  echo "no run bundle found"
else
  echo "$RUN_ROOT"
  if [ -f "$RUN_ROOT/blitz.pid" ]; then
    echo "pid=$(cat "$RUN_ROOT/blitz.pid")"
  fi
  if [ -f "$RUN_ROOT/session_path.txt" ]; then
    echo "session_path=$(cat "$RUN_ROOT/session_path.txt")"
  else
    echo "session_path=not_created_yet"
    LATEST_RUN_WITHOUT_SESSION=1
  fi
  if [ -f "$RUN_ROOT/launcher.log" ]; then
    echo "launcher_tail:"
    tail -n 12 "$RUN_ROOT/launcher.log"
  fi
  if [ -z "$EXPLICIT_SESSION" ] && [ -z "$ENV_SESSION" ] && [ -f "$RUN_ROOT/session_path.txt" ]; then
    RUN_SESSION="$(cat "$RUN_ROOT/session_path.txt")"
    if [ -d "$RUN_SESSION" ]; then
      SESSION="$RUN_SESSION"
      RUN_SELECTION=1
    fi
  fi
fi

if [ "$LATEST_RUN_WITHOUT_SESSION" = "1" ] \
  && [ -z "$EXPLICIT_SESSION" ] \
  && [ -z "$ENV_SESSION" ] \
  && { [ -z "$SESSION" ] || [ ! -d "$SESSION" ]; }; then
  SESSION=""
fi

echo
echo "[session]"
if [ -z "$SESSION" ] || [ ! -d "$SESSION" ]; then
  if [ "$LATEST_RUN_WITHOUT_SESSION" = "1" ]; then
    echo "session not created yet for latest run bundle"
    echo
    echo "[progress]"
    echo "source: latest run bundle before session creation"
    if [ "$ACTIVE_PROCESS_PRESENT" = "1" ]; then
      echo "status: RUNNING"
      if echo "$ACTIVE_PROCESSES" | grep -qi 'sha256sum .*case\.plaso'; then
        echo "current_layer: Manifest and evidence integrity check (pre-session hashing)"
        echo "message: Blitz is verifying evidence integrity before session creation. This may take a while on large evidence."
      else
        echo "current_layer: Startup/pre-session work"
        echo "message: Blitz run initiated. This may take a while; session creation has not started yet."
      fi
    else
      echo "status: INTERRUPTED"
      echo "message: Blitz DFIR process interrupted before a session was created. Check launcher_tail above for the exact failing step. If you want to continue processing, reinitiate the process after fixing the cause."
    fi
    echo
    echo "[operator result]"
    if [ "$ACTIVE_PROCESS_PRESENT" = "1" ]; then
      echo "Blitz DFIR Process still running"
    else
      echo "Blitz DFIR Process did not complete cleanly: interrupted_before_session_creation"
    fi
  else
    echo "no session found for CASE=${CASE}"
  fi
  exit 0
fi
echo "$SESSION"
if [ -n "$EXPLICIT_SESSION" ]; then
  echo "selection=explicit_arg"
elif [ -n "$ENV_SESSION" ]; then
  echo "selection=SESSION_environment"
elif [ "$RUN_SELECTION" = "1" ]; then
  echo "selection=latest_run_bundle_session"
else
  if [ "$ACTIVE_PROCESS_PRESENT" = "1" ]; then
    echo "selection=auto_running_session"
  else
    echo "selection=auto_latest_session_no_active_process"
  fi
fi
if [ "$LATEST_RUN_WITHOUT_SESSION" = "1" ] && [ "$RUN_SELECTION" != "1" ] && [ -z "$EXPLICIT_SESSION" ] && [ -z "$ENV_SESSION" ]; then
  if [ "$ACTIVE_PROCESS_PRESENT" = "1" ]; then
    echo "note=latest_run_bundle_session_pointer_pending; selected active output session"
  else
    echo "note=latest_run_bundle_has_no_session; below is historical latest session, not a new E2E result"
  fi
fi

MATCHED_RUN_ROOT="$(
  python - "$CASE" "$SESSION" "${RUN_ROOT:-}" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path

case = sys.argv[1]
session = Path(sys.argv[2])
latest_run = Path(sys.argv[3]) if sys.argv[3] else None
runs_root = Path(f"/cases/{case}/analysis/runs")


def run_points_to_session(run_root: Path) -> bool:
    session_path = run_root / "session_path.txt"
    if not session_path.exists():
        return False
    return session_path.read_text(encoding="utf-8").strip() == str(session)


if latest_run and latest_run.is_dir() and run_points_to_session(latest_run):
    print(latest_run)
    raise SystemExit

if runs_root.exists():
    runs = sorted((path for path in runs_root.iterdir() if path.is_dir()), key=lambda path: path.stat().st_mtime, reverse=True)
    for run in runs:
        if run_points_to_session(run):
            print(run)
            raise SystemExit
PY
)"
RUN_STATUS_PATH=""
if [ -n "$MATCHED_RUN_ROOT" ]; then
  RUN_STATUS_PATH="${MATCHED_RUN_ROOT}/run_status.json"
fi
POSTRUN_MANIFEST="/cases/${CASE}/analysis/postrun_checks/$(basename "$SESSION")_latest_postrun_manifest.json"
PROGRESS="${SESSION}/audit/progress.json"
STATE="${SESSION}/audit/session_state.json"
AUDIT_GLOB="${SESSION}/audit/"*.ndjson

echo
echo "[run operator status]"
python - "$MATCHED_RUN_ROOT" "$RUN_STATUS_PATH" "$POSTRUN_MANIFEST" "$ACTIVE_PROCESS_PRESENT" "$PROGRESS" "$STATE" <<'PY'
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

run_root = Path(sys.argv[1]) if sys.argv[1] else None
run_status_path = Path(sys.argv[2]) if sys.argv[2] else None
postrun_manifest_path = Path(sys.argv[3])
active_analysis_process = sys.argv[4] == "1"
progress_path = Path(sys.argv[5])
state_path = Path(sys.argv[6])


def load_json(path: Path | None) -> dict:
    if path is None or not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def pid_alive(pid: object) -> bool:
    try:
        value = int(str(pid))
    except (TypeError, ValueError):
        return False
    if value <= 0:
        return False
    try:
        os.kill(value, 0)
    except OSError:
        return False
    return True


run_status = load_json(run_status_path)
postrun = load_json(postrun_manifest_path)
progress = load_json(progress_path)
state = load_json(state_path)
if run_root:
    print(f"run_root: {run_root}")
else:
    print("run_root: not_found_for_selected_session")
if run_status_path and run_status_path.exists():
    print(f"source: {run_status_path}")
else:
    print("source: reconstructed; run_status.json not found")

status = str(run_status.get("status") or "UNKNOWN")
phase = str(run_status.get("phase") or "unknown")
analysis_exit = run_status.get("analysis_exit_code")
postrun_default = (
    "NOT_CONFIGURED"
    if status == "COMPLETED"
    else "UNKNOWN"
)
postrun_status = str(run_status.get("postrun_checks") or postrun.get("status") or postrun_default)
analysis_pid = run_status.get("analysis_pid")
supervisor_pid = run_status.get("supervisor_pid")
analysis_pid_alive = pid_alive(analysis_pid)
supervisor_pid_alive = pid_alive(supervisor_pid)
session_completed = str(progress.get("status") or state.get("status") or "").upper() == "COMPLETED" or str(
    state.get("status") or ""
).upper() == "COMPLETED"
session_failed = str(progress.get("status") or state.get("status") or "").upper() in {"FAILED", "PARTIAL"} or str(
    state.get("status") or ""
).upper() in {"FAILED", "PARTIAL"}
run_status_stale_completed = (
    bool(run_status)
    and session_completed
    and status not in {"COMPLETED", "FAILED"}
    and not active_analysis_process
    and not analysis_pid_alive
)
effective_status = "COMPLETED_FROM_SESSION_STATE" if run_status_stale_completed else status
if run_status_stale_completed and postrun_status == "UNKNOWN":
    postrun_status = "NOT_CONFIGURED"
prompt_returned = status == "COMPLETED" or run_status_stale_completed

print(f"operator_status: {status}")
if effective_status != status:
    print(f"effective_operator_status: {effective_status}")
    print("operator_status_note: run_status.json is stale; progress.json/session_state.json show the session completed.")
print(f"operator_phase: {phase}")
print(f"analysis_process_active: {'yes' if active_analysis_process or analysis_pid_alive else 'no'}")
if analysis_exit is not None:
    print(f"analysis_exit_code: {analysis_exit}")
elif run_status_stale_completed:
    print("analysis_exit_code: wrapper_missing_but_session_completed")
else:
    print("analysis_exit_code: pending")
print(f"postrun_checks: {postrun_status}")
print(f"supervisor_pid: {supervisor_pid if supervisor_pid is not None else 'unknown'} alive={'yes' if supervisor_pid_alive else 'no'}")
print(f"prompt_returned_or_returning: {'yes' if prompt_returned else 'no'}")

if postrun:
    print(f"postrun_current_check: {postrun.get('current_check')}")
    ready = postrun.get("ready") if isinstance(postrun.get("ready"), dict) else {}
    if ready:
        print("postrun_artifacts:")
        for name, exists in sorted(ready.items()):
            print(f"  {name}: {'ready' if exists else 'pending'}")

pending = []
if run_status_stale_completed:
    pending.append("run_status.json final write was interrupted; session artifacts are complete")
elif status not in {"COMPLETED", "FAILED"}:
    pending.append("supervised launcher still active or final status not written")
if analysis_exit is None and not run_status_stale_completed:
    pending.append("analysis process exit code")
if postrun_status in {"RUNNING", "NOT_STARTED", "UNKNOWN"} and not run_status_stale_completed:
    pending.append("postrun checks")
if not prompt_returned and not session_failed:
    pending.append("shell prompt return/final launcher exit")
if pending:
    print("pending_after_session_100: " + "; ".join(pending))
else:
    print("pending_after_session_100: none")
PY

echo
echo "[progress]"
python - "$PROGRESS" "$STATE" "$SESSION" "$ACTIVE_PROCESS_PRESENT" <<'PY'
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

progress_path = Path(sys.argv[1])
state_path = Path(sys.argv[2])
session = Path(sys.argv[3])
active_process_present = sys.argv[4] == "1"

LAYERS = (
    ("manifest_integrity", "Manifest and evidence integrity", 5),
    ("protocol_sift_workflow", "Protocol SIFT workflow context", 3),
    ("case_objective", "Case objective definition", 2),
    ("tool_discovery", "Tool discovery", 4),
    ("investigation_planning", "Investigation planning", 4),
    ("batch_planning", "Batch planning", 4),
    ("evidence_inventory", "Evidence inventory", 4),
    ("recovery_planning", "Recovery planning", 4),
    ("evidence_triage", "Evidence triage", 4),
    ("typed_tool_execution", "Typed SIFT tool execution", 20),
    ("parsing", "Parser result extraction", 8),
    ("normalization", "SQLite-backed normalization", 11),
    ("object_inventory", "Object inventory", 6),
    ("full_accounting", "Full accounting", 6),
    ("sqlite_event_store", "SQLite event store", 8),
    ("correlation", "Correlation and suspicion scoring", 12),
    ("investigation_guidance", "Investigation guidance", 2),
    ("temporal_analysis", "Temporal gap and attack-stage timeline", 2),
    ("evidentiary_weighting", "Evidentiary weighting", 2),
    ("contradiction_analysis", "Evidence contradiction analysis", 2),
    ("validation", "Validation", 3),
    ("unknowns", "Unknowns and coverage", 3),
    ("bounded_llm_reasoning", "Bounded LLM reasoning over validated summaries", 4),
    ("llm_report_verification", "LLM report verification", 2),
    ("report_generation", "Report generation", 2),
    ("evidence_maturity", "Evidence maturity traceability", 2),
    ("agent_trace", "Agent trace and investigative journal", 2),
    ("collated_outputs", "Overall findings, reports, and collated audit", 1),
    ("audit_finalization", "Audit finalization and artifact hashes", 1),
)


def duration(seconds: object) -> str:
    try:
        value = int(seconds)
    except (TypeError, ValueError):
        return "unknown"
    hours, rem = divmod(max(value, 0), 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def icon(status: str) -> str:
    return {
        "COMPLETED": "[x]",
        "RUNNING": "[>]",
        "FAILED": "[!]",
        "SKIPPED": "[-]",
    }.get(status, "[ ]")


def layer_count_text(layer: dict) -> str:
    layer_id = str(layer.get("layer_id"))
    details = layer.get("details") if isinstance(layer.get("details"), dict) else {}
    processed = layer.get("processed_items")
    total = layer.get("total_items")
    if layer_id == "normalization" and details:
        normalized_rows = details.get("live_processed_normalized_rows", processed)
        source_rows_seen = details.get("live_source_rows_seen")
        cap = details.get("configured_normalized_event_cap", total)
        analysis_memory_limit = details.get("analysis_event_memory_limit")
        retained = details.get("analysis_events_retained")
        parts = []
        if normalized_rows is not None:
            parts.append(f"normalized_rows={normalized_rows}")
        if source_rows_seen is not None:
            parts.append(f"source_rows_seen={source_rows_seen}")
        if cap is not None:
            parts.append(f"cap={cap}")
        if analysis_memory_limit is not None:
            parts.append(f"analysis_memory_limit={analysis_memory_limit}")
        if retained is not None:
            parts.append(f"retained={retained}")
        return f" ({', '.join(parts)})" if parts else ""
    if processed is not None and total is not None:
        return f" ({processed}/{total})"
    return ""


def bar(percent: object, width: int = 34) -> str:
    try:
        value = float(percent)
    except (TypeError, ValueError):
        value = 0.0
    value = min(max(value, 0.0), 100.0)
    done = int(round(width * value / 100.0))
    return "[" + "#" * done + "." * (width - done) + "]"


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def pid_alive(pid: object) -> bool:
    try:
        value = int(pid)
    except (TypeError, ValueError):
        return False
    if value <= 0:
        return False
    try:
        os.kill(value, 0)
    except OSError:
        return False
    return True


def audit_events() -> list[str]:
    events: list[str] = []
    for audit_path in sorted((session / "audit").glob("*.ndjson")):
        for line in audit_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            event_type = payload.get("event_type")
            if isinstance(event_type, str):
                events.append(event_type)
    return events


def reconstructed_progress() -> dict:
    state = load_json(state_path)
    events = set(audit_events())
    completed_by_event = {
        "manifest_integrity": {"protocol_sift_workflow_recorded", "case_objective_defined", "batch_plan_created"},
        "protocol_sift_workflow": {"protocol_sift_workflow_recorded"},
        "case_objective": {"case_objective_defined"},
        "tool_discovery": {"tool_discovery_completed"},
        "investigation_planning": {"investigation_plan_completed"},
        "batch_planning": {"batch_plan_created"},
        "evidence_inventory": {"evidence_inventory_completed"},
        "recovery_planning": {"recovery_plan_created"},
        "evidence_triage": {"evidence_triage_completed"},
        "typed_tool_execution": {"batch_completed"},
        "parsing": {"parser_completed", "batch_completed"},
        "normalization": {"normalization_completed", "sqlite_normalization_completed"},
        "object_inventory": {"object_inventory_completed"},
        "full_accounting": {"full_accounting_completed"},
        "sqlite_event_store": {"full_accounting_completed"},
        "correlation": {"correlation_completed"},
        "investigation_guidance": {"investigation_guidance_generated"},
        "temporal_analysis": {"temporal_analysis_completed"},
        "evidentiary_weighting": {"evidentiary_weighting_completed"},
        "contradiction_analysis": {"contradiction_analysis_completed"},
        "validation": {"validation_completed"},
        "unknowns": {"unknowns_completed"},
        "bounded_llm_reasoning": {"reasoning_completed", "reasoning_skipped"},
        "llm_report_verification": {"llm_report_verification_completed"},
        "report_generation": {"report_generation_completed", "reports_written"},
        "evidence_maturity": {"evidence_maturity_written"},
        "agent_trace": {"agent_trace_written"},
        "collated_outputs": {"collated_outputs_written"},
        "audit_finalization": {"artifact_manifest_written", "analysis_completed"},
    }
    skipped_by_event = {
        "bounded_llm_reasoning": {"reasoning_skipped"},
    }
    running_by_event = {
        "protocol_sift_workflow": {"analysis_started"},
        "case_objective": {"protocol_sift_workflow_recorded"},
        "tool_discovery": {"case_objective_defined", "manifest_loaded", "analysis_started"},
        "investigation_planning": {"tool_discovery_completed"},
        "batch_planning": {"investigation_plan_completed"},
        "evidence_inventory": {"batch_plan_created"},
        "recovery_planning": {"evidence_inventory_completed"},
        "evidence_triage": {"recovery_plan_created"},
        "typed_tool_execution": {"evidence_triage_completed", "batch_started", "tool_request_validated"},
        "parsing": {"batch_completed"},
        "normalization": {"parser_completed", "batch_completed"},
        "object_inventory": {"normalization_completed"},
        "full_accounting": {"object_inventory_completed"},
        "sqlite_event_store": {"full_accounting_completed"},
        "correlation": {"full_accounting_completed", "sql_correlation_completed"},
        "investigation_guidance": {"correlation_completed"},
        "temporal_analysis": {"investigation_guidance_generated"},
        "evidentiary_weighting": {"temporal_analysis_completed"},
        "contradiction_analysis": {"evidentiary_weighting_completed"},
        "validation": {"contradiction_analysis_completed"},
        "unknowns": {"validation_completed"},
        "bounded_llm_reasoning": {"unknowns_completed"},
        "llm_report_verification": {"reasoning_completed", "reasoning_skipped"},
        "report_generation": {"llm_report_verification_completed", "reasoning_completed", "reasoning_skipped"},
        "evidence_maturity": {"reports_written"},
        "agent_trace": {"evidence_maturity_written"},
        "collated_outputs": {"agent_trace_written"},
        "audit_finalization": {"collated_outputs_written", "reports_written"},
    }
    layers = []
    current = None
    for layer_id, name, weight in LAYERS:
        completed = bool(events & completed_by_event.get(layer_id, set()))
        skipped = bool(events & skipped_by_event.get(layer_id, set()))
        running = bool(events & running_by_event.get(layer_id, set())) and not completed
        status = "SKIPPED" if skipped else "COMPLETED" if completed else "RUNNING" if running and current is None else "PENDING"
        if status == "RUNNING":
            current = layer_id
        layers.append(
            {
                "layer_id": layer_id,
                "name": name,
                "weight": weight,
                "status": status,
                "percent": 100.0 if completed else 10.0 if status == "RUNNING" else 0.0,
                "processed_items": None,
                "total_items": None,
                "details": {},
            }
        )
    if current is None:
        current = next(
            (layer["layer_id"] for layer in layers if layer["status"] not in {"COMPLETED", "SKIPPED"}),
            "audit_finalization",
        )
    total_weight = sum(float(layer["weight"]) for layer in layers)
    done = sum(float(layer["weight"]) * float(layer["percent"]) / 100.0 for layer in layers)
    return {
        "status": state.get("status", "UNKNOWN"),
        "current_layer": current,
        "current_layer_name": next(name for layer_id, name, _ in LAYERS if layer_id == current),
        "overall_percent": round((done / total_weight) * 100.0, 2) if total_weight else 0.0,
        "elapsed_seconds": None,
        "eta_seconds": None,
        "eta_utc": None,
        "updated_at_utc": state.get("timestamp_utc"),
        "layers": layers,
        "fallback": True,
    }


payload = load_json(progress_path) if progress_path.exists() else reconstructed_progress()
if payload.get("fallback"):
    print("source: reconstructed from audit/session_state because progress.json is not present")
else:
    print("source: audit/progress.json")
status = str(payload.get("status") or "UNKNOWN")
writer_pid = payload.get("writer_pid")
writer_pid_alive = pid_alive(writer_pid)
if status == "RUNNING":
    live = writer_pid_alive if writer_pid is not None else active_process_present
    effective_status = "LIVE_RUNNING" if live else "ABANDONED_OR_PARTIAL"
elif status == "COMPLETED":
    live = False
    effective_status = "COMPLETED"
elif status in {"FAILED", "PARTIAL"}:
    live = False
    effective_status = status
else:
    live = active_process_present
    effective_status = status
print(f"status: {status}")
print(f"effective_status: {effective_status}")
print(f"live_process: {'yes' if live else 'no'}")
if writer_pid is not None:
    print(f"writer_pid: {writer_pid} alive={'yes' if writer_pid_alive else 'no'}")
if effective_status == "ABANDONED_OR_PARTIAL":
    print("message: Blitz DFIR process interrupted due to no live process updating this RUNNING session.")
    print("operator_action: preserve hashes and logs, then resume from the latest complete checkpoint or rerun. If you want to continue processing, reinitiate the process after fixing the cause.")
print(f"current_layer: {payload.get('current_layer_name')} ({payload.get('current_layer')})")
print(f"overall: {bar(payload.get('overall_percent'))} {payload.get('overall_percent')}%")
print(f"elapsed: {duration(payload.get('elapsed_seconds'))}")
print(f"eta: {duration(payload.get('eta_seconds'))}  eta_utc={payload.get('eta_utc')}")
print(f"updated_utc: {payload.get('updated_at_utc')}")
print()
for layer in payload.get("layers", []):
    status = str(layer.get("status"))
    percent = float(layer.get("percent") or 0.0)
    count = layer_count_text(layer)
    print(f"{icon(status)} {bar(percent)} {percent:6.2f}% {layer.get('name')}{count}")
    details = layer.get("details") or {}
    if status == "RUNNING" and details:
        summary = ", ".join(f"{key}={value}" for key, value in list(details.items())[:6])
        print(f"        {summary}")
PY

echo
echo "[artifact readiness]"
python - "$SESSION" "$PROGRESS" "$RUN_STATUS_PATH" "$POSTRUN_MANIFEST" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

session = Path(sys.argv[1])
progress_path = Path(sys.argv[2])
run_status_path = Path(sys.argv[3]) if sys.argv[3] else None
postrun_manifest_path = Path(sys.argv[4])


def load_json(path: Path | None) -> dict:
    if path is None or not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def exists(relative_path: str) -> bool:
    return (session / relative_path).exists()


def status_word(value: bool) -> str:
    return "ready" if value else "pending"


progress = load_json(progress_path)
state = load_json(session / "audit" / "session_state.json")
run_status = load_json(run_status_path)
postrun = load_json(postrun_manifest_path)
report = load_json(session / "reports" / "report.json")
validation = load_json(session / "findings" / "validation.json")
case_objective = load_json(session / "findings" / "case_objective.json")
investigation_plan = load_json(session / "findings" / "investigation_plan.json")
evidence_triage = load_json(session / "findings" / "evidence_triage.json")

layers = {
    str(layer.get("layer_id")): layer
    for layer in progress.get("layers", [])
    if isinstance(layer, dict)
}
llm_layer = layers.get("bounded_llm_reasoning", {})
report_layer = layers.get("report_generation", {})
agent_trace_layer = layers.get("agent_trace", {})
collated_layer = layers.get("collated_outputs", {})
audit_layer = layers.get("audit_finalization", {})

core_artifacts = {
    "case_objective": "findings/case_objective.json",
    "case_objective_markdown": "reports/case_objective.md",
    "investigation_plan": "findings/investigation_plan.json",
    "investigation_plan_markdown": "reports/investigation_plan.md",
    "investigation_guidance": "findings/investigation_guidance.json",
    "temporal_gap_analysis": "findings/temporal_gap_analysis.json",
    "temporal_gap_analysis_markdown": "reports/temporal_gap_analysis.md",
    "attack_stage_timeline": "findings/attack_stage_timeline.json",
    "attack_stage_timeline_markdown": "reports/attack_stage_timeline.md",
    "evidence_triage": "findings/evidence_triage.json",
    "evidence_triage_markdown": "reports/evidence_triage.md",
    "report_json": "reports/report.json",
    "report_markdown": "reports/report.md",
    "report_html": "reports/report.html",
    "validation": "findings/validation.json",
    "unknowns": "findings/unknowns.json",
    "signal_integrity": "findings/signal_integrity.json",
    "coverage": "findings/coverage.json",
    "evidentiary_weighting": "findings/evidentiary_weighting.json",
    "contradiction_analysis": "findings/contradiction_analysis.json",
    "evidence_maturity": "findings/evidence_maturity.json",
    "evidence_maturity_markdown": "reports/evidence_maturity.md",
    "finding_provenance": "reports/finding_provenance.md",
    "agent_trace": "findings/agent_trace.json",
    "agent_journal": "reports/agent_journal.md",
    "overall_findings": "findings/overall_findings.md",
    "overall_reports": "reports/overall_reports.md",
    "collated_audit": "audit/collated_audit.md",
    "llm_report_verification": "findings/llm_report_verification.json",
    "llm_report_verification_markdown": "reports/llm_report_verification.md",
    "artifact_manifest": "findings/artifact_manifest.json",
}
ready = {name: exists(path) for name, path in core_artifacts.items()}

objective_text = case_objective.get("objective") if isinstance(case_objective.get("objective"), str) else ""
investigation_priorities = (
    investigation_plan.get("prioritized_artifact_families")
    if isinstance(investigation_plan.get("prioritized_artifact_families"), list)
    else []
)
triaged_evidence_ids = (
    evidence_triage.get("prioritized_evidence_ids")
    if isinstance(evidence_triage.get("prioritized_evidence_ids"), list)
    else []
)
reasoning = report.get("inferred_analyst_reasoning") if isinstance(report.get("inferred_analyst_reasoning"), dict) else {}
reasoning_hypotheses = reasoning.get("hypotheses") if isinstance(reasoning.get("hypotheses"), list) else []
reasoning_evidence_type = reasoning.get("evidence_type") if reasoning else None
investigation_guidance = report.get("investigation_guidance") if isinstance(report.get("investigation_guidance"), dict) else {}
temporal_gap_analysis = report.get("temporal_gap_analysis") if isinstance(report.get("temporal_gap_analysis"), dict) else {}
attack_stage_timeline = report.get("attack_stage_timeline") if isinstance(report.get("attack_stage_timeline"), dict) else {}
llm_report_verification = report.get("llm_report_verification") if isinstance(report.get("llm_report_verification"), dict) else {}
truth_validation = report.get("truth_validation") if isinstance(report.get("truth_validation"), dict) else {}
agent_trace = load_json(session / "findings" / "agent_trace.json")

reports_ready = ready["report_json"] and ready["report_markdown"] and ready["report_html"]
objective_ready = ready["case_objective"] and bool(objective_text)
investigation_ready = ready["investigation_plan"] and len(investigation_priorities) > 0
investigation_guidance_ready = ready["investigation_guidance"] and bool(investigation_guidance.get("schema_version"))
temporal_analysis_ready = (
    ready["temporal_gap_analysis"]
    and ready["attack_stage_timeline"]
    and ready["temporal_gap_analysis_markdown"]
    and ready["attack_stage_timeline_markdown"]
    and bool(temporal_gap_analysis.get("schema_version"))
    and bool(attack_stage_timeline.get("schema_version"))
)
evidence_triage_ready = ready["evidence_triage"] and len(triaged_evidence_ids) > 0
safety_ready = (
    ready["validation"]
    and ready["unknowns"]
    and ready["signal_integrity"]
    and ready["coverage"]
    and ready["contradiction_analysis"]
)
trust_artifacts_ready = ready["evidentiary_weighting"] and ready["evidence_maturity"] and ready["finding_provenance"]
agent_trace_ready = ready["agent_trace"] and ready["agent_journal"] and bool(agent_trace.get("schema_version"))
collated_outputs_ready = ready["overall_findings"] and ready["overall_reports"] and ready["collated_audit"]
llm_verification_ready = (
    ready["llm_report_verification"]
    and ready["llm_report_verification_markdown"]
    and bool(llm_report_verification.get("schema_version"))
)
llm_status = str(llm_layer.get("status") or "UNKNOWN")
if llm_status == "SKIPPED":
    llm_readiness = "skipped_by_policy"
elif llm_status == "COMPLETED" and reasoning:
    llm_readiness = "ready"
elif llm_status == "COMPLETED":
    llm_readiness = "completed_but_missing_report_section"
else:
    llm_readiness = "pending"

run_status_value = str(run_status.get("status") or "UNKNOWN")
postrun_default = (
    "NOT_CONFIGURED"
    if run_status_value == "COMPLETED"
    else "UNKNOWN"
)
postrun_status = str(run_status.get("postrun_checks") or postrun.get("status") or postrun_default)
session_completed = str(progress.get("status") or "").upper() == "COMPLETED" or str(state.get("status") or "").upper() == "COMPLETED"
operator_status_stale_complete = bool(run_status) and session_completed and run_status_value not in {"COMPLETED", "FAILED"}
if operator_status_stale_complete and postrun_status == "UNKNOWN":
    postrun_status = "NOT_CONFIGURED"
postrun_ready_map = postrun.get("ready") if isinstance(postrun.get("ready"), dict) else {}
audit_attribution_ready = postrun_status in {"SKIPPED", "NOT_CONFIGURED"} or bool(postrun_ready_map.get("audit_attribution"))
postrun_ready = postrun_status in {"COMPLETED", "SKIPPED", "NOT_CONFIGURED"}
operator_complete = run_status_value == "COMPLETED" or operator_status_stale_complete
all_ready = (
    reports_ready
    and objective_ready
    and investigation_ready
    and investigation_guidance_ready
    and temporal_analysis_ready
    and evidence_triage_ready
    and safety_ready
    and trust_artifacts_ready
    and agent_trace_ready
    and collated_outputs_ready
    and llm_verification_ready
    and ready["artifact_manifest"]
    and postrun_ready
    and (operator_complete or not run_status)
)

print(f"reports_ready: {status_word(reports_ready)}")
print(f"report_generation_layer: {report_layer.get('status', 'UNKNOWN')}")
print(f"case_objective_ready: {status_word(objective_ready)} source={case_objective.get('source', 'unknown')}")
print(f"investigation_priorities_ready: {status_word(investigation_ready)} count={len(investigation_priorities)}")
print(f"investigation_guidance_ready: {status_word(investigation_guidance_ready)} recommendations={len(investigation_guidance.get('recommendations', [])) if isinstance(investigation_guidance.get('recommendations'), list) else 0}")
print(f"temporal_analysis_ready: {status_word(temporal_analysis_ready)} gaps={len(temporal_gap_analysis.get('gaps', [])) if isinstance(temporal_gap_analysis.get('gaps'), list) else 0} stages={attack_stage_timeline.get('stage_count', 0)}")
print(f"evidence_triage_ready: {status_word(evidence_triage_ready)} count={len(triaged_evidence_ids)}")
print(f"bounded_llm_reasoning_layer: {llm_status}")
print(f"bounded_llm_reasoning_ready: {llm_readiness}")
print(f"bounded_llm_reasoning_evidence_type: {reasoning_evidence_type or 'none'}")
if reasoning_evidence_type == "INFERRED":
    print("bounded_llm_reasoning_evidence_type_meaning: LLM narrative is explanatory analysis over bounded summaries only; it is not raw evidence and does not create findings.")
else:
    print("bounded_llm_reasoning_evidence_type_expected_values: INFERRED, none")
print(f"llm_hypothesis_count: {len(reasoning_hypotheses)}")
print(f"llm_report_verification_ready: {status_word(llm_verification_ready)} status={llm_report_verification.get('status', 'missing')}")
print(f"safety_interpretation_ready: {status_word(safety_ready)}")
validation_issues = validation.get("issues") if isinstance(validation.get("issues"), list) else []
print(f"validation_passed: {validation.get('passed', 'unknown')} issue_count={len(validation_issues)}")
if validation_issues:
    severity_counts: dict[str, int] = {}
    type_counts: dict[str, int] = {}
    for issue in validation_issues:
        if not isinstance(issue, dict):
            continue
        severity = str(issue.get("severity") or "UNKNOWN")
        issue_type = str(issue.get("issue_type") or "unknown")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        type_counts[issue_type] = type_counts.get(issue_type, 0) + 1
    print(
        "validation_issue_summary: "
        + ", ".join(f"{key}={value}" for key, value in sorted(severity_counts.items()))
        + " | "
        + ", ".join(f"{key}={value}" for key, value in sorted(type_counts.items()))
    )
    print("validation_issues:")
    for index, issue in enumerate(validation_issues[:20], 1):
        if not isinstance(issue, dict):
            print(f"  {index}. {issue}")
            continue
        severity = issue.get("severity") or "UNKNOWN"
        issue_type = issue.get("issue_type") or "unknown"
        finding_id = issue.get("finding_id") or "case"
        event_ids = issue.get("event_ids") if isinstance(issue.get("event_ids"), list) else []
        event_text = f" events={','.join(str(value) for value in event_ids[:3])}" if event_ids else ""
        message = " ".join(str(issue.get("message") or "").split())
        if len(message) > 220:
            message = message[:217] + "..."
        print(f"  {index}. severity={severity} type={issue_type} finding={finding_id}{event_text} message={message}")
    if len(validation_issues) > 20:
        print(f"  ... {len(validation_issues) - 20} more in findings/validation.json")
print(f"trust_artifacts_ready: {status_word(trust_artifacts_ready)}")
print(f"agent_trace_layer: {agent_trace_layer.get('status', 'UNKNOWN')}")
print(f"agent_trace_ready: {status_word(agent_trace_ready)} findings={((agent_trace.get('summary') or {}).get('finding_count') if isinstance(agent_trace.get('summary'), dict) else 0)} plan_changes={((agent_trace.get('summary') or {}).get('plan_change_count') if isinstance(agent_trace.get('summary'), dict) else 0)}")
print(f"collated_outputs_layer: {collated_layer.get('status', 'UNKNOWN')}")
print(f"collated_outputs_ready: {status_word(collated_outputs_ready)}")
print(f"truth_validation_status: {truth_validation.get('status', 'not_run')}")
print(f"audit_finalization_layer: {audit_layer.get('status', 'UNKNOWN')}")
print(f"artifact_manifest_ready: {status_word(ready['artifact_manifest'])}")
print(f"audit_attribution_ready: {status_word(audit_attribution_ready)}")
print(f"postrun_checks_ready: {status_word(postrun_ready)} status={postrun_status}")
if operator_status_stale_complete:
    print("operator_completion_effective: completed_from_session_state")
    print("operator_completion_note: run_status.json was not finalized, but progress/session_state completed and no active analysis process is required for readiness.")
print(f"judge_review_bundle_ready: {status_word(all_ready)}")

missing = []
for name, path in core_artifacts.items():
    if not ready[name]:
        missing.append(f"{name}: {path}")
if not objective_ready:
    missing.append("case_objective: findings/case_objective.json missing objective")
if not investigation_ready:
    missing.append("investigation_plan: findings/investigation_plan.json has no prioritized artifact families")
if not investigation_guidance_ready:
    missing.append("investigation_guidance: findings/investigation_guidance.json missing or report.json section not synced")
if not temporal_analysis_ready:
    missing.append("temporal_analysis: temporal gap and attack-stage timeline artifacts missing or report.json sections not synced")
if not evidence_triage_ready:
    missing.append("evidence_triage: findings/evidence_triage.json has no prioritized evidence IDs")
if not llm_verification_ready:
    missing.append("llm_report_verification: findings/llm_report_verification.json missing or report.json section not synced")
if llm_readiness in {"pending", "completed_but_missing_report_section"}:
    missing.append("llm_reasoning: reports/report.json inferred_analyst_reasoning not ready")
if not safety_ready:
    missing.append("safety_interpretation: validation/unknowns/signal/coverage/contradiction bundle incomplete")
if not agent_trace_ready:
    missing.append("agent_trace: findings/agent_trace.json or reports/agent_journal.md missing or invalid")
if not collated_outputs_ready:
    missing.append("collated_outputs: overall findings, overall reports, or collated audit missing")
if not audit_attribution_ready:
    missing.append("audit_attribution: postrun audit attribution check artifact missing")
if not postrun_ready:
    missing.append("postrun_checks: supervised postrun checks not complete")
if run_status and not operator_complete:
    missing.append("operator_completion: run_status.json is not COMPLETED")

if missing:
    print("pending_or_missing:")
    for item in missing:
        print(f"  - {item}")
else:
    print("pending_or_missing: none")
PY

echo
echo "[evidence category proof]"
python - "$SESSION" <<'PY'
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

session = Path(sys.argv[1])


def load_json(path: Path | None) -> dict:
    if path is None or not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def audit_entries() -> list[dict]:
    entries: list[dict] = []
    for audit_path in sorted((session / "audit").glob("*.ndjson")):
        for line in audit_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                entries.append(value)
    return entries


manifest_evidence: list[dict] = []
for entry in audit_entries():
    if entry.get("event_type") != "manifest_loaded":
        continue
    data = entry.get("data") if isinstance(entry.get("data"), dict) else {}
    evidence = data.get("evidence")
    if isinstance(evidence, list):
        manifest_evidence = [item for item in evidence if isinstance(item, dict)]

print("manifest_registered_evidence:")
if manifest_evidence:
    print(f"{'Evidence ID':<24} {'Evidence Type':<16} {'Category':<10} {'Pipeline':<10} {'Trust Tier':<22} Verified")
    print(f"{'-' * 24} {'-' * 16} {'-' * 10} {'-' * 10} {'-' * 22} {'-' * 8}")
    for item in manifest_evidence:
        print(
            f"{str(item.get('evidence_id', '')):<24} "
            f"{str(item.get('evidence_type', '')):<16} "
            f"{str(item.get('category', '')):<10} "
            f"{str(item.get('pipeline', '')):<10} "
            f"{str(item.get('trust_tier', '')):<22} "
            f"{item.get('verified')}"
        )
else:
    print("  unavailable: manifest_loaded audit event not found")

print()
print("normalized_event_category_counts:")
store = session / "findings" / "event_store.sqlite"
if not store.exists():
    print(f"  pending: {store}")
else:
    try:
        connection = sqlite3.connect(f"file:{store}?mode=ro", uri=True, timeout=1)
        try:
            table_exists = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='normalized_events'"
            ).fetchone()
            if not table_exists:
                print("  pending: normalized_events table not found")
            else:
                rows = connection.execute(
                    """
                    SELECT evidence_id, evidence_type, trust_level, COUNT(*)
                    FROM normalized_events
                    GROUP BY evidence_id, evidence_type, trust_level
                    ORDER BY evidence_id, evidence_type, trust_level
                    """
                ).fetchall()
                if not rows:
                    print("  no normalized rows recorded yet")
                else:
                    print(f"{'Evidence ID':<24} {'Event Category':<14} {'Trust Level':<22} Rows")
                    print(f"{'-' * 24} {'-' * 14} {'-' * 22} {'-' * 8}")
                    for evidence_id, category, trust_level, count in rows:
                        print(f"{str(evidence_id):<24} {str(category):<14} {str(trust_level):<22} {count}")
        finally:
            connection.close()
    except sqlite3.Error as exc:
        print(f"  unavailable: SQLite read failed: {exc}")

report = load_json(session / "reports" / "report.json")
reasoning = report.get("inferred_analyst_reasoning") if isinstance(report.get("inferred_analyst_reasoning"), dict) else {}
print()
print("bounded_llm_reasoning_category:")
if reasoning:
    print(f"  evidence_type={reasoning.get('evidence_type', 'unknown')}")
    print("  meaning=reasoning/hypotheses only; separate from manifest evidence and normalized event categories")
else:
    print("  none or skipped")
PY

echo
echo "[review map]"
python - "$SESSION" "$MATCHED_RUN_ROOT" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path

session = Path(sys.argv[1])
run_root = Path(sys.argv[2]) if sys.argv[2] else None

review_paths = (
    ("Final report HTML", "reports/report.html"),
    ("Final report Markdown", "reports/report.md"),
    ("Final report JSON", "reports/report.json"),
    ("LLM reasoning", "reports/report.json -> inferred_analyst_reasoning"),
    ("Case objective", "reports/case_objective.md"),
    ("Investigation plan", "reports/investigation_plan.md"),
    ("Investigation guidance", "findings/investigation_guidance.json"),
    ("Temporal gap analysis", "reports/temporal_gap_analysis.md"),
    ("Attack-stage timeline", "reports/attack_stage_timeline.md"),
    ("Evidence triage", "reports/evidence_triage.md"),
    ("Correlation findings and scoring", "reports/report.json -> findings"),
    ("Truth validation", "reports/report.json -> truth_validation"),
    ("LLM report verification", "findings/llm_report_verification.json"),
    ("Evidentiary weighting", "reports/evidentiary_weighting.md"),
    ("Contradiction analysis", "reports/contradiction_analysis.md"),
    ("Evidence traceability", "reports/evidence_maturity.md"),
    ("Finding provenance visualization", "reports/finding_provenance.md"),
    ("Agent trace JSON", "findings/agent_trace.json"),
    ("Agent journal", "reports/agent_journal.md"),
    ("Overall findings", "findings/overall_findings.md"),
    ("Overall reports", "reports/overall_reports.md"),
    ("Collated audit", "audit/collated_audit.md"),
    ("Audit progress", "audit/progress.json"),
    ("Session state", "audit/session_state.json"),
    ("Audit event log", f"audit/{session.name}.ndjson"),
    ("Artifact hashes", "findings/artifact_manifest.json"),
    ("Normalized event sample", "findings/normalized_events.json"),
    ("SQLite normalized event store", "findings/event_store.sqlite"),
    ("Parser results", "findings/parser_results.json"),
    ("Tool results", "findings/tool_results.json"),
    ("Coverage and unknowns", "findings/coverage.json + findings/unknowns.json"),
    ("Validation and signal integrity", "findings/validation.json + findings/signal_integrity.json"),
)

print(f"session_root: {session}")
if run_root:
    print(f"run_bundle: {run_root}")
print(f"{'Layer / Review Target':<34} Path")
print(f"{'-' * 34} {'-' * 80}")
for label, relative in review_paths:
    if " -> " in relative or " + " in relative:
        print(f"{label:<34} {session / relative.split(' -> ')[0].split(' + ')[0]} ({relative})")
    else:
        exists = "ready" if (session / relative).exists() else "missing"
        print(f"{label:<34} {session / relative} [{exists}]")
PY

echo
echo "[session state]"
python - "$STATE" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.exists():
    print("session_state.json not found yet")
    raise SystemExit
payload = json.loads(path.read_text(encoding="utf-8"))
for key in ("status", "phase", "timestamp_utc", "session_id"):
    print(f"{key}: {payload.get(key)}")
details = payload.get("details") or {}
if details:
    print("details:")
    for key, value in details.items():
        print(f"  {key}: {value}")
PY

echo
echo "[recent audit checkpoints]"
python - "$SESSION" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

session = Path(sys.argv[1])
entries = []
for audit_path in sorted((session / "audit").glob("*.ndjson")):
    for line in audit_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        entries.append(payload)


def infer_initiator(event_type: str, data: dict) -> str:
    tool = str(data.get("typed_tool") or data.get("tool") or data.get("tool_name") or "")
    parser = str(data.get("parser") or "")
    provider = str(data.get("provider") or "")
    model = str(data.get("model") or "")
    llm = "/".join(part for part in (provider, model) if part)
    if event_type in {"manifest_loaded", "evidence_verified"}:
        return "Blitz DFIR manifest/integrity gate"
    if event_type == "analysis_started":
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
    if event_type == "temporal_analysis_completed":
        return "Blitz temporal analysis layer"
    if event_type in {"validation_completed", "validation_report"}:
        return "Blitz validation engine"
    if event_type in {"unknowns_completed", "coverage_scores"}:
        return "Blitz unknowns and coverage engine"
    if event_type == "evidence_maturity_written":
        return "Blitz evidence maturity traceability layer"
    if event_type == "agent_trace_written":
        return "Blitz agent trace and journal layer"
    if event_type in {"artifact_manifest_written", "reports_written"}:
        return "Blitz reporting/audit finalizer"
    if event_type == "analysis_completed":
        return "Blitz DFIR orchestrator"
    if event_type in {"batch_started", "batch_completed", "batch_task_skipped"}:
        return "Blitz DFIR batch planner"
    if event_type in {"tool_request_validated", "tool_request_completed", "tool_request_rejected"}:
        return f"Blitz MCP dispatcher -> {tool or 'typed tool'}"
    if event_type in {"analysis_tool_result", "tool_execution", "analysis_tool_failed"}:
        return f"SIFT tool adapter: {tool or 'unknown'}"
    if event_type in {"parser_completed", "parser_result"}:
        return f"Blitz parser: {parser or 'unknown'}"
    if event_type in {"normalization_completed", "sqlite_normalization_completed"}:
        return "Blitz normalization engine"
    if event_type in {"reasoning_completed", "agent_decision"}:
        return f"Bounded LLM reasoning: {llm or 'configured provider'}"
    if event_type == "llm_report_verification_completed":
        return "Blitz LLM report verification gate"
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


def infer_component(event_type: str, data: dict) -> str:
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
    if event_type == "temporal_analysis_completed":
        return "temporal_analysis_layer"
    if event_type.startswith("reasoning") or event_type == "agent_decision":
        return "bounded_llm_reasoning_layer"
    if event_type == "llm_report_verification_completed":
        return "llm_report_verification_layer"
    if event_type == "agent_trace_written":
        return "agent_trace_layer"
    if event_type in {"report_generation_completed", "reports_written", "evidence_maturity_written", "artifact_manifest_written"}:
        return "reporting_audit_layer"
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


def infer_trust_boundary(event_type: str, data: dict) -> str:
    if event_type in {"tool_request_validated", "tool_request_completed", "tool_request_rejected"}:
        return "MCP typed allowlist"
    if event_type in {"analysis_tool_result", "tool_execution", "analysis_tool_failed"}:
        return "SIFT tool subprocess sandbox"
    if event_type in {"reasoning_completed", "agent_decision"}:
        return "bounded summaries only; no raw evidence"
    if event_type == "llm_report_verification_completed":
        return "bounded summaries verified against normalized event IDs"
    if event_type == "agent_trace_written":
        return "deterministic audit and report artifacts; no raw evidence or raw tool output"
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


def int_value(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def float_value(value: object) -> float:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return 1.0


def success_exit_code(value: object) -> bool:
    if value is None:
        return True
    if isinstance(value, bool):
        return False
    try:
        return int(str(value)) == 0
    except (TypeError, ValueError):
        return False


def infer_behavior(event_type: str, data: dict) -> str:
    if event_type == "tool_request_rejected":
        return "security_relevant_rejection"
    if event_type in {"analysis_tool_failed", "resume_tool_result_skipped"}:
        return "unexpected_or_degraded"
    if data.get("timed_out") is True:
        return "degraded_timeout"
    if not success_exit_code(data.get("exit_code")):
        return "degraded_nonzero_exit"
    if event_type == "tool_discovery_completed" and (
        int_value(data.get("missing_count")) > 0 or int_value(data.get("hash_mismatch_count")) > 0
    ):
        return "environment_degraded"
    if event_type == "evidence_inventory_completed" and (
        int_value(data.get("high_or_critical_risk_count")) > 0 or int_value(data.get("unavailable_tool_count")) > 0
    ):
        return "analyst_review_required"
    if event_type == "recovery_plan_created" and int_value(data.get("blocked_candidate_count")) > 0:
        return "manual_review_required"
    if event_type in {"batch_task_skipped", "reasoning_skipped"}:
        return "expected_skip_or_disabled"
    if event_type in {"hypothesis_formed", "plan_change"}:
        return "investigative_adaptation_recorded"
    if event_type == "temporal_analysis_completed":
        return "temporal_coverage_receipt"
    if event_type == "llm_report_verification_completed" and str(data.get("status") or "") in {"failed", "needs_review"}:
        return "analyst_review_required"
    if event_type == "llm_report_verification_completed":
        return "bounded_llm_output_verified"
    if event_type == "agent_trace_written":
        return "judge_traceability_artifact_written"
    if event_type == "analysis_scope_limited":
        return "bounded_scope_limit"
    if event_type in {"validation_completed", "validation_report"} and (
        data.get("passed") is False or int_value(data.get("issue_count")) > 0
    ):
        return "validation_issues_detected"
    if event_type == "unknowns_completed" and (
        int_value(data.get("critical_count")) > 0 or int_value(data.get("high_count")) > 0
    ):
        return "analyst_review_required"
    if event_type == "coverage_scores" and float_value(data.get("overall_case_coverage")) < 1.0:
        return "coverage_gap"
    if event_type == "integrity_check" and data.get("verified") is False:
        return "integrity_warning"
    if event_type in {"correction_attempt", "correction_history", "correction_outcome", "rerun_trigger"}:
        return "self_correction_or_recovery"
    return "expected"


for item in entries[-14:]:
    data = item.get("data") if isinstance(item.get("data"), dict) else {}
    event_type = str(item.get("event_type") or "")
    initiated_by = str(data.get("initiated_by") or infer_initiator(event_type, data))
    component = str(data.get("component") or infer_component(event_type, data))
    behavior = str(data.get("behavior") or infer_behavior(event_type, data))
    trust_boundary = str(data.get("trust_boundary") or infer_trust_boundary(event_type, data))
    summary_keys = (
        "backend",
        "tool_count",
        "available_count",
        "missing_count",
        "hash_mismatch_count",
        "batch_count",
        "task_count",
        "evidence_count",
        "event_count",
        "normalized_event_count",
        "analysis_event_count",
        "rows_scanned",
        "candidate_count",
        "support_event_count",
        "finding_count",
        "object_count",
        "total_rows",
        "artifact_count",
        "evidence_id",
        "typed_tool",
        "tool",
        "tool_name",
        "parser",
        "exit_code",
        "timed_out",
        "reason",
        "exception_type",
        "blitz_error",
        "check_type",
        "verified",
        "provider",
        "model",
        "prompt_hash",
        "hypothesis_count",
        "passed",
        "issue_count",
        "trigger_count",
        "unknown_count",
        "critical_count",
        "high_count",
        "traceable_finding_count",
        "evidence_hashes_preserved",
    )
    summary = " ".join(f"{key}={data[key]}" for key in summary_keys if key in data)
    flags = []
    if behavior != "expected":
        flags.append(f"behavior={behavior}")
    if trust_boundary:
        flags.append(f"boundary={trust_boundary}")
    suffix = " ".join(flags)
    print(
        f"{item.get('sequence')}: {item.get('timestamp_utc')} {event_type} "
        f"({initiated_by}; component={component}) {summary} {suffix}".rstrip()
    )
PY

echo
echo "[key output sizes]"
find "$SESSION" -maxdepth 3 -type f \
  -printf '%TY-%Tm-%Td %TH:%TM:%TS %12s %p\n' 2>/dev/null \
  | sort | tail -30

echo
echo "[resources]"
free -h || true
{
  df -h "/cases/${CASE}" / 2>/dev/null || df -h / 2>/dev/null || true
} | awk 'NR == 1 { print; next } !seen[$1 "|" $6]++'

if [ "${SUPPRESS_OPERATOR_RESULT}" != "1" ]; then
  echo
  echo "[operator result]"
  python - "$PROGRESS" "$STATE" "$RUN_STATUS_PATH" "$POSTRUN_MANIFEST" "$ACTIVE_PROCESS_PRESENT" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

progress_path = Path(sys.argv[1])
state_path = Path(sys.argv[2])
run_status_path = Path(sys.argv[3]) if sys.argv[3] else None
postrun_manifest_path = Path(sys.argv[4])
active_process_present = sys.argv[5] == "1"


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


progress = load_json(progress_path)
state = load_json(state_path)
run_status = load_json(run_status_path)
postrun = load_json(postrun_manifest_path)

if run_status:
    operator_status = str(run_status.get("status") or "UNKNOWN")
    phase = str(run_status.get("phase") or "unknown")
    postrun_default = (
        "NOT_CONFIGURED"
        if operator_status == "COMPLETED"
        else "UNKNOWN"
    )
    postrun_status = str(run_status.get("postrun_checks") or postrun.get("status") or postrun_default)
    session_completed = str(progress.get("status") or "").upper() == "COMPLETED" or str(
        state.get("status") or ""
    ).upper() == "COMPLETED"
    if session_completed and operator_status not in {"COMPLETED", "FAILED"} and postrun_status == "UNKNOWN":
        postrun_status = "NOT_CONFIGURED"
    if operator_status == "COMPLETED" and postrun_status in {"COMPLETED", "SKIPPED", "NOT_CONFIGURED"}:
        print("Blitz DFIR supervised run completed; prompt returned or is returning")
    elif operator_status == "FAILED":
        print(f"Blitz DFIR supervised run failed: phase={phase} postrun={postrun_status}")
    elif session_completed and not active_process_present:
        print(
            "Blitz DFIR analysis session completed; supervised run_status.json was not finalized "
            f"after terminal interruption: phase={phase} postrun={postrun_status}"
        )
    elif active_process_present or operator_status == "RUNNING":
        print(f"Blitz DFIR analysis/session progress is not the final operator state: phase={phase} postrun={postrun_status}")
    else:
        print(f"Blitz DFIR supervised run status is unresolved: phase={phase} postrun={postrun_status}")
    raise SystemExit

status = str(progress.get("status") or state.get("status") or "UNKNOWN")
state_status = str(state.get("status") or "UNKNOWN")
if status == "COMPLETED" or state_status == "COMPLETED":
    print("Blitz DFIR analysis session completed; supervised run status unavailable")
elif status in {"FAILED", "PARTIAL"} or state_status in {"FAILED", "PARTIAL"}:
    print(f"Blitz DFIR analysis session did not complete cleanly: {status}")
elif active_process_present:
    print("Blitz DFIR Process still running")
else:
    print("Blitz DFIR Process is not actively running; inspect effective_status above before resuming or rerunning")
PY
fi
