#!/usr/bin/env bash
set -euo pipefail

CASE="${CASE:-BLITZ-RD01-PLASO}"
WORKDIR="${WORKDIR:-/home/sansforensics/src/Blitz_DFIR}"
PYTHON="${PYTHON:-${WORKDIR}/.venv/bin/python}"
CASE_ROOT="/cases/${CASE}"
MANIFEST="${MANIFEST:-${CASE_ROOT}/case.yaml}"
CASE_OBJECTIVE="${CASE_OBJECTIVE:-}"
PLASO="${PLASO:-${CASE_ROOT}/processed/case.plaso}"
TOOL_CONFIG="${TOOL_CONFIG:-${WORKDIR}/config/tools.yaml}"
OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-http://192.168.88.1:11434}"
LLM_PROVIDER="${LLM_PROVIDER:-ollama}"
LLM_BASE_URL="${LLM_BASE_URL:-${OLLAMA_BASE_URL%/}/v1}"
LLM_API_KEY="${LLM_API_KEY:-ollama}"
LLM_MODEL="${LLM_MODEL:-llama3.2:1b}"
LLM_TIMEOUT_SECONDS="${LLM_TIMEOUT_SECONDS:-600}"
LLM_MAX_TOKENS="${LLM_MAX_TOKENS:-800}"
LLM_RESPONSE_FORMAT_JSON="${LLM_RESPONSE_FORMAT_JSON:-1}"
BLITZ_AGENT_FRAMEWORK="${BLITZ_AGENT_FRAMEWORK:-Protocol SIFT SIFT-VM launcher}"
ENABLE_REASONING="${ENABLE_REASONING:-1}"
MAX_NORMALIZED_EVENTS="${MAX_NORMALIZED_EVENTS:-2000000}"
MAX_ANALYSIS_EVENTS="${MAX_ANALYSIS_EVENTS:-100000}"
SQLITE_ANALYSIS_EVENT_MEMORY_LIMIT="${SQLITE_ANALYSIS_EVENT_MEMORY_LIMIT:-${BLITZ_SQLITE_ANALYSIS_EVENT_MEMORY_LIMIT:-50000}}"
SQLITE_NORMALIZATION_CHECKPOINT_INTERVAL="${SQLITE_NORMALIZATION_CHECKPOINT_INTERVAL:-${BLITZ_SQLITE_NORMALIZATION_CHECKPOINT_INTERVAL:-100000}}"
REPORT_EVENT_LIMIT="${REPORT_EVENT_LIMIT:-5000}"
REPORT_FINDING_LIMIT="${REPORT_FINDING_LIMIT:-500}"
NORMALIZED_EXPORT_LIMIT="${NORMALIZED_EXPORT_LIMIT:-10000}"
PARSER_RECORD_EXPORT_LIMIT="${PARSER_RECORD_EXPORT_LIMIT:-1000}"
PSORT_PROFILE="${PSORT_PROFILE:-triage}"
PSORT_FILTER="${PSORT_FILTER:-data_type contains 'windows:evtx'}"
TOOL_TIMEOUT="${TOOL_TIMEOUT:-7200}"
MIN_FREE_GB="${MIN_FREE_GB:-20}"
NICE_LEVEL="${NICE_LEVEL:-10}"
FORCE="${FORCE:-0}"
RESUME_SESSION="${RESUME_SESSION:-}"
OLLAMA_TAGS_TIMEOUT="${OLLAMA_TAGS_TIMEOUT:-30}"
OLLAMA_GENERATE_TIMEOUT="${OLLAMA_GENERATE_TIMEOUT:-600}"
OLLAMA_CHAT_TIMEOUT="${OLLAMA_CHAT_TIMEOUT:-600}"
OLLAMA_KEEP_ALIVE="${OLLAMA_KEEP_ALIVE:-30m}"
OLLAMA_KEEPALIVE_INTERVAL_SECONDS="${OLLAMA_KEEPALIVE_INTERVAL_SECONDS:-600}"
WAIT_FOR_COMPLETION="${WAIT_FOR_COMPLETION:-1}"
RUN_MAX_WAIT_SECONDS="${RUN_MAX_WAIT_SECONDS:-14400}"
MONITOR_INTERVAL="${MONITOR_INTERVAL:-60}"
POSTRUN_CHECKS="${POSTRUN_CHECKS:-1}"
CLEANUP_GRACE_SECONDS="${CLEANUP_GRACE_SECONDS:-15}"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
ANALYSIS_DIR="${CASE_ROOT}/analysis"
RUN_ROOT="${RUN_ROOT:-${ANALYSIS_DIR}/runs/${RUN_ID}}"
LOG="${RUN_ROOT}/launcher.log"
PIDFILE="${RUN_ROOT}/blitz.pid"
RUN_STATUS="${RUN_ROOT}/run_status.json"
TOP_LOG="${ANALYSIS_DIR}/blitz_e2e_ollama_${RUN_ID}.log"
TOP_PIDFILE="${ANALYSIS_DIR}/blitz_e2e_ollama_${RUN_ID}.pid"
PROCESS_PATTERN='app.py analyze|psort.py|log2timeline.py|psteal.py|case.plaso'
OLLAMA_KEEPALIVE_PID=""

terminate_run_process() {
  local pid="$1"
  local process_group="$2"

  if ! kill -0 "${pid}" 2>/dev/null; then
    return 0
  fi

  echo "[supervised cleanup]"
  echo "terminating_pid=${pid}"
  echo "process_group=${process_group}"
  if [[ "${process_group}" == "1" ]]; then
    kill -TERM "-${pid}" 2>/dev/null || kill -TERM "${pid}" 2>/dev/null || true
  else
    kill -TERM "${pid}" 2>/dev/null || true
  fi
  sleep "${CLEANUP_GRACE_SECONDS}"

  if kill -0 "${pid}" 2>/dev/null; then
    echo "force_kill_pid=${pid}"
    if [[ "${process_group}" == "1" ]]; then
      kill -KILL "-${pid}" 2>/dev/null || kill -KILL "${pid}" 2>/dev/null || true
    else
      kill -KILL "${pid}" 2>/dev/null || true
    fi
  fi
}

mkdir -p "${ANALYSIS_DIR}" "${RUN_ROOT}"

write_run_status() {
  local status="$1"
  local phase="$2"
  local analysis_exit="${3:-}"
  local postrun_status="${4:-}"
  local message="${5:-}"

  python3 - \
    "${RUN_STATUS}" \
    "${CASE}" \
    "${RUN_ID}" \
    "${RUN_ROOT}" \
    "${PIDFILE}" \
    "${status}" \
    "${phase}" \
    "${analysis_exit}" \
    "${postrun_status}" \
    "${message}" \
    "${WAIT_FOR_COMPLETION}" \
    "${POSTRUN_CHECKS}" \
    "$$" <<'PY'
from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

path = Path(sys.argv[1])
case = sys.argv[2]
run_id = sys.argv[3]
run_root = sys.argv[4]
pidfile = Path(sys.argv[5])
status = sys.argv[6]
phase = sys.argv[7]
analysis_exit = sys.argv[8]
postrun_status = sys.argv[9]
message = sys.argv[10]
wait_for_completion = sys.argv[11]
postrun_checks = sys.argv[12]
supervisor_pid = int(sys.argv[13])

existing = {}
if path.exists():
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            existing = loaded
    except json.JSONDecodeError:
        existing = {}

session_path = Path(run_root) / "session_path.txt"
pid = None
if pidfile.exists():
    try:
        pid = int(pidfile.read_text(encoding="utf-8").strip())
    except ValueError:
        pid = None

payload = dict(existing)
payload.update(
    {
        "schema_version": "blitz-run-status.v1",
        "case_id": case,
        "run_id": run_id,
        "run_root": run_root,
        "status": status,
        "phase": phase,
        "updated_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "supervisor_pid": supervisor_pid,
        "status_writer_pid": os.getpid(),
        "analysis_pid": pid,
        "wait_for_completion": wait_for_completion == "1",
        "postrun_checks_enabled": postrun_checks == "1",
    }
)
if session_path.exists():
    payload["session"] = session_path.read_text(encoding="utf-8").strip()
if analysis_exit:
    payload["analysis_exit_code"] = int(analysis_exit)
if postrun_status:
    payload["postrun_checks"] = postrun_status
if message:
    payload["message"] = message

path.parent.mkdir(parents=True, exist_ok=True)
tmp = path.with_suffix(path.suffix + ".tmp")
tmp.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
tmp.replace(path)
PY
}

df_unique() {
  {
    df -h "$@" 2>/dev/null || df -h / 2>/dev/null || true
  } | awk 'NR == 1 { print; next } !seen[$1 "|" $6]++'
}

start_ollama_keepalive() {
  [[ "${ENABLE_REASONING}" == "1" ]] || return 0
  local keepalive_log="${RUN_ROOT}/ollama_keepalive.log"
  (
    while true; do
      date -u +"ollama_keepalive_utc=%Y-%m-%dT%H:%M:%SZ"
      "${PYTHON}" - "${OLLAMA_BASE_URL}" "${LLM_MODEL}" "${OLLAMA_KEEP_ALIVE}" <<'PY' || true
from __future__ import annotations

import json
import sys
import time
import urllib.request

base_url = sys.argv[1].rstrip("/")
model = sys.argv[2]
keep_alive = sys.argv[3]
payload = {"model": model, "prompt": "", "stream": False, "keep_alive": keep_alive}
request = urllib.request.Request(
    f"{base_url}/api/generate",
    data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
    headers={"Accept": "application/json", "Content-Type": "application/json"},
    method="POST",
)
started = time.monotonic()
with urllib.request.urlopen(request, timeout=120) as response:
    result = json.loads(response.read().decode("utf-8"))
elapsed = time.monotonic() - started
load_duration = result.get("load_duration")
print(f"ollama_keepalive=ok elapsed_seconds={elapsed:.1f} keep_alive={keep_alive}")
if isinstance(load_duration, int):
    print(f"ollama_keepalive_load_duration_ms={load_duration / 1_000_000:.1f}")
PY
      sleep "${OLLAMA_KEEPALIVE_INTERVAL_SECONDS}"
    done
  ) >> "${keepalive_log}" 2>&1 &
  OLLAMA_KEEPALIVE_PID="$!"
  echo "${OLLAMA_KEEPALIVE_PID}" > "${RUN_ROOT}/ollama_keepalive.pid"
  echo "ollama_keepalive_started pid=${OLLAMA_KEEPALIVE_PID} interval_seconds=${OLLAMA_KEEPALIVE_INTERVAL_SECONDS} log=${keepalive_log}" | tee -a "${LOG}"
}

stop_ollama_keepalive() {
  if [[ -n "${OLLAMA_KEEPALIVE_PID}" ]]; then
    kill "${OLLAMA_KEEPALIVE_PID}" 2>/dev/null || true
    wait "${OLLAMA_KEEPALIVE_PID}" 2>/dev/null || true
    OLLAMA_KEEPALIVE_PID=""
  fi
}

trap stop_ollama_keepalive EXIT

if [[ ! -d "${WORKDIR}" ]]; then
  echo "workdir not found: ${WORKDIR}" >&2
  exit 2
fi
if [[ ! -x "${PYTHON}" ]]; then
  echo "python not found or not executable: ${PYTHON}" >&2
  exit 2
fi
if [[ ! -f "${MANIFEST}" ]]; then
  echo "manifest not found: ${MANIFEST}" >&2
  exit 2
fi
if [[ ! -f "${PLASO}" ]]; then
  echo "PLASO evidence not found: ${PLASO}" >&2
  exit 2
fi
if [[ ! -f "${TOOL_CONFIG}" ]]; then
  echo "tool config not found: ${TOOL_CONFIG}" >&2
  exit 2
fi
if [[ -n "${RESUME_SESSION}" ]]; then
  if [[ ! -d "${RESUME_SESSION}" ]]; then
    echo "resume session not found: ${RESUME_SESSION}" >&2
    exit 2
  fi
  if [[ ! -f "${RESUME_SESSION}/findings/tool_results.json" ]] \
    && ! grep -q '"event_type":"analysis_tool_result"' "${RESUME_SESSION}"/audit/*.ndjson 2>/dev/null; then
    echo "resume session has no completed typed tool results; rerun from the beginning instead: ${RESUME_SESSION}" >&2
    exit 2
  fi
fi

ACTIVE_PROCESSES="$(ps -eo pid,ppid,stat,etime,%mem,%cpu,cmd | egrep "${PROCESS_PATTERN}" | grep -v grep || true)"
if [[ -n "${ACTIVE_PROCESSES}" && "${FORCE}" != "1" ]]; then
  echo "[active Blitz/SIFT processes]"
  echo "${ACTIVE_PROCESSES}"
  echo
  echo "refusing to start another E2E run while analysis/tool work is active. Set FORCE=1 only after confirming this is safe." >&2
  exit 3
fi

FREE_GB="$(df -BG "${CASE_ROOT}" | awk 'NR==2 {gsub(/G/, "", $4); print $4}')"
if [[ -n "${FREE_GB}" && "${FREE_GB}" -lt "${MIN_FREE_GB}" ]]; then
  echo "free space below threshold: free_gb=${FREE_GB} min_free_gb=${MIN_FREE_GB}" >&2
  exit 4
fi

{
  echo "[scope]"
  echo "case=${CASE}"
  echo "run_id=${RUN_ID}"
  echo "run_root=${RUN_ROOT}"
  echo "workdir=${WORKDIR}"
  echo "manifest=${MANIFEST}"
  echo "case_objective=${CASE_OBJECTIVE:-default_evidence_first}"
  echo "tool_config=${TOOL_CONFIG}"
  echo "plaso=${PLASO}"
  echo "resume_session=${RESUME_SESSION:-none}"
  echo "ollama_base_url=${OLLAMA_BASE_URL}"
  echo "llm_provider=${LLM_PROVIDER}"
  echo "llm_base_url=${LLM_BASE_URL}"
  echo "llm_model=${LLM_MODEL}"
  echo "llm_timeout_seconds=${LLM_TIMEOUT_SECONDS}"
  echo "llm_max_tokens=${LLM_MAX_TOKENS}"
  echo "llm_response_format_json=${LLM_RESPONSE_FORMAT_JSON}"
  echo "ollama_keep_alive=${OLLAMA_KEEP_ALIVE}"
  echo "blitz_agent_framework=${BLITZ_AGENT_FRAMEWORK}"
  echo "enable_reasoning=${ENABLE_REASONING}"
  echo "max_normalized_events=${MAX_NORMALIZED_EVENTS}"
  echo "max_analysis_events=${MAX_ANALYSIS_EVENTS}"
  echo "sqlite_analysis_event_memory_limit=${SQLITE_ANALYSIS_EVENT_MEMORY_LIMIT}"
  echo "sqlite_normalization_checkpoint_interval=${SQLITE_NORMALIZATION_CHECKPOINT_INTERVAL}"
  echo "full_sql_correlation=1"
  echo "report_event_limit=${REPORT_EVENT_LIMIT}"
  echo "report_finding_limit=${REPORT_FINDING_LIMIT}"
  echo "normalized_export_limit=${NORMALIZED_EXPORT_LIMIT}"
  echo "parser_record_export_limit=${PARSER_RECORD_EXPORT_LIMIT}"
  echo "psort_profile=${PSORT_PROFILE}"
  echo "psort_filter=${PSORT_FILTER:-none}"
  echo "ollama_tags_timeout=${OLLAMA_TAGS_TIMEOUT}"
  echo "ollama_generate_timeout=${OLLAMA_GENERATE_TIMEOUT}"
  echo "ollama_chat_timeout=${OLLAMA_CHAT_TIMEOUT}"
  echo "ollama_keepalive_interval_seconds=${OLLAMA_KEEPALIVE_INTERVAL_SECONDS}"
  echo "wait_for_completion=${WAIT_FOR_COMPLETION}"
  echo "run_max_wait_seconds=${RUN_MAX_WAIT_SECONDS}"
  echo "monitor_interval=${MONITOR_INTERVAL}"
  echo "postrun_checks=${POSTRUN_CHECKS}"
  echo "cleanup_grace_seconds=${CLEANUP_GRACE_SECONDS}"

  echo
  echo "[disk before]"
  df_unique "${CASE_ROOT}" /

  echo
  echo "[memory before]"
  free -h

  echo
  echo "[before evidence hash]"
  sha256sum "${PLASO}"

  echo
  echo "[ollama preflight]"
  "${PYTHON}" - \
    "${OLLAMA_BASE_URL}" \
    "${LLM_MODEL}" \
    "${OLLAMA_TAGS_TIMEOUT}" \
    "${OLLAMA_GENERATE_TIMEOUT}" \
    "${OLLAMA_CHAT_TIMEOUT}" \
    "${OLLAMA_KEEP_ALIVE}" <<'PY'
from __future__ import annotations

import json
import socket
import sys
import time
import urllib.error
import urllib.request

base_url = sys.argv[1].rstrip("/")
model = sys.argv[2]
tags_timeout = int(sys.argv[3])
generate_timeout = int(sys.argv[4])
chat_timeout = int(sys.argv[5])
keep_alive = sys.argv[6]


def request_json(url: str, payload: dict | None = None, timeout: int = 120) -> dict:
    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": "Bearer ollama",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        method="GET" if payload is None else "POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def timed_request_json(step: str, url: str, payload: dict | None = None, timeout: int = 120) -> dict:
    started = time.monotonic()
    result = request_json(url, payload, timeout=timeout)
    elapsed = time.monotonic() - started
    print(f"{step}_elapsed_seconds={elapsed:.1f}")
    for field in ("total_duration", "load_duration", "prompt_eval_duration", "eval_duration"):
        value = result.get(field)
        if isinstance(value, int):
            print(f"{step}_{field}_ms={value / 1_000_000:.1f}")
    return result


def fail(step: str, exc: BaseException) -> None:
    print(f"{step}=failed error={exc}")
    print(f"ollama_preflight=failed step={step}")
    raise SystemExit(5)


try:
    tags = timed_request_json("ollama_tags", f"{base_url}/api/tags", timeout=tags_timeout)
    models = [item.get("name") for item in tags.get("models", []) if isinstance(item, dict)]
    print(f"ollama_tags=ok model_count={len(models)}")
    print("ollama_models=" + ", ".join(str(name) for name in models[:10]))
except (OSError, urllib.error.URLError, json.JSONDecodeError, socket.timeout) as exc:
    fail("ollama_tags", exc)

try:
    generated = timed_request_json(
        "ollama_generate",
        f"{base_url}/api/generate",
        {"model": model, "prompt": "Reply with exactly: pong", "stream": False, "keep_alive": keep_alive},
        timeout=generate_timeout,
    )
    print(f"ollama_generate=ok response={str(generated.get('response', ''))[:80]!r}")
except (OSError, urllib.error.URLError, json.JSONDecodeError, socket.timeout) as exc:
    fail("ollama_generate", exc)

try:
    chat = timed_request_json(
        "openai_compat_chat",
        f"{base_url}/v1/chat/completions",
        {
            "model": model,
            "messages": [{"role": "user", "content": "Return a JSON object with key status and value pong."}],
            "temperature": 0,
            "max_tokens": 16,
            "response_format": {"type": "json_object"},
        },
        timeout=chat_timeout,
    )
    choices = chat.get("choices") if isinstance(chat, dict) else None
    content = ""
    if isinstance(choices, list) and choices:
        message = choices[0].get("message") if isinstance(choices[0], dict) else None
        if isinstance(message, dict):
            content = str(message.get("content", ""))
    print(f"openai_compat_chat=ok response={content[:80]!r}")
except (OSError, urllib.error.URLError, json.JSONDecodeError, socket.timeout) as exc:
    fail("openai_compat_chat", exc)

print("ollama_preflight=ok")
PY
} | tee -a "${LOG}"

ln -sfn "${LOG}" "${TOP_LOG}" 2>/dev/null || true
start_ollama_keepalive

export WORKDIR PYTHON MANIFEST TOOL_CONFIG
export LLM_PROVIDER LLM_BASE_URL LLM_API_KEY LLM_MODEL LLM_TIMEOUT_SECONDS LLM_MAX_TOKENS LLM_RESPONSE_FORMAT_JSON
export BLITZ_AGENT_FRAMEWORK
export ENABLE_REASONING MAX_NORMALIZED_EVENTS MAX_ANALYSIS_EVENTS SQLITE_ANALYSIS_EVENT_MEMORY_LIMIT SQLITE_NORMALIZATION_CHECKPOINT_INTERVAL
export REPORT_EVENT_LIMIT REPORT_FINDING_LIMIT NORMALIZED_EXPORT_LIMIT PARSER_RECORD_EXPORT_LIMIT
export PSORT_PROFILE PSORT_FILTER
export TOOL_TIMEOUT NICE_LEVEL
export CASE CASE_ROOT RUN_ROOT RESUME_SESSION CASE_OBJECTIVE
export BLITZ_RUN_ROOT="${RUN_ROOT}"
export BLITZ_PROTOCOL_SIFT_WORKFLOW="${BLITZ_PROTOCOL_SIFT_WORKFLOW:-protocol_sift_compatible_supervised_sift_launcher}"
write_run_status "RUNNING" "analysis_process_starting" "" "NOT_STARTED" "Launcher preflight completed; analysis process is starting."

RUN_PROCESS_GROUP=0
if command -v setsid >/dev/null 2>&1; then
  LAUNCH_CMD=(setsid bash -lc)
  RUN_PROCESS_GROUP=1
else
  LAUNCH_CMD=(nohup bash -lc)
fi

"${LAUNCH_CMD[@]}" '
set -euo pipefail
cd "${WORKDIR}"
source .venv/bin/activate

REASONING_ARGS=()
if [[ "${ENABLE_REASONING}" == "1" ]]; then
  REASONING_ARGS+=(--enable-reasoning)
fi
RESUME_ARGS=()
if [[ -n "${RESUME_SESSION}" ]]; then
  RESUME_ARGS+=(--resume-session "${RESUME_SESSION}")
fi
OBJECTIVE_ARGS=()
if [[ -n "${CASE_OBJECTIVE}" ]]; then
  OBJECTIVE_ARGS+=(--case-objective "${CASE_OBJECTIVE}")
fi
PSORT_FILTER_ARGS=()
if [[ -n "${PSORT_FILTER}" ]]; then
  PSORT_FILTER_ARGS+=(--psort-filter "${PSORT_FILTER}")
fi

echo "[analysis command]"
printf "%q " "${PYTHON}" app.py analyze \
  --manifest "${MANIFEST}" \
  "${OBJECTIVE_ARGS[@]}" \
  --mode timeline \
  --tool-config "${TOOL_CONFIG}" \
  "${REASONING_ARGS[@]}" \
  "${RESUME_ARGS[@]}" \
  --psort-profile "${PSORT_PROFILE}" \
  "${PSORT_FILTER_ARGS[@]}" \
  --tool-timeout "${TOOL_TIMEOUT}" \
  --max-normalized-events "${MAX_NORMALIZED_EVENTS}" \
  --max-analysis-events "${MAX_ANALYSIS_EVENTS}" \
  --report-event-limit "${REPORT_EVENT_LIMIT}" \
  --report-finding-limit "${REPORT_FINDING_LIMIT}" \
  --normalized-export-limit "${NORMALIZED_EXPORT_LIMIT}" \
  --parser-record-export-limit "${PARSER_RECORD_EXPORT_LIMIT}" \
  --full-sql-correlation
echo
set +e
env \
  PYTHONUNBUFFERED=1 \
  MALLOC_ARENA_MAX=2 \
  BLITZ_SQLITE_NORMALIZATION=1 \
  BLITZ_FULL_SQL_CORRELATION=1 \
  BLITZ_RUN_ROOT="${RUN_ROOT}" \
  BLITZ_SQLITE_ANALYSIS_EVENT_MEMORY_LIMIT="${SQLITE_ANALYSIS_EVENT_MEMORY_LIMIT}" \
  BLITZ_SQLITE_NORMALIZATION_CHECKPOINT_INTERVAL="${SQLITE_NORMALIZATION_CHECKPOINT_INTERVAL}" \
  BLITZ_PROTOCOL_SIFT_WORKFLOW="${BLITZ_PROTOCOL_SIFT_WORKFLOW}" \
  CASE_ROOT="${CASE_ROOT}" \
  BLITZ_AGENT_FRAMEWORK="${BLITZ_AGENT_FRAMEWORK}" \
  LLM_PROVIDER="${LLM_PROVIDER}" \
  LLM_BASE_URL="${LLM_BASE_URL}" \
  LLM_API_KEY="${LLM_API_KEY}" \
  LLM_MODEL="${LLM_MODEL}" \
  LLM_TIMEOUT_SECONDS="${LLM_TIMEOUT_SECONDS}" \
  LLM_MAX_TOKENS="${LLM_MAX_TOKENS}" \
  LLM_RESPONSE_FORMAT_JSON="${LLM_RESPONSE_FORMAT_JSON}" \
  nice -n "${NICE_LEVEL}" "${PYTHON}" app.py analyze \
    --manifest "${MANIFEST}" \
    "${OBJECTIVE_ARGS[@]}" \
    --mode timeline \
    --tool-config "${TOOL_CONFIG}" \
    "${REASONING_ARGS[@]}" \
    "${RESUME_ARGS[@]}" \
    --psort-profile "${PSORT_PROFILE}" \
    "${PSORT_FILTER_ARGS[@]}" \
    --tool-timeout "${TOOL_TIMEOUT}" \
    --max-normalized-events "${MAX_NORMALIZED_EVENTS}" \
    --max-analysis-events "${MAX_ANALYSIS_EVENTS}" \
    --report-event-limit "${REPORT_EVENT_LIMIT}" \
    --report-finding-limit "${REPORT_FINDING_LIMIT}" \
    --normalized-export-limit "${NORMALIZED_EXPORT_LIMIT}" \
    --parser-record-export-limit "${PARSER_RECORD_EXPORT_LIMIT}" \
    --full-sql-correlation
EXIT_CODE=$?
set -e

echo "[analysis exit code] ${EXIT_CODE}"
if [[ -n "${RESUME_SESSION}" && -d "${RESUME_SESSION}" ]]; then
  LATEST_SESSION="${RESUME_SESSION}"
else
  LATEST_SESSION="$(ls -td "${CASE_ROOT}/output"/sess-* 2>/dev/null | head -n 1 || true)"
fi
if [[ -n "${LATEST_SESSION}" ]]; then
  echo "${LATEST_SESSION}" > "${RUN_ROOT}/session_path.txt"
  ln -sfn "${LATEST_SESSION}" "${RUN_ROOT}/session" 2>/dev/null || true
  if [[ -f "${LATEST_SESSION}/audit/session_state.json" ]]; then
    cp "${LATEST_SESSION}/audit/session_state.json" "${RUN_ROOT}/session_state.final.json" 2>/dev/null || true
  fi
  if [[ -f "${LATEST_SESSION}/audit/progress.json" ]]; then
    cp "${LATEST_SESSION}/audit/progress.json" "${RUN_ROOT}/progress.final.json" 2>/dev/null || true
  fi
fi

echo "[run bundle]"
echo "run_root=${RUN_ROOT}"
echo "session=${LATEST_SESSION}"
if [[ "${EXIT_CODE}" == "0" ]]; then
  echo "Blitz DFIR analysis process completed"
else
  echo "Blitz DFIR analysis process did not complete cleanly"
fi
exit "${EXIT_CODE}"
' >> "${LOG}" 2>&1 &

PID="$!"
echo "${PID}" | tee "${PIDFILE}"
ln -sfn "${PIDFILE}" "${TOP_PIDFILE}" 2>/dev/null || true
write_run_status "RUNNING" "analysis_process_running" "" "NOT_STARTED" "Analysis process started; postrun checks have not started."

echo "PID=${PID}"
echo "PIDFILE=${PIDFILE}"
echo "RUN_ROOT=${RUN_ROOT}"
echo "LOG=${LOG}"
echo
echo "Monitor until completion with:"
echo "  CASE=${CASE} bash ${WORKDIR}/scripts/blitz_monitor_until_done.sh"
echo
echo "One-time status check:"
echo "  CASE=${CASE} bash ${WORKDIR}/scripts/blitz_status.sh"
echo
echo "Tail raw log with:"
echo "  tail -f ${LOG}"

if [[ "${WAIT_FOR_COMPLETION}" != "1" ]]; then
  write_run_status "RUNNING" "background_analysis_running" "" "NOT_STARTED" "Launcher returned in background mode; use monitor until completion."
  echo
  echo "background_mode=enabled"
  echo "This launcher returned after starting the run. Use the monitor command above to watch completion."
  exit 0
fi

echo
echo "[supervised wait]"
echo "This launcher will return when the analysis process exits."
echo "Set WAIT_FOR_COMPLETION=0 to restore background-only behavior."
echo "Set RUN_MAX_WAIT_SECONDS=0 to disable the supervised runtime guard."
write_run_status "RUNNING" "supervised_wait_running" "" "NOT_STARTED" "Supervised launcher is waiting for the analysis process."

WAIT_START_EPOCH="$(date +%s)"
WAIT_EXIT=0
while kill -0 "${PID}" 2>/dev/null; do
  echo
  echo "[supervised status]"
  BLITZ_STATUS_SUPPRESS_OPERATOR_RESULT=1 CASE="${CASE}" bash "${WORKDIR}/scripts/blitz_status.sh" || true

  if [[ "${RUN_MAX_WAIT_SECONDS}" != "0" ]]; then
    NOW_EPOCH="$(date +%s)"
    ELAPSED="$((NOW_EPOCH - WAIT_START_EPOCH))"
    if [[ "${ELAPSED}" -ge "${RUN_MAX_WAIT_SECONDS}" ]]; then
      echo "supervised_timeout_seconds=${RUN_MAX_WAIT_SECONDS}" >&2
      terminate_run_process "${PID}" "${RUN_PROCESS_GROUP}"
      wait "${PID}" 2>/dev/null || true
      WAIT_EXIT=124
      break
    fi
  fi

  sleep "${MONITOR_INTERVAL}"
done

if [[ "${WAIT_EXIT}" == "0" ]]; then
  set +e
  wait "${PID}"
  WAIT_EXIT="$?"
  set -e
fi

echo
echo "[supervised result]"
echo "analysis_process_exit=${WAIT_EXIT}"
if [[ "${WAIT_EXIT}" == "0" ]]; then
  write_run_status "RUNNING" "analysis_process_completed" "${WAIT_EXIT}" "NOT_STARTED" "Analysis session completed; postrun checks are pending."
else
  write_run_status "FAILED" "analysis_process_failed" "${WAIT_EXIT}" "NOT_STARTED" "Analysis process exited before postrun checks."
fi

if [[ "${WAIT_EXIT}" == "0" ]]; then
  LATEST_SESSION=""
  if [[ -f "${RUN_ROOT}/session_path.txt" ]]; then
    LATEST_SESSION="$(cat "${RUN_ROOT}/session_path.txt")"
  fi
  if [[ -z "${LATEST_SESSION}" || ! -d "${LATEST_SESSION}" ]]; then
    LATEST_SESSION="$(ls -td "${CASE_ROOT}/output"/sess-* 2>/dev/null | head -n 1 || true)"
  fi

  echo "session=${LATEST_SESSION:-not_found}"
  if [[ "${POSTRUN_CHECKS}" == "1" && -n "${LATEST_SESSION}" && -d "${LATEST_SESSION}" ]]; then
    echo
    echo "[postrun checks]"
    write_run_status "RUNNING" "postrun_checks_running" "${WAIT_EXIT}" "RUNNING" "Analysis is complete; postrun checks are still running."
    set +e
    (
      cd "${WORKDIR}"
      CASE="${CASE}" PLASO="${PLASO}" bash scripts/blitz_vm_postrun_checks.sh "${LATEST_SESSION}"
    )
    POSTRUN_EXIT="$?"
    set -e
    if [[ "${POSTRUN_EXIT}" != "0" ]]; then
      write_run_status "FAILED" "postrun_checks_failed" "${WAIT_EXIT}" "FAILED" "Postrun checks failed; inspect analysis/postrun_checks artifacts and launcher.log."
      echo "Blitz DFIR supervised run did not complete cleanly: postrun checks failed" >&2
      exit "${POSTRUN_EXIT}"
    fi
    write_run_status "COMPLETED" "run_completed" "${WAIT_EXIT}" "COMPLETED" "Analysis and postrun checks completed; the supervised launcher is returning the prompt."
  else
    write_run_status "COMPLETED" "run_completed" "${WAIT_EXIT}" "SKIPPED" "Analysis completed; postrun checks were disabled or no session was found."
  fi

  echo
  echo "Blitz DFIR supervised run completed"
else
  echo "Blitz DFIR supervised run did not complete cleanly" >&2
fi

exit "${WAIT_EXIT}"
