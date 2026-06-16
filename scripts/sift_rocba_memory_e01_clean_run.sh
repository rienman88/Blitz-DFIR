#!/usr/bin/env bash
set -euo pipefail

CASE="${CASE:-BLITZ-ROCBA-MEMORY-E01}"
WORKDIR="${WORKDIR:-/home/sansforensics/src/Blitz_DFIR}"
PYTHON="${PYTHON:-${WORKDIR}/.venv/bin/python}"
CASE_ROOT="${CASE_ROOT:-/cases/${CASE}}"
OUTPUT_DIR="${OUTPUT_DIR:-${CASE_ROOT}/output}"
MANIFEST="${MANIFEST:-${CASE_ROOT}/case.yaml}"
TOOL_CONFIG="${TOOL_CONFIG:-${WORKDIR}/config/tools.yaml}"
VOLATILITY_SYMBOLS_DIR="${VOLATILITY_SYMBOLS_DIR:-${BLITZ_SYMBOLS_DIR:-/cases/volatility_symbols}}"

MEMORY_SRC="${MEMORY_SRC:-}"
MEMORY_SHA_FILE="${MEMORY_SHA_FILE:-}"
MEMORY_SHA_MANIFEST="${MEMORY_SHA_MANIFEST:-/cases/BLITZ-ROCBA-MEMORY/case.yaml}"
E01_SRC="${E01_SRC:-/home/sansforensics/Desktop/cases/Rocba-E01/rocba-cdrive.e01}"
E01_SHA_FILE="${E01_SHA_FILE:-/home/sansforensics/Desktop/cases/Rocba-E01/rocba-cdrive.e01.sha256}"

ENABLE_REASONING="${ENABLE_REASONING:-0}"
CASE_OBJECTIVE="${CASE_OBJECTIVE:-Analyze Rocba memory and C-drive E01 together for evidence-backed suspicious processes, execution artifacts, persistence indicators, credential activity, user activity, temporal gaps, cross-source correlation, and unknowns while avoiding unsupported conclusions.}"

OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-http://192.168.88.1:11434}"
LLM_PROVIDER="${LLM_PROVIDER:-ollama}"
LLM_BASE_URL="${LLM_BASE_URL:-${OLLAMA_BASE_URL%/}/v1}"
LLM_API_KEY="${LLM_API_KEY:-ollama}"
LLM_MODEL="${LLM_MODEL:-llama3.2:1b}"
LLM_TIMEOUT_SECONDS="${LLM_TIMEOUT_SECONDS:-600}"
LLM_MAX_TOKENS="${LLM_MAX_TOKENS:-800}"
LLM_RESPONSE_FORMAT_JSON="${LLM_RESPONSE_FORMAT_JSON:-1}"
OLLAMA_TAGS_TIMEOUT="${OLLAMA_TAGS_TIMEOUT:-30}"
OLLAMA_GENERATE_TIMEOUT="${OLLAMA_GENERATE_TIMEOUT:-600}"
OLLAMA_CHAT_TIMEOUT="${OLLAMA_CHAT_TIMEOUT:-600}"
OLLAMA_KEEP_ALIVE="${OLLAMA_KEEP_ALIVE:-30m}"
OLLAMA_KEEPALIVE_INTERVAL_SECONDS="${OLLAMA_KEEPALIVE_INTERVAL_SECONDS:-600}"

MAX_NORMALIZED_EVENTS="${MAX_NORMALIZED_EVENTS:-5000000}"
MAX_ANALYSIS_EVENTS="${MAX_ANALYSIS_EVENTS:-2000000}"
SQLITE_ANALYSIS_EVENT_MEMORY_LIMIT="${SQLITE_ANALYSIS_EVENT_MEMORY_LIMIT:-${BLITZ_SQLITE_ANALYSIS_EVENT_MEMORY_LIMIT:-50000}}"
SQLITE_NORMALIZATION_CHECKPOINT_INTERVAL="${SQLITE_NORMALIZATION_CHECKPOINT_INTERVAL:-${BLITZ_SQLITE_NORMALIZATION_CHECKPOINT_INTERVAL:-100000}}"
REPORT_EVENT_LIMIT="${REPORT_EVENT_LIMIT:-2000000}"
REPORT_FINDING_LIMIT="${REPORT_FINDING_LIMIT:-2000000}"
NORMALIZED_EXPORT_LIMIT="${NORMALIZED_EXPORT_LIMIT:-10000}"
PARSER_RECORD_EXPORT_LIMIT="${PARSER_RECORD_EXPORT_LIMIT:-10000}"
SQL_CORRELATION_FINDING_LIMIT="${SQL_CORRELATION_FINDING_LIMIT:-${BLITZ_SQL_CORRELATION_FINDING_LIMIT:-25000}}"
SQL_CORRELATION_SUPPORT_EVENT_LIMIT="${SQL_CORRELATION_SUPPORT_EVENT_LIMIT:-${BLITZ_SQL_CORRELATION_SUPPORT_EVENT_LIMIT:-50000}}"
PSORT_PROFILE="${PSORT_PROFILE:-triage}"
WINDOWS_ARTIFACT_PROFILE="${WINDOWS_ARTIFACT_PROFILE:-${BLITZ_WINDOWS_ARTIFACT_PROFILE:-windows-light}}"
WINDOWS_LIGHT_PSORT_FILTER="(data_type contains 'windows:evtx' or data_type contains 'windows:prefetch' or data_type contains 'windows:lnk' or data_type contains 'windows:registry' or data_type contains 'windows:timeline' or data_type contains 'setupapi' or data_type contains 'srum')"
if [[ -z "${PSORT_FILTER+x}" ]]; then
  if [[ "${WINDOWS_ARTIFACT_PROFILE}" == "windows-light" ]]; then
    PSORT_FILTER="${WINDOWS_LIGHT_PSORT_FILTER}"
  else
    PSORT_FILTER="data_type contains 'windows:evtx'"
  fi
fi
TOOL_TIMEOUT="${TOOL_TIMEOUT:-7200}"
NICE_LEVEL="${NICE_LEVEL:-10}"
MIN_FREE_GB="${MIN_FREE_GB:-5}"
RECOMMENDED_FREE_GB="${RECOMMENDED_FREE_GB:-40}"
FORCE="${FORCE:-0}"
RUN_SUFFIX="${RUN_SUFFIX:-rocba_memory_e01_clean}"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)_${RUN_SUFFIX}"
RUN_ROOT="${RUN_ROOT:-${CASE_ROOT}/analysis/runs/${RUN_ID}}"
LOG="${RUN_ROOT}/launcher.log"
RUN_STATUS="${RUN_ROOT}/run_status.json"
PROCESS_PATTERN='app.py analyze|(^|[[:space:]/])vol([[:space:]]|$)|psort.py|log2timeline.py|tsk_e01_triage.py|(^|[[:space:]/])fls([[:space:]]|$)|(^|[[:space:]/])mmls([[:space:]]|$)|psteal.py|case.plaso'
OLLAMA_KEEPALIVE_PID=""

fail() {
  local reason="$1"
  local code="${2:-2}"
  echo "preflight_failed=${reason}" >&2
  echo "case=${CASE:-unset}" >&2
  echo "case_root=${CASE_ROOT:-unset}" >&2
  echo "output_dir=${OUTPUT_DIR:-unset}" >&2
  echo "manifest=${MANIFEST:-unset}" >&2
  echo "memory_src=${MEMORY_SRC:-unset}" >&2
  echo "e01_src=${E01_SRC:-unset}" >&2
  echo "workdir=${WORKDIR:-unset}" >&2
  exit "${code}"
}

choose_existing_file() {
  local candidate
  for candidate in "$@"; do
    if [[ -f "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  return 1
}

absolute_path() {
  "${PYTHON}" - "$1" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path

print(Path(sys.argv[1]).expanduser().resolve())
PY
}

df_unique() {
  {
    df -h "$@" 2>/dev/null || df -h / 2>/dev/null || true
  } | awk 'NR == 1 { print; next } !seen[$1 "|" $6]++'
}

hash_from_manifest() {
  local manifest_path="$1"
  [[ -f "${manifest_path}" ]] || return 1
  awk '/sha256:/ {print $2; exit}' "${manifest_path}"
}

verify_hash() {
  local hash="$1"
  local path="$2"
  [[ -n "${hash}" ]] || return 1
  echo "${hash}  ${path}" | sha256sum -c - >/dev/null 2>&1
}

resolve_hash() {
  local path="$1"
  local explicit_hash="${2:-}"
  local hash_file="${3:-}"
  local hash_manifest="${4:-}"
  local candidate=""

  if [[ -n "${explicit_hash}" ]]; then
    if verify_hash "${explicit_hash}" "${path}"; then
      printf '%s\n' "${explicit_hash}"
      return 0
    fi
    echo "warning=explicit_hash_did_not_match path=${path}" >&2
  fi

  if [[ -f "${hash_file}" ]]; then
    candidate="$(awk '{print $1; exit}' "${hash_file}")"
    if verify_hash "${candidate}" "${path}"; then
      printf '%s\n' "${candidate}"
      return 0
    fi
    echo "warning=hash_file_did_not_match hash_file=${hash_file} path=${path}; computing hash" >&2
  fi

  candidate="$(hash_from_manifest "${hash_manifest}" || true)"
  if [[ -n "${candidate}" ]]; then
    if verify_hash "${candidate}" "${path}"; then
      printf '%s\n' "${candidate}"
      return 0
    fi
    echo "warning=manifest_hash_did_not_match hash_manifest=${hash_manifest} path=${path}; computing hash" >&2
  fi

  sha256sum "${path}" | awk '{print $1}'
}

write_run_status() {
  local status="$1"
  local phase="$2"
  local analysis_exit="${3:-}"
  local message="${4:-}"
  python3 - "${RUN_STATUS}" "${CASE}" "${RUN_ID}" "${RUN_ROOT}" "${status}" "${phase}" "${analysis_exit}" "${message}" <<'PY'
from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

path = Path(sys.argv[1])
case = sys.argv[2]
run_id = sys.argv[3]
run_root = sys.argv[4]
status = sys.argv[5]
phase = sys.argv[6]
analysis_exit = sys.argv[7]
message = sys.argv[8]

payload = {
    "schema_version": "blitz-memory-e01-run-status.v2",
    "case_id": case,
    "run_id": run_id,
    "run_root": run_root,
    "status": status,
    "phase": phase,
    "updated_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    "raw_evidence_mode": "external_absolute_paths_no_copy",
}
session_path = Path(run_root) / "session_path.txt"
if session_path.exists():
    payload["session"] = session_path.read_text(encoding="utf-8").strip()
if analysis_exit:
    payload["analysis_exit_code"] = int(analysis_exit)
if status == "COMPLETED":
    payload["postrun_checks"] = "NOT_CONFIGURED"
    payload["postrun_checks_enabled"] = False
    payload["postrun_checks_reason"] = (
        "combined memory plus E01 runner has no separate postrun QA phase; "
        "analysis validation, coverage, reporting, and artifact hashing complete inside the Blitz pipeline."
    )
if message:
    payload["message"] = message
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
PY
}

preflight_ollama() {
  "${PYTHON}" - "${OLLAMA_BASE_URL}" "${LLM_MODEL}" "${OLLAMA_TAGS_TIMEOUT}" "${OLLAMA_GENERATE_TIMEOUT}" "${OLLAMA_CHAT_TIMEOUT}" "${OLLAMA_KEEP_ALIVE}" <<'PY'
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

if [[ -z "${MEMORY_SRC}" ]]; then
  MEMORY_SRC="$(
    choose_existing_file \
      "/home/sansforensics/Desktop/cases/BLITZ-ROCBA-MEMORY/raw/Rocba-Memory.raw" \
      "/home/sansforensics/Desktop/cases/BLITZ-ROCBA-MEMORY/raw/Rocba-Memory/Rocba-Memory.raw" \
      "/cases/BLITZ-ROCBA-MEMORY/raw/Rocba-Memory/Rocba-Memory.raw" \
      "/cases/BLITZ-ROCBA-MEMORY/raw/Rocba-Memory.raw"
  )" || fail "memory_src_not_found"
fi

[[ -n "${CASE}" ]] || fail "empty_case"
[[ "${CASE_ROOT}" == /cases/* ]] || fail "case_root_must_be_under_cases"
[[ "${OUTPUT_DIR}" == "${CASE_ROOT}/output" ]] || fail "output_dir_must_be_case_specific"
[[ "${MANIFEST}" == "${CASE_ROOT}/case.yaml" ]] || fail "manifest_must_be_case_specific"
[[ -d "${WORKDIR}" ]] || fail "workdir_not_found"
[[ -x "${PYTHON}" ]] || fail "python_not_executable"
[[ -f "${TOOL_CONFIG}" ]] || fail "tool_config_not_found"
[[ -f "${MEMORY_SRC}" ]] || fail "memory_src_not_found"
[[ -f "${E01_SRC}" ]] || fail "e01_src_not_found"

MEMORY_SRC="$(absolute_path "${MEMORY_SRC}")"
E01_SRC="$(absolute_path "${E01_SRC}")"

mkdir -p "${RUN_ROOT}" "${OUTPUT_DIR}" "${CASE_ROOT}/analysis/runs"

if ! mkdir -p "${VOLATILITY_SYMBOLS_DIR}" 2>/dev/null; then
  echo "volatility_symbols_dir_create_failed=${VOLATILITY_SYMBOLS_DIR}" >&2
  echo "Run once on SIFT:" >&2
  echo "  sudo mkdir -p ${VOLATILITY_SYMBOLS_DIR}" >&2
  echo "  sudo chown \"\$USER:\$USER\" ${VOLATILITY_SYMBOLS_DIR}" >&2
  echo "  chmod 700 ${VOLATILITY_SYMBOLS_DIR}" >&2
  exit 2
fi
if ! touch "${VOLATILITY_SYMBOLS_DIR}/.blitz_write_probe" 2>/dev/null; then
  echo "volatility_symbols_dir_not_writable=${VOLATILITY_SYMBOLS_DIR}" >&2
  echo "Run once on SIFT:" >&2
  echo "  sudo chown \"\$USER:\$USER\" ${VOLATILITY_SYMBOLS_DIR}" >&2
  echo "  chmod 700 ${VOLATILITY_SYMBOLS_DIR}" >&2
  exit 2
fi
rm -f "${VOLATILITY_SYMBOLS_DIR}/.blitz_write_probe"

ACTIVE_PROCESSES="$(ps -eo pid,ppid,stat,etime,%mem,%cpu,cmd | egrep "${PROCESS_PATTERN}" | grep -v grep || true)"
if [[ -n "${ACTIVE_PROCESSES}" && "${FORCE}" != "1" ]]; then
  echo "[active Blitz/SIFT processes]"
  echo "${ACTIVE_PROCESSES}"
  echo
  echo "refusing to start another combined run while analysis/tool work is active. Set FORCE=1 only after confirming this is safe." >&2
  exit 3
fi

FREE_GB="$(df -BG "${CASE_ROOT}" 2>/dev/null | awk 'NR==2 {gsub(/G/, "", $4); print $4}')"
if [[ -n "${FREE_GB}" && "${FREE_GB}" -lt "${MIN_FREE_GB}" ]]; then
  echo "free space below hard threshold: free_gb=${FREE_GB} min_free_gb=${MIN_FREE_GB}" >&2
  echo "Blitz will not copy raw evidence, but it still needs output space for logs, timelines, SQLite stores, and reports." >&2
  exit 4
fi
if [[ -n "${FREE_GB}" && "${FREE_GB}" -lt "${RECOMMENDED_FREE_GB}" ]]; then
  echo "warning=free_space_below_recommended free_gb=${FREE_GB} recommended_free_gb=${RECOMMENDED_FREE_GB}" >&2
  echo "warning=run_may_fail_during_log2timeline_or_sqlite_outputs raw_evidence_will_not_be_copied" >&2
fi

MEMORY_HASH="$(resolve_hash "${MEMORY_SRC}" "${MEMORY_HASH:-}" "${MEMORY_SHA_FILE}" "${MEMORY_SHA_MANIFEST}")"
E01_HASH="$(resolve_hash "${E01_SRC}" "${E01_HASH:-}" "${E01_SHA_FILE}" "")"
echo "${MEMORY_HASH}  ${MEMORY_SRC}" | sha256sum -c -
echo "${E01_HASH}  ${E01_SRC}" | sha256sum -c -

"${PYTHON}" - "${MANIFEST}" "${CASE}" "${OUTPUT_DIR}" "${MEMORY_SRC}" "${MEMORY_HASH}" "${E01_SRC}" "${E01_HASH}" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path

import yaml

manifest_path = Path(sys.argv[1])
case_id = sys.argv[2]
output_root = sys.argv[3]
memory_path = sys.argv[4]
memory_hash = sys.argv[5]
e01_path = sys.argv[6]
e01_hash = sys.argv[7]

payload = {
    "case_id": case_id,
    "evidence_root": "external",
    "output_root": output_root,
    "evidence": [
        {
            "id": "rocba-memory",
            "path": memory_path,
            "type": "MEMORY",
            "sha256": memory_hash,
            "description": "Rocba memory image referenced in place; raw evidence is not copied into the Blitz case.",
        },
        {
            "id": "rocba-cdrive-e01",
            "path": e01_path,
            "type": "E01",
            "sha256": e01_hash,
            "description": "Rocba C-drive E01 referenced in place; raw evidence is not copied into the Blitz case.",
        },
    ],
}
manifest_path.parent.mkdir(parents=True, exist_ok=True)
manifest_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
PY

{
  echo "[scope]"
  echo "case=${CASE}"
  echo "run_id=${RUN_ID}"
  echo "run_mode=clean"
  echo "run_root=${RUN_ROOT}"
  echo "workdir=${WORKDIR}"
  echo "manifest=${MANIFEST}"
  echo "case_root=${CASE_ROOT}"
  echo "output_dir=${OUTPUT_DIR}"
  echo "memory_src=${MEMORY_SRC}"
  echo "e01_src=${E01_SRC}"
  echo "raw_evidence_mode=external_absolute_paths_no_copy"
  echo "tool_config=${TOOL_CONFIG}"
  echo "volatility_symbols_dir=${VOLATILITY_SYMBOLS_DIR}"
  echo "case_objective=${CASE_OBJECTIVE}"
  echo "enable_reasoning=${ENABLE_REASONING}"
  echo "llm_provider=${LLM_PROVIDER}"
  echo "llm_base_url=${LLM_BASE_URL}"
  echo "llm_model=${LLM_MODEL}"
  echo "llm_timeout_seconds=${LLM_TIMEOUT_SECONDS}"
  echo "llm_max_tokens=${LLM_MAX_TOKENS}"
  echo "llm_response_format_json=${LLM_RESPONSE_FORMAT_JSON}"
  echo "ollama_keep_alive=${OLLAMA_KEEP_ALIVE}"
  echo "ollama_tags_timeout=${OLLAMA_TAGS_TIMEOUT}"
  echo "ollama_generate_timeout=${OLLAMA_GENERATE_TIMEOUT}"
  echo "ollama_chat_timeout=${OLLAMA_CHAT_TIMEOUT}"
  echo "ollama_keepalive_interval_seconds=${OLLAMA_KEEPALIVE_INTERVAL_SECONDS}"
  echo "max_normalized_events=${MAX_NORMALIZED_EVENTS}"
  echo "max_analysis_events=${MAX_ANALYSIS_EVENTS}"
  echo "sqlite_analysis_event_memory_limit=${SQLITE_ANALYSIS_EVENT_MEMORY_LIMIT}"
  echo "sqlite_normalization_checkpoint_interval=${SQLITE_NORMALIZATION_CHECKPOINT_INTERVAL}"
  echo "sql_correlation_finding_limit=${SQL_CORRELATION_FINDING_LIMIT}"
  echo "sql_correlation_support_event_limit=${SQL_CORRELATION_SUPPORT_EVENT_LIMIT}"
  echo "psort_profile=${PSORT_PROFILE}"
  echo "psort_filter=${PSORT_FILTER}"
  echo "windows_artifact_profile=${WINDOWS_ARTIFACT_PROFILE}"
  echo "log2timeline_partitions=${BLITZ_LOG2TIMELINE_PARTITIONS:-all}"
  echo "log2timeline_vss_stores=${BLITZ_LOG2TIMELINE_VSS_STORES:-none}"
  echo "log2timeline_parsers=${BLITZ_LOG2TIMELINE_PARSERS:-profile:${WINDOWS_ARTIFACT_PROFILE}}"
  echo "disk_triage_fallback=${BLITZ_E01_DISK_TRIAGE_FALLBACK:-1}"
  echo "disk_triage_max_partitions=${BLITZ_DISK_TRIAGE_MAX_PARTITIONS:-8}"
  echo "disk_triage_max_entries=${BLITZ_DISK_TRIAGE_MAX_ENTRIES:-3000000}"
  echo "disk_triage_seconds_per_partition=${BLITZ_DISK_TRIAGE_SECONDS_PER_PARTITION:-1800}"
  echo "full_sql_correlation=1"
  echo
  echo "[disk before]"
  df_unique "${CASE_ROOT}" /
  echo
  echo "[memory before]"
  free -h
  echo
  echo "[manifest]"
  sed -n '1,140p' "${MANIFEST}"
  echo
  echo "[manifest preflight]"
  (
    cd "${WORKDIR}"
    "${PYTHON}" - "${MANIFEST}" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path

from blitz_dfir.core.manifest import load_manifest

manifest = load_manifest(Path(sys.argv[1]))
print(f"manifest_ok=1 case_id={manifest.case_id} external_evidence={manifest.external_evidence} evidence_count={len(manifest.evidence)}")
for evidence in manifest.evidence:
    print(
        "evidence "
        f"id={evidence.evidence_id} type={evidence.evidence_type.value} "
        f"path={evidence.path} verified={evidence.verified} size={evidence.size_bytes}"
    )
PY
  )
  if [[ "${ENABLE_REASONING}" == "1" ]]; then
    echo
    echo "[ollama preflight]"
    preflight_ollama
  fi
} | tee "${LOG}"

start_ollama_keepalive

write_run_status "RUNNING" "analysis_starting" "" "Combined memory plus E01 runner preflight completed with external evidence paths."

ANALYZE_ARGS=(
  app.py analyze
  --manifest "${MANIFEST}"
  --mode timeline
  --tool-config "${TOOL_CONFIG}"
  --case-objective "${CASE_OBJECTIVE}"
  --psort-profile "${PSORT_PROFILE}"
  --psort-filter "${PSORT_FILTER}"
  --windows-artifact-profile "${WINDOWS_ARTIFACT_PROFILE}"
  --tool-timeout "${TOOL_TIMEOUT}"
  --max-normalized-events "${MAX_NORMALIZED_EVENTS}"
  --max-analysis-events "${MAX_ANALYSIS_EVENTS}"
  --report-event-limit "${REPORT_EVENT_LIMIT}"
  --report-finding-limit "${REPORT_FINDING_LIMIT}"
  --normalized-export-limit "${NORMALIZED_EXPORT_LIMIT}"
  --parser-record-export-limit "${PARSER_RECORD_EXPORT_LIMIT}"
  --full-sql-correlation
)
if [[ "${ENABLE_REASONING}" == "1" ]]; then
  ANALYZE_ARGS+=(--enable-reasoning)
fi

{
  echo
  echo "[analysis command]"
  printf "%q " "${PYTHON}" "${ANALYZE_ARGS[@]}"
  echo
} | tee -a "${LOG}"

set +e
(
  cd "${WORKDIR}"
  env \
    PYTHONUNBUFFERED=1 \
    MALLOC_ARENA_MAX=2 \
    BLITZ_SQLITE_NORMALIZATION=1 \
    BLITZ_FULL_SQL_CORRELATION=1 \
    BLITZ_SQL_CORRELATION_FINDING_LIMIT="${SQL_CORRELATION_FINDING_LIMIT}" \
    BLITZ_SQL_CORRELATION_SUPPORT_EVENT_LIMIT="${SQL_CORRELATION_SUPPORT_EVENT_LIMIT}" \
    BLITZ_SQLITE_ANALYSIS_EVENT_MEMORY_LIMIT="${SQLITE_ANALYSIS_EVENT_MEMORY_LIMIT}" \
    BLITZ_SQLITE_NORMALIZATION_CHECKPOINT_INTERVAL="${SQLITE_NORMALIZATION_CHECKPOINT_INTERVAL}" \
    BLITZ_RUN_ROOT="${RUN_ROOT}" \
    BLITZ_WINDOWS_ARTIFACT_PROFILE="${WINDOWS_ARTIFACT_PROFILE}" \
    BLITZ_SYMBOLS_DIR="${VOLATILITY_SYMBOLS_DIR}" \
    VOLATILITY_SYMBOLS="${VOLATILITY_SYMBOLS_DIR}" \
    CASE_ROOT="${CASE_ROOT}" \
    LLM_PROVIDER="${LLM_PROVIDER}" \
    LLM_BASE_URL="${LLM_BASE_URL}" \
    LLM_API_KEY="${LLM_API_KEY}" \
    LLM_MODEL="${LLM_MODEL}" \
    LLM_TIMEOUT_SECONDS="${LLM_TIMEOUT_SECONDS}" \
    LLM_MAX_TOKENS="${LLM_MAX_TOKENS}" \
    LLM_RESPONSE_FORMAT_JSON="${LLM_RESPONSE_FORMAT_JSON}" \
    nice -n "${NICE_LEVEL}" "${PYTHON}" "${ANALYZE_ARGS[@]}"
) 2>&1 | tee -a "${LOG}"
ANALYSIS_EXIT="${PIPESTATUS[0]}"
set -e

echo "analysis_exit=${ANALYSIS_EXIT}" | tee "${RUN_ROOT}/run_exit.txt"

LATEST_SESSION="$(ls -td "${CASE_ROOT}/output"/sess-* 2>/dev/null | head -n 1 || true)"
if [[ -n "${LATEST_SESSION}" ]]; then
  echo "${LATEST_SESSION}" > "${RUN_ROOT}/session_path.txt"
  ln -sfn "${LATEST_SESSION}" "${RUN_ROOT}/session" 2>/dev/null || true
fi

if [[ "${ANALYSIS_EXIT}" == "0" ]]; then
  write_run_status "COMPLETED" "analysis_completed" "${ANALYSIS_EXIT}" "Combined memory plus E01 analysis completed."
else
  write_run_status "FAILED" "analysis_failed" "${ANALYSIS_EXIT}" "Combined memory plus E01 analysis exited non-zero."
fi

echo
echo "[status]"
CASE="${CASE}" bash "${WORKDIR}/scripts/blitz_status.sh" || true

exit "${ANALYSIS_EXIT}"
