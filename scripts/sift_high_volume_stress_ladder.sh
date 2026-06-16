#!/usr/bin/env bash
set -euo pipefail

CASE="${CASE:-BLITZ-RD01-PLASO}"
WORKDIR="${WORKDIR:-/home/sansforensics/src/Blitz_DFIR}"
CASE_ROOT="${CASE_ROOT:-/cases/${CASE}}"
PLASO="${PLASO:-${CASE_ROOT}/processed/case.plaso}"
CASE_OBJECTIVE="${CASE_OBJECTIVE:-}"
STRESS_TARGETS="${STRESS_TARGETS:-1000000 2000000 3000000 4000000 5000000}"
STRESS_RUN_ID="${STRESS_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
STRESS_ROOT="${STRESS_ROOT:-${CASE_ROOT}/analysis/high_volume_stress}"
STRESS_DIR="${STRESS_ROOT}/${STRESS_RUN_ID}"
MIN_FREE_GB="${MIN_FREE_GB:-25}"
REQUIRE_TARGET_ROWS="${REQUIRE_TARGET_ROWS:-1}"
CONTINUE_AFTER_FAILURE="${CONTINUE_AFTER_FAILURE:-0}"
MAX_SUPPORTED_STRESS_TARGET="${MAX_SUPPORTED_STRESS_TARGET:-5000000}"

# Empty PSORT_FILTER means "full PLASO export"; the normal launcher default remains EVTX-only.
PSORT_FILTER="${PSORT_FILTER-}"
PSORT_PROFILE="${PSORT_PROFILE:-triage}"
ENABLE_REASONING="${ENABLE_REASONING:-1}"
MAX_ANALYSIS_EVENTS="${MAX_ANALYSIS_EVENTS:-100000}"
REPORT_EVENT_LIMIT="${REPORT_EVENT_LIMIT:-5000}"
REPORT_FINDING_LIMIT="${REPORT_FINDING_LIMIT:-500}"
NORMALIZED_EXPORT_LIMIT="${NORMALIZED_EXPORT_LIMIT:-10000}"
PARSER_RECORD_EXPORT_LIMIT="${PARSER_RECORD_EXPORT_LIMIT:-1000}"
TOOL_TIMEOUT="${TOOL_TIMEOUT:-7200}"
RUN_MAX_WAIT_SECONDS="${RUN_MAX_WAIT_SECONDS:-43200}"
MONITOR_INTERVAL="${MONITOR_INTERVAL:-120}"
POSTRUN_CHECKS="${POSTRUN_CHECKS:-1}"

mkdir -p "${STRESS_DIR}"
MASTER_LOG="${STRESS_DIR}/high_volume_stress.log"
SUMMARY_JSONL="${STRESS_DIR}/stage_summaries.jsonl"
STATUS_JSONL="${STRESS_DIR}/stage_status.jsonl"

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "${MASTER_LOG}"
}

free_gb() {
  df -Pk "${CASE_ROOT}" | awk 'NR == 2 { printf "%.0f", $4 / 1024 / 1024 }'
}

check_free_space() {
  local free
  free="$(free_gb)"
  log "free_gb=${free} min_free_gb=${MIN_FREE_GB}"
  if [[ "${free}" -lt "${MIN_FREE_GB}" ]]; then
    log "stopping: free disk below threshold"
    exit 70
  fi
}

validate_targets() {
  local target
  for target in ${STRESS_TARGETS}; do
    if ! [[ "${target}" =~ ^[0-9]+$ ]]; then
      log "invalid stress target: ${target}"
      exit 64
    fi
    if [[ "${target}" -lt 1 ]]; then
      log "invalid stress target below 1: ${target}"
      exit 64
    fi
    if [[ "${target}" -gt "${MAX_SUPPORTED_STRESS_TARGET}" ]]; then
      log "unsupported stress target: target=${target} max_supported=${MAX_SUPPORTED_STRESS_TARGET}"
      log "recommendation: run the current ceiling ladder first, then redesign accounting/storage before claiming 20M/50M support."
      exit 64
    fi
  done
}

summarize_stage() {
  local stage="$1"
  local target="$2"
  local run_root="$3"
  local rc="$4"
  local session=""
  local summary="${STRESS_DIR}/${stage}.summary.json"

  if [[ -f "${run_root}/session_path.txt" ]]; then
    session="$(cat "${run_root}/session_path.txt")"
  fi
  if [[ -z "${session}" || ! -d "${session}" ]]; then
    session="$(ls -td "${CASE_ROOT}/output"/sess-* 2>/dev/null | head -n 1 || true)"
  fi
  if [[ -z "${session}" || ! -d "${session}" ]]; then
    log "stage=${stage} no session directory found"
    if [[ -f "${run_root}/run_status.json" ]]; then
      log "stage=${stage} run_status:"
      sed -n '1,160p' "${run_root}/run_status.json" | tee -a "${MASTER_LOG}" || true
    fi
    if [[ -f "${run_root}/launcher.log" ]]; then
      log "stage=${stage} launcher.log tail:"
      tail -n 120 "${run_root}/launcher.log" | tee -a "${MASTER_LOG}" || true
    else
      log "stage=${stage} launcher.log missing at ${run_root}/launcher.log"
    fi
    python3 - "${STATUS_JSONL}" "${stage}" "${target}" "${rc}" "0" "no_session" <<'PY'
from __future__ import annotations

import json
import sys
from datetime import UTC, datetime

path, stage, target, rc, actual, verdict = sys.argv[1:7]
with open(path, "a", encoding="utf-8") as handle:
    handle.write(json.dumps({
        "timestamp_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "stage": stage,
        "target_normalized_events": int(target),
        "actual_normalized_events": int(actual),
        "exit_code": int(rc),
        "verdict": verdict,
    }, sort_keys=True) + "\n")
PY
    return 1
  fi

  python3 "${WORKDIR}/scripts/sift_summarize_session.py" "${session}" "${PLASO}" > "${summary}"
  python3 - "${SUMMARY_JSONL}" "${STATUS_JSONL}" "${summary}" "${stage}" "${target}" "${rc}" <<'PY'
from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

summary_jsonl, status_jsonl, summary_path, stage, target, rc = sys.argv[1:7]
target_int = int(target)
rc_int = int(rc)
summary = json.loads(Path(summary_path).read_text(encoding="utf-8"))
event_store = summary.get("event_store") if isinstance(summary.get("event_store"), dict) else {}
full_accounting = summary.get("full_accounting") if isinstance(summary.get("full_accounting"), dict) else {}
state = summary.get("state") if isinstance(summary.get("state"), dict) else {}
stress = summary.get("stress_report") if isinstance(summary.get("stress_report"), dict) else {}
validation = summary.get("validation") if isinstance(summary.get("validation"), dict) else {}
actual = int(event_store.get("event_rows") or full_accounting.get("total_rows") or stress.get("normalized_event_count") or 0)
completed = state.get("status") == "COMPLETED" and rc_int == 0
target_met = actual >= target_int
verdict = "passed" if completed and target_met else "source_under_target" if completed else "failed"
record = dict(summary)
record["stress_stage"] = {
    "stage": stage,
    "target_normalized_events": target_int,
    "actual_normalized_events": actual,
    "target_met": target_met,
    "exit_code": rc_int,
    "validation_passed": validation.get("passed"),
    "verdict": verdict,
}
with open(summary_jsonl, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(record, sort_keys=True) + "\n")
with open(status_jsonl, "a", encoding="utf-8") as handle:
    handle.write(json.dumps({
        "timestamp_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "stage": stage,
        "target_normalized_events": target_int,
        "actual_normalized_events": actual,
        "target_met": target_met,
        "exit_code": rc_int,
        "session": summary.get("session"),
        "summary": summary_path,
        "verdict": verdict,
    }, sort_keys=True) + "\n")
print(f"actual_normalized_events={actual}")
print(f"target_met={target_met}")
print(f"verdict={verdict}")
PY
}

run_stage() {
  local target="$1"
  local stage="normalized_${target}"
  local run_root="${CASE_ROOT}/analysis/runs/${STRESS_RUN_ID}_${stage}"
  local stage_log="${STRESS_DIR}/${stage}.launcher-wrapper.log"
  local rc=0

  check_free_space
  log "stage=${stage} target=${target} psort_filter=${PSORT_FILTER:-none} start"
  set +e
  (
    cd "${WORKDIR}"
    CASE="${CASE}" \
    CASE_ROOT="${CASE_ROOT}" \
    WORKDIR="${WORKDIR}" \
    RUN_ROOT="${run_root}" \
    PLASO="${PLASO}" \
    CASE_OBJECTIVE="${CASE_OBJECTIVE}" \
    PSORT_PROFILE="${PSORT_PROFILE}" \
    PSORT_FILTER="${PSORT_FILTER}" \
    ENABLE_REASONING="${ENABLE_REASONING}" \
    MAX_NORMALIZED_EVENTS="${target}" \
    MAX_ANALYSIS_EVENTS="${MAX_ANALYSIS_EVENTS}" \
    REPORT_EVENT_LIMIT="${REPORT_EVENT_LIMIT}" \
    REPORT_FINDING_LIMIT="${REPORT_FINDING_LIMIT}" \
    NORMALIZED_EXPORT_LIMIT="${NORMALIZED_EXPORT_LIMIT}" \
    PARSER_RECORD_EXPORT_LIMIT="${PARSER_RECORD_EXPORT_LIMIT}" \
    TOOL_TIMEOUT="${TOOL_TIMEOUT}" \
    RUN_MAX_WAIT_SECONDS="${RUN_MAX_WAIT_SECONDS}" \
    MONITOR_INTERVAL="${MONITOR_INTERVAL}" \
    POSTRUN_CHECKS="${POSTRUN_CHECKS}" \
    bash scripts/sift_e2e_ollama_run.sh
  ) 2>&1 | tee "${stage_log}"
  rc="${PIPESTATUS[0]}"
  set -e
  log "stage=${stage} launcher_exit=${rc} run_root=${run_root}"

  local summary_rc=0
  if summarize_stage "${stage}" "${target}" "${run_root}" "${rc}" | tee -a "${MASTER_LOG}"; then
    if [[ "${REQUIRE_TARGET_ROWS}" == "1" ]]; then
      local latest_status
      latest_status="$(tail -n 1 "${STATUS_JSONL}")"
      if ! python3 - "${latest_status}" <<'PY'
from __future__ import annotations

import json
import sys

payload = json.loads(sys.argv[1])
raise SystemExit(0 if payload.get("target_met") is True and payload.get("exit_code") == 0 else 1)
PY
      then
        log "stage=${stage} did not meet target rows; stopping because REQUIRE_TARGET_ROWS=1"
        return 80
      fi
    fi
  else
    summary_rc=$?
    if [[ "${rc}" == "0" ]]; then
      rc="${summary_rc}"
    fi
  fi

  if [[ "${rc}" != "0" ]]; then
    return "${rc}"
  fi
  return 0
}

log "high-volume stress started case=${CASE} run_id=${STRESS_RUN_ID}"
log "workdir=${WORKDIR}"
log "plaso=${PLASO}"
log "targets=${STRESS_TARGETS}"
log "max_supported_stress_target=${MAX_SUPPORTED_STRESS_TARGET}"
log "psort_filter=${PSORT_FILTER:-none}"
log "enable_reasoning=${ENABLE_REASONING}"
log "max_analysis_events=${MAX_ANALYSIS_EVENTS}"
log "report_event_limit=${REPORT_EVENT_LIMIT}"
log "require_target_rows=${REQUIRE_TARGET_ROWS}"

if [[ ! -f "${PLASO}" ]]; then
  log "missing PLASO evidence: ${PLASO}"
  exit 2
fi

validate_targets

for target in ${STRESS_TARGETS}; do
  set +e
  run_stage "${target}"
  rc="$?"
  set -e
  if [[ "${rc}" == "0" ]]; then
    log "target=${target} passed"
    continue
  fi
  log "target=${target} failed rc=${rc}"
  if [[ "${CONTINUE_AFTER_FAILURE}" != "1" ]]; then
    exit "${rc}"
  fi
done

log "high-volume stress completed status_jsonl=${STATUS_JSONL} summary_jsonl=${SUMMARY_JSONL}"
