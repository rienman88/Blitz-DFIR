#!/usr/bin/env bash
set -uo pipefail

CASE="${CASE:-BLITZ-RD01-PLASO}"
WORKDIR="${WORKDIR:-$HOME/src/Blitz_DFIR}"
MANIFEST="${MANIFEST:-/cases/${CASE}/case.yaml}"
TOOL_CONFIG="${TOOL_CONFIG:-${WORKDIR}/config/tools.yaml}"
EVIDENCE="${EVIDENCE:-/cases/${CASE}/processed/case.plaso}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
STABILITY_ROOT="${STABILITY_ROOT:-/cases/${CASE}/analysis/stability}"
STABILITY_DIR="${STABILITY_ROOT}/${RUN_ID}"
MIN_FREE_GB="${MIN_FREE_GB:-15}"
DELETE_PASSED_SESSIONS="${DELETE_PASSED_SESSIONS:-0}"
HASH_EACH_PHASE="${HASH_EACH_PHASE:-1}"
STABILITY_PROFILE="${STABILITY_PROFILE:-default}"
CONTINUE_AFTER_FAILURE="${CONTINUE_AFTER_FAILURE:-0}"

mkdir -p "$STABILITY_DIR"
MASTER_LOG="${STABILITY_DIR}/stability_run.log"
SUMMARY_JSONL="${STABILITY_DIR}/phase_summaries.jsonl"
STATUS_JSONL="${STABILITY_DIR}/phase_status.jsonl"

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$MASTER_LOG"
}

free_gb() {
  df -Pk "/cases/${CASE}" | awk 'NR == 2 { printf "%.0f", $4 / 1024 / 1024 }'
}

check_free_space() {
  local free
  free="$(free_gb)"
  log "free_gb=${free} min_free_gb=${MIN_FREE_GB}"
  if [ "$free" -lt "$MIN_FREE_GB" ]; then
    log "stopping: free disk below threshold"
    exit 70
  fi
}

summarize_latest_session() {
  local phase="$1"
  local latest
  latest="$(ls -td "/cases/${CASE}/output"/sess-* 2>/dev/null | head -n 1 || true)"
  if [ -z "$latest" ]; then
    log "phase=${phase} no session directory found"
    return 1
  fi

  local summary="${STABILITY_DIR}/${phase}.summary.json"
  if ! python "${WORKDIR}/scripts/sift_summarize_session.py" "$latest" "$EVIDENCE" > "$summary"; then
    log "phase=${phase} failed to summarize latest session=${latest}"
    return 1
  fi
  python - "$phase" "$summary" >> "$SUMMARY_JSONL" <<'PY'
import json
import sys
phase = sys.argv[1]
summary_path = sys.argv[2]
data = json.load(open(summary_path, encoding="utf-8"))
data["phase_name"] = phase
print(json.dumps(data, sort_keys=True))
PY
  log "phase=${phase} summary=${summary}"

  if [ "$DELETE_PASSED_SESSIONS" = "1" ]; then
    python - "$summary" "$latest" <<'PY'
import json
import shutil
import sys
summary = json.load(open(sys.argv[1], encoding="utf-8"))
session = sys.argv[2]
state = summary.get("state") or {}
stress = summary.get("stress_report") or {}
timed_out = bool(stress.get("timed_out_tools"))
if state.get("status") == "COMPLETED" and not timed_out:
    shutil.rmtree(session)
    print(f"deleted_completed_session={session}")
else:
    print(f"kept_session={session}")
PY
  fi
}

run_phase() {
  local phase="$1"
  local timeout_seconds="$2"
  local max_normalized="$3"
  local filter="$4"
  local profile="$5"
  local phase_log="${STABILITY_DIR}/${phase}.log"
  local rc=0

  check_free_space
  log "phase=${phase} start timeout=${timeout_seconds} max_normalized=${max_normalized} profile=${profile} filter=${filter}"
  {
    echo "[phase] ${phase}"
    echo "[before evidence hash]"
    if [ "$HASH_EACH_PHASE" = "1" ]; then
      sha256sum "$EVIDENCE"
    else
      echo "skipped HASH_EACH_PHASE=${HASH_EACH_PHASE}"
    fi
    cd "$WORKDIR"
    source .venv/bin/activate
    set +e
    python app.py analyze \
      --manifest "$MANIFEST" \
      --mode timeline \
      --tool-config "$TOOL_CONFIG" \
      --psort-profile "$profile" \
      --psort-filter "$filter" \
      --tool-timeout "$timeout_seconds" \
      --max-normalized-events "$max_normalized"
    rc=$?
    echo "[analysis exit code] ${rc}"
    echo "[after evidence hash]"
    if [ "$HASH_EACH_PHASE" = "1" ]; then
      sha256sum "$EVIDENCE"
    else
      echo "skipped HASH_EACH_PHASE=${HASH_EACH_PHASE}"
    fi
    exit "$rc"
  } > "$phase_log" 2>&1
  rc=$?
  log "phase=${phase} command exited rc=${rc} log=${phase_log}"
  if ! summarize_latest_session "$phase"; then
    log "phase=${phase} summary unavailable after rc=${rc}"
  fi
  python - "$STATUS_JSONL" "$phase" "$rc" "$phase_log" <<'PY'
import json
import sys
from datetime import datetime, timezone

path, phase, rc, phase_log = sys.argv[1:5]
with open(path, "a", encoding="utf-8") as handle:
    handle.write(json.dumps({
        "timestamp_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "phase": phase,
        "exit_code": int(rc),
        "phase_log": phase_log,
    }, sort_keys=True) + "\n")
PY
  return "$rc"
}

log "stability run started case=${CASE} run_id=${RUN_ID}"
log "workdir=${WORKDIR}"
log "manifest=${MANIFEST}"
log "tool_config=${TOOL_CONFIG}"
log "evidence=${EVIDENCE}"
log "delete_passed_sessions=${DELETE_PASSED_SESSIONS}"
log "hash_each_phase=${HASH_EACH_PHASE}"
log "stability_profile=${STABILITY_PROFILE}"
log "continue_after_failure=${CONTINUE_AFTER_FAILURE}"

if [ ! -f "$MANIFEST" ]; then
  log "missing manifest: ${MANIFEST}"
  exit 2
fi
if [ ! -f "$EVIDENCE" ]; then
  log "missing evidence: ${EVIDENCE}"
  exit 2
fi

FILTER_EVTX="data_type contains 'windows:evtx'"

run_optional_phase() {
  local phase="$1"
  shift
  if run_phase "$phase" "$@"; then
    return 0
  fi
  local rc=$?
  log "phase=${phase} failed rc=${rc}"
  if [ "$CONTINUE_AFTER_FAILURE" = "1" ]; then
    log "continuing after failure because CONTINUE_AFTER_FAILURE=1"
    return 0
  fi
  return "$rc"
}

case "$STABILITY_PROFILE" in
  lowmem)
    # Conservative profile for 8 GB hosts / 4 GB SIFT VMs.
    run_optional_phase "evtx_baseline_5k" "3600" "5000" "$FILTER_EVTX" "triage" || exit $?
    run_optional_phase "evtx_normalized_25k" "3600" "25000" "$FILTER_EVTX" "triage" || exit $?
    run_optional_phase "evtx_normalized_50k" "3600" "50000" "$FILTER_EVTX" "triage" || exit $?
    run_optional_phase "evtx_repeat_5k" "3600" "5000" "$FILTER_EVTX" "triage" || exit $?
    ;;
  timeout-only)
    run_optional_phase "timeout_probe_120s" "120" "5000" "$FILTER_EVTX" "triage" || true
    ;;
  baseline-only)
    run_optional_phase "evtx_baseline_5k" "3600" "5000" "$FILTER_EVTX" "triage" || exit $?
    ;;
  default)
    # Fast failure-mode test: proves timeout handling, partial accounting, unknowns, and validation.
    run_optional_phase "timeout_probe_120s" "120" "5000" "$FILTER_EVTX" "triage" || true

    # Clean baseline: proves full tool completion and full accounting with bounded report size.
    run_optional_phase "evtx_baseline_5k" "3600" "5000" "$FILTER_EVTX" "triage" || exit $?

    # Normalized/report stress ladder: proves larger report generation without changing evidence accounting.
    run_optional_phase "evtx_normalized_25k" "3600" "25000" "$FILTER_EVTX" "triage" || exit $?
    run_optional_phase "evtx_normalized_50k" "3600" "50000" "$FILTER_EVTX" "triage" || exit $?

    # Reproducibility check: rerun the bounded baseline and compare summaries manually.
    run_optional_phase "evtx_repeat_5k" "3600" "5000" "$FILTER_EVTX" "triage" || exit $?
    ;;
  *)
    log "unsupported STABILITY_PROFILE=${STABILITY_PROFILE}"
    exit 2
    ;;
esac

log "stability run completed summaries=${SUMMARY_JSONL}"
