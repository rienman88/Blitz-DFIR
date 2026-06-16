#!/usr/bin/env bash
set -euo pipefail

CASE="${CASE:-BLITZ-RD01-PLASO}"
CASE_ROOT="${CASE_ROOT:-/cases/${CASE}}"
WORKDIR="${WORKDIR:-/home/sansforensics/src/Blitz_DFIR}"
SESSION="${SESSION:-${1:-}}"
RUN_ROOT="${RUN_ROOT:-}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${OUT:-/tmp/${CASE}_failure_diag_${STAMP}.txt}"
PROCESS_PATTERN='app.py analyze|(^|[[:space:]/])vol([[:space:]]|$)|psort.py|log2timeline.py|tsk_e01_triage.py|(^|[[:space:]/])fls([[:space:]]|$)|(^|[[:space:]/])mmls([[:space:]]|$)|psteal.py|case.plaso|ollama'

if [[ -z "${RUN_ROOT}" && -d "${CASE_ROOT}/analysis/runs" ]]; then
  RUN_ROOT="$(ls -td "${CASE_ROOT}/analysis/runs"/* 2>/dev/null | head -n 1 || true)"
fi

if [[ -z "${SESSION}" && -n "${RUN_ROOT}" && -f "${RUN_ROOT}/session_path.txt" ]]; then
  SESSION="$(cat "${RUN_ROOT}/session_path.txt" 2>/dev/null || true)"
fi

if [[ -z "${SESSION}" && -d "${CASE_ROOT}/output" ]]; then
  SESSION="$(ls -td "${CASE_ROOT}/output"/sess-* 2>/dev/null | head -n 1 || true)"
fi

sqlite_count() {
  local db="$1"
  local table="$2"
  if [[ -f "${db}" ]] && command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "${db}" "SELECT COUNT(*) FROM ${table};" 2>/dev/null || true
  fi
}

{
  echo "CASE=${CASE}"
  echo "CASE_ROOT=${CASE_ROOT}"
  echo "RUN_ROOT=${RUN_ROOT:-none}"
  echo "SESSION=${SESSION:-none}"
  echo "WORKDIR=${WORKDIR}"
  echo "DIAGNOSTIC_UTC=${STAMP}"
  echo

  echo "=== process check ==="
  ps -eo pid,ppid,stat,etime,%mem,%cpu,rss,vsz,cmd | egrep "${PROCESS_PATTERN}" | grep -v grep || true
  echo

  echo "=== disk ==="
  df -h "${CASE_ROOT}" / /tmp 2>/dev/null || df -h / || true
  echo
  if [[ -d "${CASE_ROOT}" ]]; then
    du -sh "${CASE_ROOT}/output" "${CASE_ROOT}/analysis" 2>/dev/null || true
  fi
  echo

  echo "=== memory ==="
  free -h || true
  swapon --show || true
  echo

  echo "=== latest run status ==="
  if [[ -n "${RUN_ROOT}" && -f "${RUN_ROOT}/run_status.json" ]]; then
    cat "${RUN_ROOT}/run_status.json"
  else
    echo "run_status_missing"
  fi
  echo

  echo "=== blitz status ==="
  if [[ -x "${WORKDIR}/scripts/blitz_status.sh" || -f "${WORKDIR}/scripts/blitz_status.sh" ]]; then
    if [[ -n "${SESSION}" ]]; then
      BLITZ_STATUS_SUPPRESS_OPERATOR_RESULT=1 CASE="${CASE}" bash "${WORKDIR}/scripts/blitz_status.sh" "${SESSION}" || true
    else
      BLITZ_STATUS_SUPPRESS_OPERATOR_RESULT=1 CASE="${CASE}" bash "${WORKDIR}/scripts/blitz_status.sh" || true
    fi
  else
    echo "status_script_missing=${WORKDIR}/scripts/blitz_status.sh"
  fi
  echo

  echo "=== launcher tail ==="
  if [[ -n "${RUN_ROOT}" && -f "${RUN_ROOT}/launcher.log" ]]; then
    tail -n 220 "${RUN_ROOT}/launcher.log"
  else
    echo "launcher_log_missing"
  fi
  echo

  echo "=== run exit ==="
  if [[ -n "${RUN_ROOT}" && -f "${RUN_ROOT}/run_exit.txt" ]]; then
    cat "${RUN_ROOT}/run_exit.txt"
  else
    echo "run_exit_missing"
  fi
  echo

  echo "=== session state ==="
  if [[ -n "${SESSION}" && -f "${SESSION}/audit/session_state.json" ]]; then
    cat "${SESSION}/audit/session_state.json"
  else
    echo "session_state_missing"
  fi
  echo

  echo "=== progress ==="
  if [[ -n "${SESSION}" && -f "${SESSION}/audit/progress.json" ]]; then
    cat "${SESSION}/audit/progress.json"
  else
    echo "progress_missing"
  fi
  echo

  echo "=== sqlite event store ==="
  if [[ -n "${SESSION}" ]]; then
    ls -lh "${SESSION}/findings/event_store.sqlite"* 2>/dev/null || true
    DB="${SESSION}/findings/event_store.sqlite"
    if [[ -f "${DB}" ]]; then
      echo "normalized_events_count=$(sqlite_count "${DB}" normalized_events)"
      echo "normalized_events_next_count=$(sqlite_count "${DB}" normalized_events_next)"
    fi
  fi
  echo

  echo "=== recent errors ==="
  if [[ -n "${RUN_ROOT}" ]]; then
    grep -RniE 'error|failed|traceback|killed|out of memory|no space|timeout|exit_code=1|analysis_exit=' "${RUN_ROOT}" 2>/dev/null | tail -n 160 || true
  fi
  if [[ -n "${SESSION}" ]]; then
    grep -RniE 'error|failed|traceback|killed|out of memory|no space|timeout|exit_code=1|analysis_exit=' "${SESSION}" 2>/dev/null | tail -n 160 || true
  fi
} | tee "${OUT}"

echo
echo "diagnostic_written=${OUT}"
