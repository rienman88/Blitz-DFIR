#!/usr/bin/env bash
set -euo pipefail

CASE="${CASE:-BLITZ-RD01-PLASO}"
CASE_ROOT="/cases/${CASE}"
KEEP_RECEIPTS="${KEEP_RECEIPTS:-1}"
APPLY="${APPLY:-0}"
FORCE="${FORCE:-0}"
PROCESS_PATTERN='app.py analyze|psort.py|log2timeline.py|tsk_e01_triage.py|(^|[[:space:]/])fls([[:space:]]|$)|(^|[[:space:]/])mmls([[:space:]]|$)|psteal.py|case.plaso'

df_unique() {
  {
    df -h "$@" 2>/dev/null || df -h / 2>/dev/null || true
  } | awk 'NR == 1 { print; next } !seen[$1 "|" $6]++'
}

if [[ ! -d "${CASE_ROOT}" ]]; then
  echo "case directory not found: ${CASE_ROOT}" >&2
  exit 2
fi

if [[ "${CASE_ROOT}" != /cases/* ]]; then
  echo "refusing unsafe case root: ${CASE_ROOT}" >&2
  exit 2
fi

ACTIVE_PROCESSES="$(ps -eo pid,ppid,stat,etime,%mem,%cpu,cmd | egrep "${PROCESS_PATTERN}" | grep -v grep || true)"
if [[ -n "${ACTIVE_PROCESSES}" ]]; then
  echo "[active Blitz/SIFT processes]"
  echo "${ACTIVE_PROCESSES}"
  echo
  if [[ "${FORCE}" != "1" ]]; then
    echo "refusing cleanup because an analysis/tool process is active. Stop it first, or rerun with FORCE=1 only after confirming it is safe." >&2
    exit 3
  fi
  echo "FORCE=1 set; continuing despite active process match."
  echo
fi

echo "[case]"
echo "${CASE_ROOT}"

echo
echo "[keep]"
printf '%s\n' \
  "${CASE_ROOT}/processed/case.plaso" \
  "${CASE_ROOT}/case.yaml"
if [[ "${KEEP_RECEIPTS}" == "1" ]]; then
  printf '%s\n' \
    "${CASE_ROOT}/analysis/run_receipts" \
    "${CASE_ROOT}/analysis/failed_run_receipts"
fi

echo
echo "[disk before]"
df_unique "${CASE_ROOT}" /

echo
echo "[delete candidates]"
find "${CASE_ROOT}/output" -mindepth 1 -maxdepth 1 -type d -name 'sess-*' -print 2>/dev/null || true
find "${CASE_ROOT}/analysis/runs" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null || true
find "${CASE_ROOT}/analysis/stability" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null || true
find "${CASE_ROOT}/analysis" -maxdepth 1 -type f \( -name '*.log' -o -name '*.pid' -o -name '*.jsonl' -o -name '*.tmp' \) -print 2>/dev/null || true

if [[ "${KEEP_RECEIPTS}" != "1" ]]; then
  find "${CASE_ROOT}/analysis/run_receipts" -mindepth 1 -print 2>/dev/null || true
  find "${CASE_ROOT}/analysis/failed_run_receipts" -mindepth 1 -print 2>/dev/null || true
fi

if [[ "${APPLY}" != "1" ]]; then
  echo
  echo "dry run only. Re-run with APPLY=1 after reviewing candidates."
  exit 0
fi

find "${CASE_ROOT}/output" -mindepth 1 -maxdepth 1 -type d -name 'sess-*' -exec rm -rf -- {} + 2>/dev/null || true
find "${CASE_ROOT}/analysis/runs" -mindepth 1 -maxdepth 1 -type d -exec rm -rf -- {} + 2>/dev/null || true
find "${CASE_ROOT}/analysis/stability" -mindepth 1 -maxdepth 1 -type d -exec rm -rf -- {} + 2>/dev/null || true
find "${CASE_ROOT}/analysis" -maxdepth 1 -type f \( -name '*.log' -o -name '*.pid' -o -name '*.jsonl' -o -name '*.tmp' \) -delete 2>/dev/null || true

if [[ "${KEEP_RECEIPTS}" != "1" ]]; then
  rm -rf "${CASE_ROOT}/analysis/run_receipts"/* "${CASE_ROOT}/analysis/failed_run_receipts"/* 2>/dev/null || true
fi

echo
echo "[disk after]"
df_unique "${CASE_ROOT}" /
