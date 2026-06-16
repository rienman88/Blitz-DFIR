#!/usr/bin/env bash
set -euo pipefail

APPLY="${APPLY:-0}"
GRACE_SECONDS="${GRACE_SECONDS:-10}"
PROCESS_PATTERN="${PROCESS_PATTERN:-app.py analyze|psort.py|log2timeline.py|psteal.py|case.plaso}"

mapfile -t PIDS < <(
  ps -eo pid=,cmd= \
    | egrep "${PROCESS_PATTERN}" \
    | grep -v grep \
    | awk '{print $1}' \
    | sort -u
)

echo "[matched Blitz/SIFT processes]"
if [[ "${#PIDS[@]}" -eq 0 ]]; then
  echo "none"
  exit 0
fi

ps -fp "$(IFS=,; echo "${PIDS[*]}")" || true

if [[ "${APPLY}" != "1" ]]; then
  echo
  echo "dry run only. Re-run with APPLY=1 to send TERM, then KILL remaining matched processes after ${GRACE_SECONDS}s."
  exit 0
fi

echo
echo "[terminate]"
kill -TERM "${PIDS[@]}" 2>/dev/null || true
sleep "${GRACE_SECONDS}"

mapfile -t REMAINING < <(
  ps -eo pid=,cmd= \
    | egrep "${PROCESS_PATTERN}" \
    | grep -v grep \
    | awk '{print $1}' \
    | sort -u
)

if [[ "${#REMAINING[@]}" -gt 0 ]]; then
  echo "[force kill remaining]"
  ps -fp "$(IFS=,; echo "${REMAINING[*]}")" || true
  kill -KILL "${REMAINING[@]}" 2>/dev/null || true
fi

echo
echo "[after]"
ps -eo pid,ppid,stat,etime,%mem,%cpu,cmd \
  | egrep "${PROCESS_PATTERN}" \
  | grep -v grep || echo "no matched Blitz/SIFT processes remain"
