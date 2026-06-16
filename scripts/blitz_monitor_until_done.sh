#!/usr/bin/env bash
set -euo pipefail

CASE="${CASE:-BLITZ-RD01-PLASO}"
WORKDIR="${WORKDIR:-/home/sansforensics/src/Blitz_DFIR}"
INTERVAL="${INTERVAL:-15}"
MAX_WAIT_SECONDS="${MAX_WAIT_SECONDS:-0}"
CLEAR_SCREEN="${CLEAR_SCREEN:-0}"
STALE_GRACE_SECONDS="${STALE_GRACE_SECONDS:-180}"
SESSION_ARG="${1:-${SESSION:-}}"
PROCESS_PATTERN='app.py analyze|psort.py|log2timeline.py|tsk_e01_triage.py|(^|[[:space:]/])fls([[:space:]]|$)|(^|[[:space:]/])mmls([[:space:]]|$)|psteal.py|case.plaso'
START_EPOCH="$(date +%s)"

while true; do
  if [ "${CLEAR_SCREEN}" = "1" ] && [ -t 1 ]; then
    clear || true
  fi

  if [ -n "${SESSION_ARG}" ]; then
    BLITZ_STATUS_SUPPRESS_OPERATOR_RESULT=1 CASE="${CASE}" bash "${WORKDIR}/scripts/blitz_status.sh" "${SESSION_ARG}" || true
  else
    BLITZ_STATUS_SUPPRESS_OPERATOR_RESULT=1 CASE="${CASE}" bash "${WORKDIR}/scripts/blitz_status.sh" || true
  fi

  DECISION="$(
    python - "${CASE}" "${SESSION_ARG}" "${PROCESS_PATTERN}" "${STALE_GRACE_SECONDS}" <<'PY'
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

case = sys.argv[1]
session_arg = sys.argv[2]
process_pattern = sys.argv[3]
stale_grace_seconds = int(sys.argv[4])
case_root = Path(f"/cases/{case}")


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


def active_process_present() -> bool:
    result = subprocess.run(
        ["bash", "-lc", f"ps -eo pid,ppid,stat,etime,%mem,%cpu,rss,vsz,cmd | egrep {process_pattern!r} | grep -v grep"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return bool(result.stdout.strip())


def seconds_since(timestamp: object) -> int | None:
    if not isinstance(timestamp, str) or not timestamp:
        return None
    try:
        then = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    now = datetime.now(timezone.utc)
    return max(int((now - then).total_seconds()), 0)


def latest_run_root() -> Path | None:
    runs_root = case_root / "analysis" / "runs"
    if not runs_root.exists():
        return None
    runs = sorted((item for item in runs_root.iterdir() if item.is_dir()), key=lambda path: path.stat().st_mtime, reverse=True)
    return runs[0] if runs else None


def run_root_for_session(session: Path | None) -> Path | None:
    runs_root = case_root / "analysis" / "runs"
    if session is None or not runs_root.exists():
        return latest_run_root()
    runs = sorted((item for item in runs_root.iterdir() if item.is_dir()), key=lambda path: path.stat().st_mtime, reverse=True)
    for run in runs:
        session_path = run / "session_path.txt"
        if not session_path.exists():
            continue
        if session_path.read_text(encoding="utf-8").strip() == str(session):
            return run
    return latest_run_root()


def selected_session() -> Path | None:
    if session_arg:
        path = Path(session_arg)
        return path if path.exists() else None
    run_root = latest_run_root()
    if run_root:
        session_path = run_root / "session_path.txt"
        if session_path.exists():
            candidate = Path(session_path.read_text(encoding="utf-8").strip())
            if candidate.exists():
                return candidate
        return None
    output_root = case_root / "output"
    if output_root.exists():
        sessions = sorted(output_root.glob("sess-*"), key=lambda path: path.stat().st_mtime, reverse=True)
        if sessions:
            return sessions[0]
    return None


session = selected_session()
run_root = run_root_for_session(session)
if session is None:
    run_pid_alive = False
    if run_root:
        pid_path = run_root / "blitz.pid"
        if pid_path.exists():
            run_pid_alive = pid_alive(pid_path.read_text(encoding="utf-8").strip())
    if run_pid_alive or active_process_present():
        print("WAIT:no_session_yet")
    else:
        print("ERROR:no_session_and_no_live_process")
    raise SystemExit

run_status = load_json(run_root / "run_status.json") if run_root else {}
if run_status and bool(run_status.get("wait_for_completion")):
    operator_status = str(run_status.get("status") or "UNKNOWN")
    phase = str(run_status.get("phase") or "unknown")
    postrun_status = str(run_status.get("postrun_checks") or "UNKNOWN")
    analysis_pid_alive = pid_alive(run_status.get("analysis_pid"))
    supervisor_pid_alive = pid_alive(run_status.get("supervisor_pid"))
    if operator_status == "COMPLETED":
        print("DONE:run_completed")
    elif operator_status == "FAILED":
        print(f"ERROR:{phase or 'run_failed'}")
    elif active_process_present() or analysis_pid_alive or supervisor_pid_alive:
        print(f"WAIT:{phase};postrun={postrun_status}")
    else:
        print(f"ERROR:run_status_{operator_status.lower()}_no_live_process")
    raise SystemExit

progress = load_json(session / "audit" / "progress.json")
state = load_json(session / "audit" / "session_state.json")
status = str(progress.get("status") or state.get("status") or "UNKNOWN")
writer_pid = progress.get("writer_pid")
has_live_process = active_process_present()
progress_age = seconds_since(progress.get("updated_at_utc"))
if status == "COMPLETED":
    print("DONE:completed")
elif status in {"FAILED", "PARTIAL"}:
    print(f"ERROR:{status.lower()}")
elif status == "RUNNING" and not has_live_process and (writer_pid is None or not pid_alive(writer_pid)):
    if progress_age is not None and progress_age <= stale_grace_seconds:
        print(f"WAIT:recent_progress_no_process_age_{progress_age}s")
    else:
        print("ERROR:abandoned_or_partial")
else:
    print("WAIT:running")
PY
  )"

  echo
  case "${DECISION}" in
    DONE:completed|DONE:run_completed)
      echo "Blitz DFIR Process completed"
      exit 0
      ;;
    ERROR:*)
      echo "Blitz DFIR Process did not complete cleanly: ${DECISION#ERROR:}" >&2
      exit 2
      ;;
  esac

  if [ "${MAX_WAIT_SECONDS}" != "0" ]; then
    NOW_EPOCH="$(date +%s)"
    if [ "$((NOW_EPOCH - START_EPOCH))" -ge "${MAX_WAIT_SECONDS}" ]; then
      echo "Blitz DFIR monitor timed out before completion" >&2
      exit 124
    fi
  fi

  echo "monitor_decision=${DECISION}; next_refresh_seconds=${INTERVAL}; clear_screen=${CLEAR_SCREEN}"
  echo "Tip: use CLEAR_SCREEN=1 only if you want dashboard-style redraws. Press Ctrl+C in duplicate monitor terminals."
  echo
  sleep "${INTERVAL}"
done
