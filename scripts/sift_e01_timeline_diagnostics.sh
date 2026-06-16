#!/usr/bin/env bash
set -euo pipefail

CASE="${CASE:-BLITZ-ROCBA-MEMORY-E01}"
WORKDIR="${WORKDIR:-/home/sansforensics/src/Blitz_DFIR}"
PYTHON="${PYTHON:-${WORKDIR}/.venv/bin/python}"
CASE_ROOT="${CASE_ROOT:-/cases/${CASE}}"
SESSION="${SESSION:-}"
MANIFEST="${MANIFEST:-${CASE_ROOT}/case.yaml}"

if [[ -z "${SESSION}" ]]; then
  SESSION="$(ls -td "${CASE_ROOT}/output"/sess-* 2>/dev/null | head -n 1 || true)"
fi

echo "[scope]"
echo "case=${CASE}"
echo "case_root=${CASE_ROOT}"
echo "session=${SESSION:-none}"
echo "manifest=${MANIFEST}"
echo "python=${PYTHON}"
echo

echo "[tool versions]"
for tool in log2timeline.py psort.py pinfo.py ewfinfo ewfverify mmls fls; do
  printf '%s=' "${tool}"
  command -v "${tool}" || true
done
log2timeline.py --version 2>/dev/null || true
psort.py --version 2>/dev/null || true
echo

echo "[manifest e01 paths]"
"${PYTHON}" - "${MANIFEST}" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path

import yaml

path = Path(sys.argv[1])
if not path.exists():
    raise SystemExit(0)
raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
for item in raw.get("evidence", []) or []:
    if str(item.get("type", "")).upper() == "E01":
        print(item.get("path", ""))
PY
echo

if [[ -n "${SESSION}" && -d "${SESSION}" ]]; then
  echo "[timeline tool results]"
  "${PYTHON}" - "${SESSION}/findings/tool_results.json" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.exists():
    raise SystemExit(0)
for item in json.loads(path.read_text(encoding="utf-8")):
    tool = item.get("tool_name") or item.get("typed_tool")
    if tool in {"log2timeline", "timeline", "psort", "disk_triage"} or item.get("evidence_id", "").lower().endswith("e01"):
        print(json.dumps({
            "command": (item.get("execution") or {}).get("command") or item.get("command"),
            "tool_name": item.get("tool_name"),
            "evidence_id": item.get("evidence_id"),
            "exit_code": item.get("exit_code") or (item.get("execution") or {}).get("exit_code"),
            "timed_out": item.get("timed_out") or (item.get("execution") or {}).get("timed_out"),
            "primary_output_path": item.get("primary_output_path") or (item.get("outputs") or {}).get("primary_output"),
            "stderr_path": item.get("stderr_path") or (item.get("outputs") or {}).get("stderr"),
        }, sort_keys=True))
PY
  echo

  echo "[stderr tails]"
  find "${SESSION}/timelines" -type f \( -name '*.stderr.txt' -o -name '*log2timeline*.log.gz' \) -print 2>/dev/null |
  while IFS= read -r path; do
    echo "--- ${path}"
    case "${path}" in
      *.gz) gzip -cd "${path}" 2>/dev/null | tail -n 80 || true ;;
      *) tail -n 80 "${path}" || true ;;
    esac
  done
  find "${SESSION}/findings" -type f \( -name '*disk_triage*.stderr.txt' -o -name '*.disk_triage.json' \) -print 2>/dev/null |
  while IFS= read -r path; do
    echo "--- ${path}"
    tail -n 80 "${path}" || true
  done
  echo
fi

echo "[e01 filesystem view]"
"${PYTHON}" - "${MANIFEST}" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path

import yaml

path = Path(sys.argv[1])
if not path.exists():
    raise SystemExit(0)
raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
for item in raw.get("evidence", []) or []:
    if str(item.get("type", "")).upper() != "E01":
        continue
    e01 = Path(str(item.get("path", "")))
    print(f"path={e01}")
    print(f"exists={e01.exists()}")
    if e01.exists():
        print(f"size_bytes={e01.stat().st_size}")
        stem = e01.name.rsplit(".", 1)[0]
        segments = sorted(e01.parent.glob(stem + ".E??")) + sorted(e01.parent.glob(stem + ".e??"))
        print("segments=" + ", ".join(str(segment.name) for segment in segments))
PY
