#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKDIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${WORKDIR}"

CASE="${CASE:-BLITZ-RD01-PLASO}"
CASE_ROOT="${CASE_ROOT:-/cases/${CASE}}"
SESSION="${1:-${SESSION:-}}"
PLASO="${PLASO:-${CASE_ROOT}/processed/case.plaso}"
OUTPUT_DIR="${OUTPUT_DIR:-${CASE_ROOT}/analysis/postrun_checks}"

if [[ -z "${SESSION}" ]]; then
  RUN_ROOT="$(ls -td "${CASE_ROOT}/analysis/runs"/* 2>/dev/null | head -n 1 || true)"
  if [[ -n "${RUN_ROOT}" && -f "${RUN_ROOT}/session_path.txt" ]]; then
    SESSION="$(cat "${RUN_ROOT}/session_path.txt")"
  fi
fi

if [[ -z "${SESSION}" ]]; then
  SESSION="$(ls -td "${CASE_ROOT}/output"/sess-* 2>/dev/null | head -n 1 || true)"
fi

if [[ -z "${SESSION}" || ! -d "${SESSION}" ]]; then
  echo "no session found for CASE=${CASE}" >&2
  exit 2
fi

mkdir -p "${OUTPUT_DIR}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SAFE_SESSION="$(basename "${SESSION}")"
PREFIX="${OUTPUT_DIR}/${STAMP}_${SAFE_SESSION}"
POSTRUN_MANIFEST="${OUTPUT_DIR}/${SAFE_SESSION}_latest_postrun_manifest.json"

write_postrun_manifest() {
  local status="$1"
  local current_check="$2"
  local message="${3:-}"
  python3 - \
    "${POSTRUN_MANIFEST}" \
    "${CASE}" \
    "${SESSION}" \
    "${PREFIX}" \
    "${status}" \
    "${current_check}" \
    "${message}" <<'PY'
from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

path = Path(sys.argv[1])
case = sys.argv[2]
session = sys.argv[3]
prefix = sys.argv[4]
status = sys.argv[5]
current_check = sys.argv[6]
message = sys.argv[7]

artifacts = {
    "status": f"{prefix}_status.txt",
    "e2e_check": f"{prefix}_e2e_check.txt",
    "llm_reasoning": f"{prefix}_llm_reasoning.txt",
    "session_summary": f"{prefix}_session_summary.json",
    "audit_attribution": f"{prefix}_audit_attribution.txt",
}
payload = {
    "schema_version": "blitz-postrun-manifest.v1",
    "case_id": case,
    "session": session,
    "status": status,
    "current_check": current_check,
    "updated_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    "message": message,
    "artifacts": artifacts,
    "ready": {name: Path(value).exists() for name, value in artifacts.items()},
}
path.parent.mkdir(parents=True, exist_ok=True)
tmp = path.with_suffix(path.suffix + ".tmp")
tmp.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
tmp.replace(path)
PY
}

write_postrun_manifest "RUNNING" "status" "Postrun checks started."

echo "[postrun scope]"
echo "case=${CASE}"
echo "session=${SESSION}"
echo "output_prefix=${PREFIX}"
echo

echo "[status]"
BLITZ_STATUS_SUPPRESS_OPERATOR_RESULT=1 bash scripts/blitz_status.sh "${SESSION}" \
  | tee "${PREFIX}_status.txt"

echo
echo "[e2e check]"
write_postrun_manifest "RUNNING" "e2e_check" "Running end-to-end artifact checks."
bash scripts/blitz_e2e_ollama_check.sh "${SESSION}" \
  | tee "${PREFIX}_e2e_check.txt"

echo
echo "[llm reasoning summary]"
write_postrun_manifest "RUNNING" "llm_reasoning" "Summarizing bounded LLM reasoning containment."
bash scripts/blitz_llm_reasoning_summary.sh "${SESSION}" \
  | tee "${PREFIX}_llm_reasoning.txt"

echo
echo "[session summary]"
write_postrun_manifest "RUNNING" "session_summary" "Building session summary."
if [[ -f "${PLASO}" ]]; then
  python scripts/sift_summarize_session.py "${SESSION}" "${PLASO}" \
    | tee "${PREFIX}_session_summary.json"
else
  python scripts/sift_summarize_session.py "${SESSION}" \
    | tee "${PREFIX}_session_summary.json"
fi

echo
echo "[audit attribution check]"
write_postrun_manifest "RUNNING" "audit_attribution" "Checking audit attribution fields and inferred attribution."
python - "${SESSION}" <<'PY' | tee "${PREFIX}_audit_attribution.txt"
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
        if isinstance(payload, dict):
            entries.append(payload)

fields = ("initiated_by", "component", "trust_boundary", "behavior")
counts = dict.fromkeys(fields, 0)
security_relevant = []
degraded = []
for entry in entries:
    data = entry.get("data")
    if not isinstance(data, dict):
        continue
    for field in fields:
        if data.get(field):
            counts[field] += 1
    behavior = str(data.get("behavior") or "")
    if behavior == "security_relevant_rejection":
        security_relevant.append(entry)
    elif behavior and behavior != "expected":
        degraded.append(entry)

print(f"session={session}")
print(f"audit_entry_count={len(entries)}")
for field in fields:
    print(f"{field}_count={counts[field]}")
if all(counts[field] == 0 for field in fields):
    print("audit_attribution_mode=legacy_inferred_by_status_script_only")
else:
    print("audit_attribution_mode=embedded_in_audit_entries")
print(f"security_relevant_event_count={len(security_relevant)}")
print(f"non_expected_behavior_count={len(degraded)}")
if security_relevant:
    print("security_relevant_events:")
    for item in security_relevant[:10]:
        data = item.get("data") if isinstance(item.get("data"), dict) else {}
        print(
            f"- seq={item.get('sequence')} event={item.get('event_type')} "
            f"tool={data.get('tool') or data.get('typed_tool')} reason={data.get('reason')}"
        )
if degraded:
    print("non_expected_behavior_samples:")
    for item in degraded[:10]:
        data = item.get("data") if isinstance(item.get("data"), dict) else {}
        print(
            f"- seq={item.get('sequence')} event={item.get('event_type')} "
            f"behavior={data.get('behavior')} component={data.get('component')}"
        )
PY

echo
echo "postrun_checks=passed"
echo "artifacts=${PREFIX}_*.txt ${PREFIX}_session_summary.json"
write_postrun_manifest "COMPLETED" "complete" "Postrun checks passed."
