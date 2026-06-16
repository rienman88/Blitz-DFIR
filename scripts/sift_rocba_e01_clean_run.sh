#!/usr/bin/env bash
set -euo pipefail

CASE="${CASE:-BLITZ-ROCBA-E01}"
WORKDIR="${WORKDIR:-/home/sansforensics/src/Blitz_DFIR}"
PYTHON="${PYTHON:-${WORKDIR}/.venv/bin/python}"
SRC_E01="${SRC_E01:-/home/sansforensics/Desktop/cases/Rocba-E01/rocba-cdrive.e01}"
EVIDENCE_ID="${EVIDENCE_ID:-rocba-cdrive-e01}"
CASE_ROOT="${CASE_ROOT:-/cases/${CASE}}"
RAW_DIR="${RAW_DIR:-${CASE_ROOT}/raw/Rocba-E01}"
OUTPUT_DIR="${OUTPUT_DIR:-${CASE_ROOT}/output}"
MANIFEST="${MANIFEST:-${CASE_ROOT}/case.yaml}"
TOOL_CONFIG="${TOOL_CONFIG:-${WORKDIR}/config/tools.yaml}"
IMPORT_MODE="${IMPORT_MODE:-in_place}"
CASE_OBJECTIVE="${CASE_OBJECTIVE:-Analyze the Rocba C-drive E01 for evidence-backed execution artifacts, persistence indicators, credential activity, user activity, temporal gaps, and unknowns while avoiding unsupported conclusions.}"

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
COPY_RESERVE_GB="${COPY_RESERVE_GB:-30}"
RECOMMENDED_FREE_GB="${RECOMMENDED_FREE_GB:-30}"
FORCE="${FORCE:-0}"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)_rocba_e01_no_llm"
RUN_ROOT="${RUN_ROOT:-${CASE_ROOT}/analysis/runs/${RUN_ID}}"
LOG="${RUN_ROOT}/launcher.log"
RUN_STATUS="${RUN_ROOT}/run_status.json"
PROCESS_PATTERN='app.py analyze|psort.py|log2timeline.py|tsk_e01_triage.py|(^|[[:space:]/])fls([[:space:]]|$)|(^|[[:space:]/])mmls([[:space:]]|$)|psteal.py|case.plaso'

fail() {
  local reason="$1"
  local code="${2:-2}"
  echo "preflight_failed=${reason}" >&2
  echo "case=${CASE:-unset}" >&2
  echo "case_root=${CASE_ROOT:-unset}" >&2
  echo "source_e01=${SRC_E01:-unset}" >&2
  echo "manifest=${MANIFEST:-unset}" >&2
  echo "workdir=${WORKDIR:-unset}" >&2
  exit "${code}"
}

df_unique() {
  {
    df -h "$@" 2>/dev/null || df -h / 2>/dev/null || true
  } | awk 'NR == 1 { print; next } !seen[$1 "|" $6]++'
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
    "schema_version": "blitz-e01-run-status.v1",
    "case_id": case,
    "run_id": run_id,
    "run_root": run_root,
    "status": status,
    "phase": phase,
    "updated_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    "postrun_checks": "NOT_CONFIGURED" if status == "COMPLETED" else "UNKNOWN",
    "postrun_checks_enabled": False,
    "postrun_checks_reason": (
        "E01 runner has no separate postrun QA phase; analysis validation, coverage, "
        "reporting, and artifact hashing complete inside the Blitz pipeline."
    ),
}
session_path = Path(run_root) / "session_path.txt"
if session_path.exists():
    payload["session"] = session_path.read_text(encoding="utf-8").strip()
if analysis_exit:
    payload["analysis_exit_code"] = int(analysis_exit)
if message:
    payload["message"] = message
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
PY
}

[[ -n "${CASE}" ]] || fail "empty_case"
[[ "${CASE_ROOT}" == /cases/* ]] || fail "unsafe_case_root"
[[ -d "${WORKDIR}" ]] || fail "workdir_not_found"
[[ -x "${PYTHON}" ]] || fail "python_not_executable"
[[ -f "${TOOL_CONFIG}" ]] || fail "tool_config_not_found"
[[ -f "${SRC_E01}" ]] || fail "source_e01_not_found"
[[ "${IMPORT_MODE}" == "copy" || "${IMPORT_MODE}" == "in_place" ]] || fail "import_mode_must_be_copy_or_in_place"

ACTIVE_PROCESSES="$(ps -eo pid,ppid,stat,etime,%mem,%cpu,cmd | egrep "${PROCESS_PATTERN}" | grep -v grep || true)"
if [[ -n "${ACTIVE_PROCESSES}" && "${FORCE}" != "1" ]]; then
  echo "[active Blitz/SIFT processes]"
  echo "${ACTIVE_PROCESSES}"
  echo
  echo "refusing to start another E01 run while analysis/tool work is active. Set FORCE=1 only after confirming this is safe." >&2
  exit 3
fi

mkdir -p "${RUN_ROOT}" "${OUTPUT_DIR}" "${CASE_ROOT}/analysis/runs"

SOURCE_DIR="$(dirname "${SRC_E01}")"
SOURCE_NAME="$(basename "${SRC_E01}")"

mapfile -t SOURCE_SEGMENTS < <("${PYTHON}" - "${SRC_E01}" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

source = Path(sys.argv[1]).resolve()
stem = re.sub(r"\.[eE]\d{2}$", "", source.name)
pattern = re.compile(re.escape(stem) + r"\.[eE]\d{2}$")
segments = sorted(
    (path for path in source.parent.iterdir() if path.is_file() and pattern.fullmatch(path.name)),
    key=lambda path: path.name.lower(),
)
if source not in segments:
    segments.insert(0, source)
for path in segments:
    print(path)
PY
)

if [[ "${IMPORT_MODE}" == "copy" ]]; then
  SOURCE_SIZE_GB="$("${PYTHON}" - "${SOURCE_SEGMENTS[@]}" <<'PY'
from __future__ import annotations

import math
import sys
from pathlib import Path

total = sum(Path(path).stat().st_size for path in sys.argv[1:])
print(max(math.ceil(total / (1024 ** 3)), 1))
PY
)"
  FREE_GB="$(df -BG "${CASE_ROOT}" 2>/dev/null | awk 'NR==2 {gsub(/G/, "", $4); print $4}')"
  REQUIRED_FREE_GB="$((SOURCE_SIZE_GB + COPY_RESERVE_GB))"
  if [[ -n "${FREE_GB}" && "${FREE_GB}" -lt "${REQUIRED_FREE_GB}" ]]; then
    echo "free space below E01 copy threshold: free_gb=${FREE_GB} required_free_gb=${REQUIRED_FREE_GB} source_size_gb=${SOURCE_SIZE_GB} reserve_gb=${COPY_RESERVE_GB}" >&2
    echo "Use IMPORT_MODE=in_place only if you accept reading the E01 from its current path without copying it to /cases raw storage." >&2
    exit 4
  fi
  mkdir -p "${RAW_DIR}"
  echo "[copy E01 evidence]"
  echo "source_size_gb=${SOURCE_SIZE_GB}"
  echo "required_free_gb=${REQUIRED_FREE_GB}"
  printf 'source_segments=%s\n' "${#SOURCE_SEGMENTS[@]}"
  for segment in "${SOURCE_SEGMENTS[@]}"; do
    echo "copying=${segment}"
    if command -v rsync >/dev/null 2>&1; then
      rsync -aH --info=progress2 --partial --append-verify --sparse "${segment}" "${RAW_DIR}/"
    else
      cp -a --reflink=auto --sparse=always "${segment}" "${RAW_DIR}/"
    fi
  done
  EVIDENCE_ROOT="$(dirname "${RAW_DIR}")"
  EVIDENCE_FILE="${RAW_DIR}/${SOURCE_NAME}"
  EVIDENCE_PATH="$(realpath --relative-to="${EVIDENCE_ROOT}" "${EVIDENCE_FILE}")"
  HASH_TARGETS=( "${RAW_DIR}"/* )
else
  FREE_GB="$(df -BG "${CASE_ROOT}" 2>/dev/null | awk 'NR==2 {gsub(/G/, "", $4); print $4}')"
  if [[ -n "${FREE_GB}" && "${FREE_GB}" -lt "${MIN_FREE_GB}" ]]; then
    echo "free space below E01 in-place threshold: free_gb=${FREE_GB} min_free_gb=${MIN_FREE_GB}" >&2
    exit 4
  fi
  if [[ -n "${FREE_GB}" && "${FREE_GB}" -lt "${RECOMMENDED_FREE_GB}" ]]; then
    echo "warning=free_space_below_recommended free_gb=${FREE_GB} recommended_free_gb=${RECOMMENDED_FREE_GB}" >&2
    echo "warning=full_log2timeline_may_fail_but_disk_triage_fallback_can_still_run raw_evidence_not_copied" >&2
  fi
  EVIDENCE_ROOT="${SOURCE_DIR}"
  EVIDENCE_FILE="${SRC_E01}"
  EVIDENCE_PATH="${SOURCE_NAME}"
  HASH_TARGETS=( "${SOURCE_SEGMENTS[@]}" )
fi

[[ -f "${EVIDENCE_FILE}" ]] || fail "evidence_file_not_ready_after_import"

FIRST_HASH="$(sha256sum "${EVIDENCE_FILE}" | awk '{print $1}')"
{
  for target in "${HASH_TARGETS[@]}"; do
    [[ -f "${target}" ]] || continue
    sha256sum "${target}"
  done
} | tee "${CASE_ROOT}/SHA256SUMS.txt" >/dev/null

cat > "${MANIFEST}" <<EOF
case_id: ${CASE}
evidence_root: ${EVIDENCE_ROOT}
output_root: ${OUTPUT_DIR}
evidence:
  - id: ${EVIDENCE_ID}
    path: "${EVIDENCE_PATH}"
    type: E01
    sha256: ${FIRST_HASH}
    description: "Rocba C-drive E01 image for E01-only Blitz test."
EOF

chmod a-w "${MANIFEST}" "${CASE_ROOT}/SHA256SUMS.txt" 2>/dev/null || true
if [[ "${IMPORT_MODE}" == "copy" ]]; then
  chmod a-w "${RAW_DIR}"/* 2>/dev/null || true
fi

{
  echo "[scope]"
  echo "case=${CASE}"
  echo "run_id=${RUN_ID}"
  echo "run_mode=clean"
  echo "run_root=${RUN_ROOT}"
  echo "workdir=${WORKDIR}"
  echo "source_e01=${SRC_E01}"
  echo "import_mode=${IMPORT_MODE}"
  echo "evidence_file=${EVIDENCE_FILE}"
  echo "manifest=${MANIFEST}"
  echo "case_root=${CASE_ROOT}"
  echo "tool_config=${TOOL_CONFIG}"
  echo "case_objective=${CASE_OBJECTIVE}"
  echo "enable_reasoning=0"
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
  sed -n '1,120p' "${MANIFEST}"
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
print(f"manifest_ok=1 case_id={manifest.case_id} evidence_count={len(manifest.evidence)}")
for evidence in manifest.evidence:
    print(
        "evidence "
        f"id={evidence.evidence_id} type={evidence.evidence_type.value} "
        f"path={evidence.path} verified={evidence.verified} size={evidence.size_bytes}"
    )
PY
  )
} | tee "${LOG}"

write_run_status "RUNNING" "analysis_starting" "" "E01 runner preflight completed."

ANALYZE_ARGS=(
  app.py analyze
  --manifest "${MANIFEST}"
  --case-objective "${CASE_OBJECTIVE}"
  --mode timeline
  --tool-config "${TOOL_CONFIG}"
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
    CASE_ROOT="${CASE_ROOT}" \
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
  write_run_status "COMPLETED" "analysis_completed" "${ANALYSIS_EXIT}" "E01 analysis completed."
else
  write_run_status "FAILED" "analysis_failed" "${ANALYSIS_EXIT}" "E01 analysis exited non-zero."
fi

echo
echo "[status]"
CASE="${CASE}" bash "${WORKDIR}/scripts/blitz_status.sh" || true

exit "${ANALYSIS_EXIT}"
