#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${ZIP:-}" ]]; then
  ZIP="$(ls -t "$HOME"/blitz_dfir_deploy_*.zip 2>/dev/null | head -n 1 || true)"
  ZIP="${ZIP:-$HOME/blitz_dfir_deploy_20260615_sqlite_cap_checkpoint.zip}"
fi
EXPECTED_SHA256="${EXPECTED_SHA256:-}"
SRC_ROOT="${SRC_ROOT:-/home/sansforensics/src}"
APP="${APP:-${SRC_ROOT}/Blitz_DFIR}"
DEPLOY="${DEPLOY:-/tmp/$(basename "${ZIP}" .zip)}"

if [[ ! -f "${ZIP}" ]]; then
  echo "deploy_zip_missing=${ZIP}" >&2
  echo "Copy it from Windows first with scp, then rerun this deploy command." >&2
  exit 2
fi

if [[ -n "${EXPECTED_SHA256}" ]]; then
  echo "${EXPECTED_SHA256}  ${ZIP}" | sha256sum -c -
fi

if [[ ! -d "${APP}" ]]; then
  echo "app_dir_missing=${APP}" >&2
  exit 2
fi

cd "${SRC_ROOT}"
cp -a Blitz_DFIR "Blitz_DFIR.backup.$(date -u +%Y%m%dT%H%M%SZ)"
rm -rf "${DEPLOY}"
mkdir -p "${DEPLOY}"
unzip -oq "${ZIP}" -d "${DEPLOY}"

if [[ ! -d "${DEPLOY}/Blitz_DFIR" ]]; then
  echo "deploy_payload_missing=${DEPLOY}/Blitz_DFIR" >&2
  exit 2
fi

rsync -a --delete \
  --exclude '.venv/' \
  --exclude '__pycache__/' \
  --exclude '.pytest_cache/' \
  "${DEPLOY}/Blitz_DFIR/" "${APP}/"

cd "${APP}"
.venv/bin/python -m compileall -q app.py blitz_dfir tests

echo "deploy_complete=${APP}"
grep -n 'vss_stores.*default="none"' blitz_dfir/tools/log2timeline_tool.py
grep -n 'BLITZ_LOG2TIMELINE_VSS_STORES", "none"' blitz_dfir/pipeline/analyze.py
grep -n 'disk_triage' config/tools.yaml blitz_dfir/pipeline/analyze.py blitz_dfir/mcp/default_tools.py
