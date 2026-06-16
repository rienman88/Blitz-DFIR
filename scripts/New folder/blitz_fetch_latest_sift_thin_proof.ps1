param(
    [string]$VmHost = "192.168.88.133",
    [string]$VmUser = "sansforensics",
    [string]$Case = "BLITZ-RD01-PLASO",
    [string]$SessionId = "",
    [string]$RunId = "",
    [string]$LocalProofDir = "",
    [int]$Port = 22,
    [switch]$SkipArchive
)

$ErrorActionPreference = "Stop"

if (-not $LocalProofDir) {
    $repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
    $LocalProofDir = Join-Path $repoRoot "Blitz_DFIR_Proof"
}

New-Item -ItemType Directory -Force -Path $LocalProofDir | Out-Null

$target = "${VmUser}@${VmHost}"
$remoteScriptPath = "/tmp/blitz-fetch-latest-thin-proof.sh"
$localRemoteScript = Join-Path ([System.IO.Path]::GetTempPath()) ("blitz-fetch-thin-proof-{0}.sh" -f ([System.Guid]::NewGuid().ToString("N")))
$sshArgs = @("-p", [string]$Port)
$scpArgs = @("-P", [string]$Port)

$remoteScript = @'
set -euo pipefail

CASE="$1"
REQUESTED_SESSION_ID="$2"
REQUESTED_RUN_ID="$3"
SKIP_ARCHIVE="$4"

CASE_DIR="/cases/${CASE}"
OUTPUT_DIR="${CASE_DIR}/output"
RUNS_DIR="${CASE_DIR}/analysis/runs"
POSTRUN_DIR="${CASE_DIR}/analysis/postrun_checks"
EXPORT_DIR="${CASE_DIR}/proof_exports"
STATUS_SCRIPT="/home/sansforensics/src/Blitz_DFIR/scripts/blitz_status.sh"

mkdir -p "${EXPORT_DIR}"

DISCOVERY="$(
python3 - "${CASE_DIR}" "${REQUESTED_SESSION_ID}" "${REQUESTED_RUN_ID}" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

case_dir = Path(sys.argv[1])
requested_session_id = sys.argv[2].strip()
requested_run_id = sys.argv[3].strip()
output_dir = case_dir / "output"
runs_dir = case_dir / "analysis" / "runs"


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


if requested_session_id:
    session = output_dir / requested_session_id
    if not session.is_dir():
        raise SystemExit(f"requested session not found: {session}")
else:
    sessions = sorted(output_dir.glob("sess-*"), key=lambda path: path.stat().st_mtime, reverse=True)
    session = None
    for candidate in sessions:
        progress = load_json(candidate / "audit" / "progress.json")
        state = load_json(candidate / "audit" / "session_state.json")
        if progress.get("status") == "COMPLETED" or state.get("status") == "COMPLETED":
            session = candidate
            break
    if session is None and sessions:
        session = sessions[0]
    if session is None:
        raise SystemExit(f"no sessions found under {output_dir}")

if requested_run_id:
    run = runs_dir / requested_run_id
    if not run.is_dir():
        raise SystemExit(f"requested run not found: {run}")
else:
    run = None
    runs = sorted((path for path in runs_dir.glob("*") if path.is_dir()), key=lambda path: path.stat().st_mtime, reverse=True)
    for candidate in runs:
        pointer = candidate / "session_path.txt"
        if pointer.exists() and pointer.read_text(encoding="utf-8").strip() == str(session):
            run = candidate
            break
    if run is None:
        raise SystemExit(f"no run bundle points to session: {session}")

print(f"SESSION_ID={session.name}")
print(f"RUN_ID={run.name}")
print(f"SESSION_DIR={session}")
print(f"RUN_DIR={run}")
PY
)"

eval "${DISCOVERY}"

ARCHIVE="${EXPORT_DIR}/${SESSION_ID}_thin_layer_proof.tar.gz"
STATUS_CAPTURE="${EXPORT_DIR}/${SESSION_ID}_status_review_map.txt"
POSTRUN_MANIFEST="${POSTRUN_DIR}/${SESSION_ID}_latest_postrun_manifest.json"

echo "===== latest SIFT thin proof archive ====="
echo "case=${CASE_DIR}"
echo "session=${SESSION_DIR}"
echo "run=${RUN_DIR}"
echo "status_capture=${STATUS_CAPTURE}"
echo "postrun_manifest=${POSTRUN_MANIFEST}"
echo "archive=${ARCHIVE}"

test -d "${SESSION_DIR}"
test -d "${RUN_DIR}"

if [ -f "${STATUS_SCRIPT}" ]; then
  CASE="${CASE}" BLITZ_STATUS_SUPPRESS_OPERATOR_RESULT=1 bash "${STATUS_SCRIPT}" "${SESSION_DIR}" > "${STATUS_CAPTURE}" 2>&1 || {
    {
      echo "status_capture_failed=true"
      echo "status_script=${STATUS_SCRIPT}"
      echo "session=${SESSION_DIR}"
    } > "${STATUS_CAPTURE}"
  }
else
  {
    echo "status_capture_available=false"
    echo "status_script_missing=${STATUS_SCRIPT}"
    echo "session=${SESSION_DIR}"
  } > "${STATUS_CAPTURE}"
fi
sha256sum "${STATUS_CAPTURE}" > "${STATUS_CAPTURE}.sha256"

if [ "${SKIP_ARCHIVE}" = "1" ] && [ -f "${ARCHIVE}" ]; then
  echo "archive_create=skipped_existing"
else
  rm -f "${ARCHIVE}" "${ARCHIVE}.sha256"
  TAR_ITEMS=("output/${SESSION_ID}" "analysis/runs/${RUN_ID}")
  if [ -f "${CASE_DIR}/case.yaml" ]; then
    TAR_ITEMS+=("case.yaml")
  fi
  if [ -f "${POSTRUN_MANIFEST}" ]; then
    TAR_ITEMS+=("analysis/postrun_checks/${SESSION_ID}_latest_postrun_manifest.json")
  fi
  TAR_ITEMS+=("proof_exports/${SESSION_ID}_status_review_map.txt")
  TAR_ITEMS+=("proof_exports/${SESSION_ID}_status_review_map.txt.sha256")

  tar -C "${CASE_DIR}" \
    --exclude="output/${SESSION_ID}/timelines" \
    --exclude="output/${SESSION_ID}/findings/event_store.sqlite" \
    --exclude="output/${SESSION_ID}/findings/event_store.sqlite-wal" \
    --exclude="output/${SESSION_ID}/findings/event_store.sqlite-shm" \
    --exclude="output/${SESSION_ID}/findings/normalized_events.json" \
    --exclude="output/${SESSION_ID}/findings/full_accounting.json" \
    --exclude="output/${SESSION_ID}/findings/tool_results.json" \
    -czf "${ARCHIVE}" "${TAR_ITEMS[@]}"
  echo "archive_create=completed"
fi

sha256sum "${ARCHIVE}" > "${ARCHIVE}.sha256"
ls -lh "${ARCHIVE}" "${ARCHIVE}.sha256" "${STATUS_CAPTURE}" "${STATUS_CAPTURE}.sha256"
df -h /
'@
$remoteScript = $remoteScript -replace "`r`n", "`n"

try {
    [System.IO.File]::WriteAllText(
        $localRemoteScript,
        $remoteScript,
        [System.Text.UTF8Encoding]::new($false)
    )

    Write-Host "[remote thin proof archive]"
    Write-Host "${target}:/cases/${Case}/proof_exports/"
    & scp @scpArgs $localRemoteScript "$($target):$remoteScriptPath"
    if ($LASTEXITCODE -ne 0) {
        throw "SCP remote thin proof script copy failed with exit code ${LASTEXITCODE}"
    }

    $skipFlag = if ($SkipArchive) { "1" } else { "0" }
    $remoteOutput = & ssh @sshArgs $target "chmod +x '$remoteScriptPath' && bash '$remoteScriptPath' '$Case' '$SessionId' '$RunId' '$skipFlag'; rc=`$?; rm -f '$remoteScriptPath'; exit `$rc"
    $remoteOutput | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) {
        throw "Remote thin proof archive failed with exit code ${LASTEXITCODE}"
    }
}
finally {
    if (Test-Path -LiteralPath $localRemoteScript) {
        Remove-Item -LiteralPath $localRemoteScript -Force
    }
}

$archiveLine = $remoteOutput | Where-Object { $_ -like "archive=*" } | Select-Object -Last 1
if (-not $archiveLine) {
    throw "Remote output did not include archive path"
}
$remoteArchive = $archiveLine.Substring("archive=".Length).Trim()
$remoteSha = "${remoteArchive}.sha256"
$archiveName = Split-Path -Leaf $remoteArchive

Write-Host
Write-Host "[copy to host]"
& scp @scpArgs "$($target):$remoteArchive" $LocalProofDir
if ($LASTEXITCODE -ne 0) {
    throw "SCP thin proof archive copy failed with exit code ${LASTEXITCODE}"
}
& scp @scpArgs "$($target):$remoteSha" $LocalProofDir
if ($LASTEXITCODE -ne 0) {
    throw "SCP thin proof archive sha256 copy failed with exit code ${LASTEXITCODE}"
}

$localArchive = Join-Path $LocalProofDir $archiveName
$localSha = Join-Path $LocalProofDir "${archiveName}.sha256"
$expected = ((Get-Content -LiteralPath $localSha -Raw).Trim() -split "\s+")[0].ToUpperInvariant()
$actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $localArchive).Hash.ToUpperInvariant()
$size = (Get-Item -LiteralPath $localArchive).Length

Write-Host
Write-Host "[verify]"
Write-Host "expected=$expected"
Write-Host "actual=$actual"
Write-Host "size_bytes=$size"
if ($expected -ne $actual) {
    throw "Hash mismatch for ${archiveName}"
}

Write-Host
Write-Host "latest_sift_thin_proof_fetch=passed"
Write-Host $localArchive
Write-Host $localSha
