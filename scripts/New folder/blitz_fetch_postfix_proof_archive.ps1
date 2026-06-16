param(
    [string]$VmHost = "192.168.88.133",
    [string]$VmUser = "sansforensics",
    [string]$Case = "BLITZ-RD01-PLASO",
    [string]$SessionId = "sess-20260601T010722Z-40b51cee",
    [string]$RunId = "20260601T005215Z",
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
$archiveName = "${SessionId}_postfix_proof_full.tar"
$remoteArchive = "/cases/${Case}/proof_exports/${archiveName}"
$remoteSha = "${remoteArchive}.sha256"
$remoteScriptPath = "/tmp/blitz-postfix-proof-archive.sh"
$localRemoteScript = Join-Path ([System.IO.Path]::GetTempPath()) ("blitz-postfix-proof-{0}.sh" -f ([System.Guid]::NewGuid().ToString("N")))
$sshArgs = @("-p", [string]$Port)
$scpArgs = @("-P", [string]$Port)

$remoteScript = @'
set -euo pipefail

CASE="$1"
SESSION_ID="$2"
RUN_ID="$3"
SKIP_ARCHIVE="$4"

CASE_DIR="/cases/${CASE}"
OUT="${CASE_DIR}/proof_exports/${SESSION_ID}_postfix_proof_full.tar"
SESSION_DIR="${CASE_DIR}/output/${SESSION_ID}"
RUN_DIR="${CASE_DIR}/analysis/runs/${RUN_ID}"

mkdir -p "${CASE_DIR}/proof_exports"

echo "===== postfix proof archive ====="
echo "case=${CASE_DIR}"
echo "session=${SESSION_DIR}"
echo "run=${RUN_DIR}"
echo "archive=${OUT}"

test -d "${SESSION_DIR}"
test -d "${RUN_DIR}"

if [ "${SKIP_ARCHIVE}" = "1" ] && [ -f "${OUT}" ]; then
  echo "archive_create=skipped_existing"
else
  rm -f "${OUT}" "${OUT}.sha256"
  tar -C "${CASE_DIR}" -cf "${OUT}" "output/${SESSION_ID}" "analysis/runs/${RUN_ID}"
  echo "archive_create=completed"
fi

sha256sum "${OUT}" > "${OUT}.sha256"
ls -lh "${OUT}" "${OUT}.sha256"
df -h /
'@
$remoteScript = $remoteScript -replace "`r`n", "`n"

try {
    [System.IO.File]::WriteAllText(
        $localRemoteScript,
        $remoteScript,
        [System.Text.UTF8Encoding]::new($false)
    )

    Write-Host "[remote archive]"
    Write-Host "${target}:${remoteArchive}"
    & scp @scpArgs $localRemoteScript "$($target):$remoteScriptPath"
    if ($LASTEXITCODE -ne 0) {
        throw "SCP remote archive script copy failed with exit code ${LASTEXITCODE}"
    }

    $skipFlag = if ($SkipArchive) { "1" } else { "0" }
    & ssh @sshArgs $target "chmod +x '$remoteScriptPath' && bash '$remoteScriptPath' '$Case' '$SessionId' '$RunId' '$skipFlag'; rc=`$?; rm -f '$remoteScriptPath'; exit `$rc"
    if ($LASTEXITCODE -ne 0) {
        throw "Remote proof archive failed with exit code ${LASTEXITCODE}"
    }
}
finally {
    if (Test-Path -LiteralPath $localRemoteScript) {
        Remove-Item -LiteralPath $localRemoteScript -Force
    }
}

Write-Host
Write-Host "[copy to host]"
& scp @scpArgs "$($target):$remoteArchive" $LocalProofDir
if ($LASTEXITCODE -ne 0) {
    throw "SCP proof archive copy failed with exit code ${LASTEXITCODE}"
}
& scp @scpArgs "$($target):$remoteSha" $LocalProofDir
if ($LASTEXITCODE -ne 0) {
    throw "SCP proof archive sha256 copy failed with exit code ${LASTEXITCODE}"
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
Write-Host "postfix_proof_archive_fetch=passed"
Write-Host $localArchive
Write-Host $localSha
