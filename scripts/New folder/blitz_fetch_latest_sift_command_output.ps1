param(
    [string]$VmHost = "192.168.88.133",
    [string]$VmUser = "sansforensics",
    [string]$Case = "BLITZ-RD01-PLASO",
    [string]$RemotePath = "/home/sansforensics/src/Blitz_DFIR",
    [string]$LocalProofDir = "",
    [int]$Port = 22
)

$ErrorActionPreference = "Stop"

if (-not $LocalProofDir) {
    $repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
    $LocalProofDir = Join-Path $repoRoot "Blitz_DFIR_Proof"
}

New-Item -ItemType Directory -Force -Path $LocalProofDir | Out-Null

$target = "${VmUser}@${VmHost}"
$remoteOut = "/cases/${Case}/proof_exports/latest_command_output.txt"
$remoteSha = "${remoteOut}.sha256"
$sshArgs = @("-p", [string]$Port)
$scpArgs = @("-P", [string]$Port)

$remoteScript = @'
set -euo pipefail
WORKDIR="$1"
CASE="$2"
OUT="/cases/${CASE}/proof_exports/latest_command_output.txt"
mkdir -p "/cases/${CASE}/proof_exports"
cd "${WORKDIR}"

{
  echo "===== compile/check output ====="
  python -m compileall -q app.py blitz_dfir scripts tests
  echo "compileall_exit=$?"

  echo
  echo "===== dedupe code check ====="
  grep -n "_dedupe_findings" blitz_dfir/correlation/sqlite_backend.py
  grep -n "model narrative suppressed" blitz_dfir/reasoning/analyst.py

  echo
  echo "===== cleanup dry run ====="
  CASE="${CASE}" bash scripts/sift_clean_generated_for_rerun.sh
} 2>&1 | tee "${OUT}"

sha256sum "${OUT}" > "${OUT}.sha256"
ls -l "${OUT}" "${OUT}.sha256"
'@
$remoteScript = $remoteScript -replace "`r`n", "`n"
$localRemoteScript = Join-Path ([System.IO.Path]::GetTempPath()) ("blitz-fetch-latest-{0}.sh" -f ([System.Guid]::NewGuid().ToString("N")))
$remoteScriptPath = "/tmp/blitz-fetch-latest-command-output.sh"

Write-Host "[remote capture]"
Write-Host "${target}:${remoteOut}"
try {
    [System.IO.File]::WriteAllText(
        $localRemoteScript,
        $remoteScript,
        [System.Text.UTF8Encoding]::new($false)
    )

    & scp @scpArgs $localRemoteScript "$($target):$remoteScriptPath"
    if ($LASTEXITCODE -ne 0) {
        throw "SCP remote capture script copy failed with exit code ${LASTEXITCODE}"
    }

    & ssh @sshArgs $target "chmod +x '$remoteScriptPath' && bash '$remoteScriptPath' '$RemotePath' '$Case'; rc=`$?; rm -f '$remoteScriptPath'; exit `$rc"
    if ($LASTEXITCODE -ne 0) {
        throw "Remote capture failed with exit code ${LASTEXITCODE}"
    }
}
finally {
    if (Test-Path -LiteralPath $localRemoteScript) {
        Remove-Item -LiteralPath $localRemoteScript -Force
    }
}

Write-Host
Write-Host "[copy to host]"
& scp @scpArgs "$($target):$remoteOut" $LocalProofDir
if ($LASTEXITCODE -ne 0) {
    throw "SCP output copy failed with exit code ${LASTEXITCODE}"
}
& scp @scpArgs "$($target):$remoteSha" $LocalProofDir
if ($LASTEXITCODE -ne 0) {
    throw "SCP sha256 copy failed with exit code ${LASTEXITCODE}"
}

$localOut = Join-Path $LocalProofDir "latest_command_output.txt"
$localSha = Join-Path $LocalProofDir "latest_command_output.txt.sha256"
$expected = ((Get-Content -LiteralPath $localSha -Raw).Trim() -split "\s+")[0].ToUpperInvariant()
$actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $localOut).Hash.ToUpperInvariant()

Write-Host
Write-Host "[verify]"
Write-Host "expected=$expected"
Write-Host "actual=$actual"
if ($expected -ne $actual) {
    throw "Hash mismatch for latest_command_output.txt"
}

Write-Host
Write-Host "capture_fetch=passed"
Write-Host $localOut
Write-Host $localSha
