param(
    [Parameter(Mandatory = $true)]
    [string]$VmHost,

    [string]$VmUser = "sansforensics",
    [string]$RemotePath = "/home/sansforensics/src/Blitz_DFIR",
    [int]$Port = 22,
    [string]$IdentityFile = "",
    [switch]$CleanRemote,
    [switch]$SkipRemoteChecks,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

function Require-Command {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command not found on host PATH: $Name"
    }
}

function Bash-SingleQuote {
    param([string]$Value)
    return "'" + $Value.Replace("'", "'`"`"'`"`"'") + "'"
}

function Invoke-Logged {
    param(
        [string]$Exe,
        [string[]]$CommandArgs
    )
    Write-Host ("+ {0} {1}" -f $Exe, ($CommandArgs -join " "))
    if ($DryRun) {
        return
    }
    & $Exe @CommandArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $Exe"
    }
}

Require-Command ssh
Require-Command scp
Require-Command tar

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$archive = Join-Path ([System.IO.Path]::GetTempPath()) "blitz-dfir-sync-${timestamp}.tar.gz"
$remoteArchive = "/tmp/blitz-dfir-sync-${timestamp}.tar.gz"
$target = "${VmUser}@${VmHost}"

$sshArgs = @()
$scpArgs = @()
if ($IdentityFile) {
    $sshArgs += @("-i", $IdentityFile)
    $scpArgs += @("-i", $IdentityFile)
}
$sshArgs += @("-p", [string]$Port)
$scpArgs += @("-P", [string]$Port)

$excludeArgs = @(
    "--exclude=.git",
    "--exclude=.env",
    "--exclude=*.local.env",
    "--exclude=*.private.env",
    "--exclude=.venv",
    "--exclude=venv",
    "--exclude=.deps",
    "--exclude=test_tmp",
    "--exclude=.sync",
    "--exclude=__pycache__",
    "--exclude=.pytest_cache",
    "--exclude=.mypy_cache",
    "--exclude=.ruff_cache",
    "--exclude=.blitz_sessions",
    "--exclude=local",
    "--exclude=private",
    "--exclude=cases",
    "--exclude=evidence",
    "--exclude=Blitz_DFIR_Proof",
    "--exclude=proof_exports",
    "--exclude=extracted_review",
    "--exclude=output/*",
    "--exclude=analysis/runs",
    "--exclude=*.tar",
    "--exclude=*.tar.gz",
    "--exclude=*.zip",
    "--exclude=*.E01",
    "--exclude=*.Ex01",
    "--exclude=*.L01",
    "--exclude=*.dd",
    "--exclude=*.raw",
    "--exclude=*.mem",
    "--exclude=*.vmem",
    "--exclude=*.dmp",
    "--exclude=*.img",
    "--exclude=*.aff4",
    "--exclude=*.vhd",
    "--exclude=*.vhdx",
    "--exclude=*.ad1",
    "--exclude=*.pcap",
    "--exclude=*.pcapng",
    "--exclude=*.plaso",
    "--exclude=*.sqlite",
    "--exclude=*.pyc",
    "--exclude=*.pyo"
)

Write-Host "[source]"
Write-Host $repoRoot
Write-Host
Write-Host "[target]"
Write-Host "${target}:${RemotePath}"
Write-Host

try {
    $tarArgs = @("-czf", $archive) + $excludeArgs + @("-C", $repoRoot, ".")
    Invoke-Logged -Exe "tar" -CommandArgs $tarArgs

    $remotePathQ = Bash-SingleQuote $RemotePath
    $remoteArchiveQ = Bash-SingleQuote $remoteArchive

    Invoke-Logged -Exe "ssh" -CommandArgs ($sshArgs + @($target, "mkdir -p -- ${remotePathQ}"))
    Invoke-Logged -Exe "scp" -CommandArgs ($scpArgs + @($archive, "$($target):$remoteArchive"))

    if ($CleanRemote) {
        $cleanCommand = @"
set -euo pipefail
mkdir -p -- ${remotePathQ}
find ${remotePathQ} -mindepth 1 -maxdepth 1 \
  ! -name .venv \
  ! -name .git \
  ! -name .env \
  ! -name local \
  ! -name private \
  ! -name cases \
  ! -name evidence \
  ! -name Blitz_DFIR_Proof \
  ! -name output \
  -exec rm -rf -- {} +
"@
        Invoke-Logged -Exe "ssh" -CommandArgs ($sshArgs + @($target, $cleanCommand))
    }

    $extractCommand = @"
set -euo pipefail
mkdir -p -- ${remotePathQ}
tar -xzf ${remoteArchiveQ} -C ${remotePathQ}
rm -f -- ${remoteArchiveQ}
chmod +x ${remotePathQ}/scripts/*.sh ${remotePathQ}/scripts/*.py 2>/dev/null || true
"@
    Invoke-Logged -Exe "ssh" -CommandArgs ($sshArgs + @($target, $extractCommand))

    if (-not $SkipRemoteChecks) {
        $checkCommand = @"
set -euo pipefail
cd ${remotePathQ}
if [ -x .venv/bin/python ]; then
  PY=.venv/bin/python
else
  PY=python3
fi
`$PY -m compileall -q app.py blitz_dfir scripts tests
bash -n scripts/blitz_status.sh scripts/blitz_monitor_until_done.sh scripts/sift_e2e_ollama_run.sh scripts/blitz_e2e_ollama_check.sh scripts/sift_clean_generated_for_rerun.sh scripts/sift_failure_diagnostics.sh scripts/sift_clean_remote_proof_archives.sh scripts/blitz_vm_postrun_checks.sh scripts/blitz_stop_processes.sh scripts/sift_high_volume_stress_ladder.sh
echo sync_remote_checks=passed
"@
        Invoke-Logged -Exe "ssh" -CommandArgs ($sshArgs + @($target, $checkCommand))
    }

    Write-Host
    Write-Host "[next on VM]"
    Write-Host "cd ${RemotePath}"
    Write-Host "python -m compileall -q app.py blitz_dfir scripts tests"
    Write-Host "APPLY=1 CASE=BLITZ-RD01-PLASO bash scripts/sift_clean_generated_for_rerun.sh"
    Write-Host "APPLY=1 CASE=BLITZ-RD01-PLASO bash scripts/sift_clean_remote_proof_archives.sh"
    Write-Host "CASE_OBJECTIVE='Identify evidence-backed malicious or suspicious activity while preserving unknowns and avoiding unsupported conclusions.' CASE=BLITZ-RD01-PLASO bash scripts/sift_e2e_ollama_run.sh"
    Write-Host "CASE=BLITZ-RD01-PLASO bash scripts/blitz_monitor_until_done.sh"
    Write-Host "# Evidence-first default: CASE=BLITZ-RD01-PLASO bash scripts/sift_e2e_ollama_run.sh"
    Write-Host "# Detached mode only: WAIT_FOR_COMPLETION=0 CASE=BLITZ-RD01-PLASO bash scripts/sift_e2e_ollama_run.sh"
    Write-Host "# Detached monitor: CASE=BLITZ-RD01-PLASO bash scripts/blitz_monitor_until_done.sh"
Write-Host "# Next proof order: evidence-first PLASO proof, EVTX-focused rerun, 1M/2M/3M/4M/5M ceiling stress ladder, then the 17G memory dataset."
    Write-Host "# High-volume stress ladder, full PLASO export: PSORT_FILTER= CASE=BLITZ-RD01-PLASO bash scripts/sift_high_volume_stress_ladder.sh"
}
finally {
    if ((Test-Path -LiteralPath $archive) -and -not $DryRun) {
        Remove-Item -LiteralPath $archive -Force
    }
}
