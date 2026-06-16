param(
    [string]$VmHost = "192.168.88.133",
    [string]$VmUser = "sansforensics",
    [string]$RemotePath = "/home/sansforensics/src/Blitz_DFIR",
    [int]$Port = 22,
    [string]$IdentityFile = "",
    [switch]$SkipRemoteChecks,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$deployScript = Join-Path $PSScriptRoot "blitz_scp_latest_code_to_sift.ps1"
$deployParams = @{
    VmHost = $VmHost
    VmUser = $VmUser
    RemotePath = $RemotePath
    Port = $Port
    CleanRemote = $true
}

if ($IdentityFile) {
    $deployParams.IdentityFile = $IdentityFile
}
if ($SkipRemoteChecks) {
    $deployParams.SkipRemoteChecks = $true
}
if ($DryRun) {
    $deployParams.DryRun = $true
}

& $deployScript @deployParams
