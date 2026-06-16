param(
    [string]$VmHost = "192.168.88.133",
    [string]$VmUser = "sansforensics",
    [string]$RemotePath = "/home/sansforensics/src/Blitz_DFIR",
    [int]$Port = 22,
    [string]$IdentityFile = "",
    [switch]$CleanRemote,
    [switch]$SkipRemoteChecks,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$syncScript = Join-Path $PSScriptRoot "blitz_sync_to_sift_vm.ps1"
$syncParams = @{
    VmHost = $VmHost
    VmUser = $VmUser
    RemotePath = $RemotePath
    Port = $Port
}

if ($IdentityFile) {
    $syncParams.IdentityFile = $IdentityFile
}
if ($CleanRemote) {
    $syncParams.CleanRemote = $true
}
if ($SkipRemoteChecks) {
    $syncParams.SkipRemoteChecks = $true
}
if ($DryRun) {
    $syncParams.DryRun = $true
}

& $syncScript @syncParams
