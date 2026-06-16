param(
    [string]$VmHost = "192.168.88.133",
    [string]$VmUser = "sansforensics",
    [string]$Case = "BLITZ-RD01-PLASO",
    [string]$Session = "/cases/BLITZ-RD01-PLASO/output/sess-20260601T010722Z-40b51cee",
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
$remoteOut = "/cases/${Case}/proof_exports/postfix_session_quality.txt"
$remoteSha = "${remoteOut}.sha256"
$remoteScriptPath = "/tmp/blitz-postfix-session-quality.sh"
$localRemoteScript = Join-Path ([System.IO.Path]::GetTempPath()) ("blitz-postfix-quality-{0}.sh" -f ([System.Guid]::NewGuid().ToString("N")))
$sshArgs = @("-p", [string]$Port)
$scpArgs = @("-P", [string]$Port)

$remoteScript = @'
set -euo pipefail
SESSION="$1"
CASE="$2"
OUT="/cases/${CASE}/proof_exports/postfix_session_quality.txt"
mkdir -p "/cases/${CASE}/proof_exports"

{
  echo "===== postfix report quality check ====="
  python3 - "${SESSION}" <<'PY'
import json
import sys
from collections import Counter
from pathlib import Path

session = Path(sys.argv[1])
report_path = session / "reports" / "report.json"
evidence_maturity_path = session / "findings" / "evidence_maturity.json"
progress_path = session / "audit" / "progress.json"

print(f"session={session}")
print(f"report_path={report_path}")
print(f"report_exists={report_path.exists()}")
if not report_path.exists():
    raise SystemExit(2)

report = json.loads(report_path.read_text())
findings = report.get("findings", [])
ids = [str(f.get("finding_id", "")) for f in findings]
labels = [str(f.get("finding", "")) for f in findings]
confidence = [str(f.get("confidence", "")) for f in findings]
modifiers = Counter(
    modifier
    for finding in findings
    for modifier in finding.get("confidence_modifiers", [])
)
label_counts = Counter(labels)
reasoning = report.get("inferred_analyst_reasoning", {})
narrative = str(reasoning.get("narrative", "")).lower()
analysis_limits = reasoning.get("analysis_limits", ())

print(f"findings_total={len(ids)}")
print(f"unique_ids={len(set(ids))}")
print(f"duplicate_ids={len(ids) - len(set(ids))}")
print(f"generic_evt_labels={sum(label == 'SQL-correlated suspicious event: evt' for label in labels)}")
print(f"sql_injection_in_reasoning={'sql injection' in narrative}")
print(f"database_in_reasoning={'database' in narrative}")
print(f"reasoning_evidence_type={reasoning.get('evidence_type', '')}")
print(f"analysis_limit_count={len(analysis_limits) if isinstance(analysis_limits, list) else len(tuple(analysis_limits or ())) }")
print("confidence_distribution=" + json.dumps(dict(Counter(confidence)), sort_keys=True))
print("confidence_modifiers=" + json.dumps(dict(sorted(modifiers.items())), sort_keys=True))
print("top_labels=" + json.dumps(label_counts.most_common(10), ensure_ascii=True))

if evidence_maturity_path.exists():
    maturity = json.loads(evidence_maturity_path.read_text())
    traces = maturity.get("finding_traces", maturity.get("findings", []))
    trace_ids = [
        str(item.get("finding_id", ""))
        for item in traces
        if isinstance(item, dict)
    ]
    complete = [
        item
        for item in traces
        if isinstance(item, dict)
        and str(item.get("traceability_status", item.get("status", ""))).lower() in {"complete", "traceable", "preserved"}
    ]
    print(f"evidence_maturity_exists=True")
    print(f"evidence_maturity_traces={len(traces)}")
    print(f"evidence_maturity_unique_ids={len(set(trace_ids))}")
    print(f"evidence_maturity_complete_or_traceable={len(complete)}")
else:
    print("evidence_maturity_exists=False")

if progress_path.exists():
    progress = json.loads(progress_path.read_text())
    print(f"progress_status={progress.get('status')}")
    print(f"progress_effective_status={progress.get('effective_status')}")
    print(f"parser_result_count={progress.get('parser_result_count')}")
    print(f"parser_processed_count={progress.get('parser_processed_count')}")
PY
} 2>&1 | tee "${OUT}"

sha256sum "${OUT}" > "${OUT}.sha256"
ls -l "${OUT}" "${OUT}.sha256"
'@
$remoteScript = $remoteScript -replace "`r`n", "`n"

try {
    [System.IO.File]::WriteAllText(
        $localRemoteScript,
        $remoteScript,
        [System.Text.UTF8Encoding]::new($false)
    )

    Write-Host "[remote quality capture]"
    Write-Host "${target}:${remoteOut}"
    & scp @scpArgs $localRemoteScript "$($target):$remoteScriptPath"
    if ($LASTEXITCODE -ne 0) {
        throw "SCP remote quality script copy failed with exit code ${LASTEXITCODE}"
    }

    & ssh @sshArgs $target "chmod +x '$remoteScriptPath' && bash '$remoteScriptPath' '$Session' '$Case'; rc=`$?; rm -f '$remoteScriptPath'; exit `$rc"
    if ($LASTEXITCODE -ne 0) {
        throw "Remote quality capture failed with exit code ${LASTEXITCODE}"
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
    throw "SCP quality output copy failed with exit code ${LASTEXITCODE}"
}
& scp @scpArgs "$($target):$remoteSha" $LocalProofDir
if ($LASTEXITCODE -ne 0) {
    throw "SCP quality sha256 copy failed with exit code ${LASTEXITCODE}"
}

$localOut = Join-Path $LocalProofDir "postfix_session_quality.txt"
$localSha = Join-Path $LocalProofDir "postfix_session_quality.txt.sha256"
$expected = ((Get-Content -LiteralPath $localSha -Raw).Trim() -split "\s+")[0].ToUpperInvariant()
$actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $localOut).Hash.ToUpperInvariant()

Write-Host
Write-Host "[verify]"
Write-Host "expected=$expected"
Write-Host "actual=$actual"
if ($expected -ne $actual) {
    throw "Hash mismatch for postfix_session_quality.txt"
}

Write-Host
Write-Host "postfix_quality_fetch=passed"
Write-Host $localOut
Write-Host $localSha
