# Code Update To SIFT: 2026-06-01

Purpose: collate the latest source-code changes that should be synced to the SIFT VM without copying datasets, proof archives, generated results, or temporary dependencies.

## Included Code Changes

- SQL correlation now deduplicates repeated finding IDs before candidate persistence.
- Report generation now deduplicates repeated finding IDs before applying report limits.
- SQL finding titles now use evidence-derived language instead of generic `SQL-correlated suspicious event: evt`.
- Bounded LLM Reasoning now suppresses non-JSON/freeform model narrative and records uncertainty instead.
- Regression tests were added for SQL dedupe/title behavior, report dedupe, and LLM narrative suppression.
- `scripts/sift_e2e_ollama_run.sh` now runs in supervised mode by default: it waits for the launched analysis PID, prints periodic status, enforces a configurable runtime guard, runs post-run checks on success, and returns the shell prompt with a clear exit code.
- Detached/background behavior is still available with `WAIT_FOR_COMPLETION=0`.
- Status, monitor, cleanup, and stop scripts now avoid matching `blitz_e2e`/`blitz_resume` log or helper names as active analysis processes.
- Evidentiary weighting was added as a first-class proof artifact: future runs write `findings/evidentiary_weighting.json` and `reports/evidentiary_weighting.md`.
- Evidence contradiction analysis was formalized as a first-class proof artifact: future runs write `findings/contradiction_analysis.json` and `reports/contradiction_analysis.md`, and related finding confidence is reduced with `CONTRADICTION_PENALTY`.
- Finding provenance visualization was added: future runs write `reports/finding_provenance.md` with Mermaid finding-to-evidence flowcharts from `findings/evidence_maturity.json`.
- `tests/adversarial/` now contains harmless prompt-injection, corrupted parser-output, evidentiary weighting, and contradiction-penalty tests.
- Completed progress layers now replace stale running counters, fixing the misleading completed parser display such as `Parser result extraction (0/1)`.
- Completed runs now checkpoint the SQLite event store before final artifact-manifest hashing, reducing proof-archive dependence on `event_store.sqlite-wal` and `event_store.sqlite-shm` sidecars.
- The active alert-intake/trigger overlay was removed from the code path to keep Blitz DFIR evidence-first instead of SOC alert-first.
- Evidence-first planning was added: optional `--case-objective`, `findings/case_objective.json`, `findings/investigation_plan.json`, `findings/evidence_triage.json`, matching Markdown reports, report sections, progress layers, audit events, monitor readiness, and E2E checks.
- The SIFT launcher now accepts `CASE_OBJECTIVE` instead of `ALERT_PATH`.
- `scripts/blitz_clean_deploy_to_sift.ps1` was added for clean code deployment after proof archives have already been preserved.
- `scripts/blitz_status.sh` now prints active Blitz/SIFT processes as a compact operator table instead of dumping raw long command lines.
- `scripts/blitz_status.sh` now includes a review map for final reports, bounded LLM reasoning, correlation findings/scoring, evidentiary weighting, contradiction analysis, evidence traceability, audit progress, and artifact hashes.
- `scripts/blitz_status.sh` now includes an evidence-category proof section so PLASO/processed evidence remains visibly `DERIVED` while bounded LLM reasoning remains separately labeled `INFERRED`.
- `scripts/blitz_fetch_latest_sift_proof_archive.ps1` was added to discover the latest completed SIFT session/run, archive the proof bundle, copy it to the host, and verify SHA256. The final full-archive copy now defaults to `sftp reget` so interrupted 9GB transfers can resume when rerun with `-SkipArchive`.
- `scripts/blitz_fetch_latest_sift_thin_proof.ps1` was added for unstable networks and layer-review workflows; it excludes bulk timelines, SQLite event stores, normalized exports, full accounting, and tool-result payloads while preserving reports, audit, progress, scoring, traceability, postrun status, and the status review-map capture.
- `scripts/sift_high_volume_stress_ladder.sh` now defaults `TOOL_TIMEOUT` to the Blitz typed-tool cap of `7200`; the previous `21600` value caused `app.py analyze` to exit before session creation. The ladder also preserves the real failed stage exit code and prints `run_status.json` plus the launcher log tail when no session is created.
- `scripts/sift_high_volume_stress_ladder.sh` now defaults to an actual current-ceiling ladder of `1M/2M/3M/4M/5M` normalized rows and fails fast for targets above the current `5M` hard cap. A stage only passes when the generated SQLite/accounting rows meet or exceed the target.
- Mixed-source correlation intake was added: manifest runs now allow up to six evidence inputs and typed processed outputs can be declared as `VOLATILITY_JSON`, `YARA_MATCHES`, `STRINGS_OUTPUT`, `PREPROCESSED_EVTX`, `CSV_TIMELINE`, or `JSON_EXPORT`.
- Direct processed parser routing now sends Volatility JSON, YARA matches, and strings output through deterministic parsers without invoking external tools.
- Final reports and audit now include correlation-scope proof: `report.json.correlation_scope` and audit event `correlation_scope_recorded` show input count, source mix, participating evidence IDs, normalized/analysis event counts, unsupported evidence, and evidence that produced no normalized events.
- Documentation/checklists were updated to record the SANS Find Evil dataset permission, unknown ground truth status, analyst expectations, evidence-first proof order, EVTX rerun, stress ladder, and memory-test sequencing.

## Transfer Script

Use this from Windows PowerShell:

```powershell
cd "C:\Users\rienm\Desktop\Personal Projects\Cyber Security automation\app_backups\Blitz_DFIR"
.\scripts\blitz_scp_latest_code_to_sift.ps1
```

For a clean code refresh after proof archives are safely copied to the host:

```powershell
.\scripts\blitz_clean_deploy_to_sift.ps1
```

Dry-run first if you want to inspect the exact package and commands:

```powershell
.\scripts\blitz_clean_deploy_to_sift.ps1 -DryRun
```

If the SIFT IP changes:

```powershell
.\scripts\blitz_scp_latest_code_to_sift.ps1 -VmHost 192.168.88.133
```

## Fetch Latest Completed Proof Archive

After a successful SIFT run, use this from Windows PowerShell to archive and import the newest completed session/run pair:

```powershell
cd "C:\Users\rienm\Desktop\Personal Projects\Cyber Security automation\app_backups\Blitz_DFIR"
.\scripts\blitz_fetch_latest_sift_proof_archive.ps1
```

The script copies the tar plus `.sha256` sidecar into `Blitz_DFIR_Proof/` and verifies the host hash. To force a specific run:

```powershell
.\scripts\blitz_fetch_latest_sift_proof_archive.ps1 `
  -SessionId "sess-YYYYMMDDTHHMMSSZ-xxxxxxxx" `
  -RunId "YYYYMMDDTHHMMSSZ"
```

For normal layer proof review on unstable networks, prefer the thin archive:

```powershell
.\scripts\blitz_fetch_latest_sift_thin_proof.ps1
```

For a full archive on an unstable network, the script uses resumable `sftp reget` by default. If the large copy disconnects, rerun the same command with `-SkipArchive` so the remote tar is not regenerated and the local partial file can resume:

```powershell
.\scripts\blitz_fetch_latest_sift_proof_archive.ps1 -SkipArchive
```

## Excluded From Transfer

The sync script excludes:

- `Blitz_DFIR_Proof/`
- `cases/`
- `evidence/`
- `output/`
- `analysis/runs/`
- `.venv/`
- `.deps/`
- `test_tmp/`
- `local/`
- `private/`
- `.env`
- forensic evidence files such as `.E01`, `.Ex01`, `.L01`, `.dd`, `.raw`, `.mem`, `.vmem`, `.dmp`, `.img`, `.aff4`, `.vhd`, `.vhdx`, `.ad1`, `.pcap`, `.pcapng`, `.plaso`
- generated archives such as `.tar`, `.tar.gz`, `.zip`
- generated SQLite stores such as `.sqlite`

## After Sync On SIFT

Run:

```bash
cd /home/sansforensics/src/Blitz_DFIR
python -m compileall -q app.py blitz_dfir scripts tests
python -m pytest -q
APPLY=1 CASE=BLITZ-RD01-PLASO bash scripts/sift_clean_generated_for_rerun.sh
APPLY=1 CASE=BLITZ-RD01-PLASO bash scripts/sift_clean_remote_proof_archives.sh
CASE_OBJECTIVE='Identify evidence-backed malicious or suspicious activity while preserving unknowns and avoiding unsupported conclusions.' CASE=BLITZ-RD01-PLASO bash scripts/sift_e2e_ollama_run.sh
CASE=BLITZ-RD01-PLASO bash scripts/blitz_monitor_until_done.sh
```

Recommended proof order after this sync:

1. Evidence-first PLASO proof run.
2. EVTX-focused rerun.
3. Current-ceiling normalized-event stress ladder: `PSORT_FILTER= CASE=BLITZ-RD01-PLASO bash scripts/sift_high_volume_stress_ladder.sh`.
4. 17G memory dataset, only after disk space and Volatility/profile readiness are checked.

The E2E run command now waits until the analysis process exits. Use this only when you intentionally want detached behavior:

```bash
WAIT_FOR_COMPLETION=0 CASE=BLITZ-RD01-PLASO bash scripts/sift_e2e_ollama_run.sh
CASE=BLITZ-RD01-PLASO bash scripts/blitz_monitor_until_done.sh
```

Do not commit or transfer raw evidence/proof archives unless explicitly needed for a private local review.
