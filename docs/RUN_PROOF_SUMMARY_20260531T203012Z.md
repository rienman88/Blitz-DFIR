# Run Proof Summary: sess-20260531T203012Z-bff65d82

Purpose: preserve the proof-relevant facts from the pasted SIFT run result and separate what this run proves from what still remains for final judge-grade accuracy.

## Run Identity

- Run bundle: `/cases/BLITZ-RD01-PLASO/analysis/runs/20260531T202550Z`
- Session: `/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82`
- Case: `BLITZ-RD01-PLASO`
- Evidence ID observed: `rd01-plaso`
- Evidence type observed: `PLASO`
- Completion timestamp UTC: `2026-05-31T21:17:03Z`
- Completion timestamp Singapore: `2026-06-01T05:17:03+08:00`
- Reported elapsed time: `46m 50s`
- Session status: `COMPLETED`
- Effective status: `COMPLETED`
- Final phase: `analysis_completed`

## Captured Launcher Settings

Command capture copied to host:

```text
C:\Users\rienm\Desktop\Personal Projects\Cyber Security automation\app_backups\Blitz_DFIR\Blitz_DFIR_Proof\sess-20260531T203012Z-bff65d82_command_capture.txt
```

Command-capture SHA256:

```text
f35d3238e865f97d83020d1f5f0ee15bc7529c39298c8ce679227aa9501962b2
```

- SIFT-generated command-capture sidecar copied to host: `C:\Users\rienm\Desktop\Personal Projects\Cyber Security automation\app_backups\Blitz_DFIR\Blitz_DFIR_Proof\sess-20260531T203012Z-bff65d82_command_capture.txt.sha256`
- Host-computed command-capture SHA256 matched the copied SIFT sidecar on 2026-06-01.

Run scope from `launcher.log`:

```text
case=BLITZ-RD01-PLASO
run_id=20260531T202550Z
run_root=/cases/BLITZ-RD01-PLASO/analysis/runs/20260531T202550Z
workdir=/home/sansforensics/src/Blitz_DFIR
manifest=/cases/BLITZ-RD01-PLASO/case.yaml
tool_config=/home/sansforensics/src/Blitz_DFIR/config/tools.yaml
plaso=/cases/BLITZ-RD01-PLASO/processed/case.plaso
resume_session=none
ollama_base_url=http://192.168.88.1:11434
llm_provider=ollama
llm_base_url=http://192.168.88.1:11434/v1
llm_model=llama3.2:1b
llm_timeout_seconds=600
blitz_agent_framework=Protocol SIFT SIFT-VM launcher
enable_reasoning=1
max_normalized_events=2000000
max_analysis_events=100000
full_sql_correlation=1
report_event_limit=5000
report_finding_limit=500
normalized_export_limit=10000
parser_record_export_limit=1000
```

Exact analysis command from `launcher.log`:

```bash
/home/sansforensics/src/Blitz_DFIR/.venv/bin/python app.py analyze --manifest /cases/BLITZ-RD01-PLASO/case.yaml --mode timeline --tool-config /home/sansforensics/src/Blitz_DFIR/config/tools.yaml --enable-reasoning --psort-profile triage --psort-filter data_type\ contains\ \'windows:evtx\' --tool-timeout 7200 --max-normalized-events 2000000 --max-analysis-events 100000 --report-event-limit 5000 --report-finding-limit 500 --normalized-export-limit 10000 --parser-record-export-limit 1000 --full-sql-correlation
```

Evidence hash before analysis from `launcher.log`:

```text
cd9a0ce596ecdda9100176ccc950ec9f539787c47ef3d421d32d7e9ebe0c1e55  /cases/BLITZ-RD01-PLASO/processed/case.plaso
```

## Execution Facts

- Typed tool executed: `psort`
- Tool exit code: `0`
- Tool timed out: `False`
- Tool duration: `1,123,619 ms`
- Batch completed: `batch-01-plaso_timeline`
- Parser results: `1`
- Normalized events: `1,329,652`
- Normalization warnings: `2`
- Analysis events loaded into bounded Python/report window: `100,000`
- Object inventory source: `sqlite_normalized_events`
- Object count: `7,268`
- Full accounting total rows: `1,329,652`
- SQL correlation rows scanned: `1,329,652`
- SQL correlation candidates: `17,880`
- SQL support events loaded: `504`
- Findings: `500`
- Attack/correlation stages: `4`
- Validation passed: `True`
- Validation issues: `0`
- Unknowns: `2`
- Unknown critical count: `0`
- Unknown high count: `0`
- Bounded LLM Reasoning: completed over bounded summaries only
- Reasoning provider/model: `ollama/llama3.2:1b`
- Reasoning prompt hash: `346c5c9273e9b81bae3221d85d5f70835248ab20d9c375d55ecb09337fdfc19e`
- Reasoning hypothesis count: `0`
- Evidence maturity finding count: `500`
- Evidence maturity traceable finding count: `500`
- Evidence hashes preserved according to evidence maturity event: `True`
- Artifact manifest written: `True`
- Reports written: `True`
- Analysis completed audit event: `True`

## Key Artifacts From Pasted Output

- Batch plan: `/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82/findings/batch_plan.json`
- Evidence inventory: `/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82/findings/evidence_inventory.json`
- Recovery plan: `/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82/findings/recovery_plan.json`
- Tool results: `/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82/findings/tool_results.json`
- Parser results: `/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82/findings/parser_results.json`
- Object inventory: `/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82/findings/object_inventory.json`
- Event store: `/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82/findings/event_store.sqlite`
- Full accounting: `/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82/findings/full_accounting.json`
- Unknowns: `/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82/findings/unknowns.json`
- Validation: `/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82/findings/validation.json`
- Coverage: `/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82/findings/coverage.json`
- Signal integrity: `/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82/findings/signal_integrity.json`
- Correction history: `/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82/findings/correction_history.json`
- Normalized events export: `/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82/findings/normalized_events.json`
- Stress report: `/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82/findings/stress_report.json`
- Report JSON: `/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82/reports/report.json`
- Report Markdown: `/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82/reports/report.md`
- Report HTML: `/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82/reports/report.html`
- Evidence maturity JSON: `/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82/findings/evidence_maturity.json`
- Evidence maturity Markdown: `/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82/reports/evidence_maturity.md`
- Artifact manifest: `/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82/findings/artifact_manifest.json`
- Session state: `/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82/audit/session_state.json`
- Audit log: `/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82/audit/sess-20260531T203012Z-bff65d82.ndjson`
- Progress: `/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82/audit/progress.json`

## Archived Proof Package

- [x] Full proof archive copied from SIFT to Windows host.
- Local archive path: `C:\Users\rienm\Desktop\Personal Projects\Cyber Security automation\app_backups\Blitz_DFIR\Blitz_DFIR_Proof\sess-20260531T203012Z-bff65d82_proof_full.tar`
- Local SHA256 file path: `C:\Users\rienm\Desktop\Personal Projects\Cyber Security automation\app_backups\Blitz_DFIR\Blitz_DFIR_Proof\sess-20260531T203012Z-bff65d82_proof_full.tar.sha256`
- Archive size on host: `9,859,072,000` bytes.
- Expected SHA256 from SIFT: `4c2772e55f8cc728a92769f517021b3d6cb92c1a7619b54ddd3b1c8ffc8cd28e`
- Host-computed SHA256: `4c2772e55f8cc728a92769f517021b3d6cb92c1a7619b54ddd3b1c8ffc8cd28e`
- Verification result: host archive hash matches SIFT hash file.

Do not commit this proof archive to GitHub. It is a local/private proof package.

## What This Run Strongly Proves

- The SIFT pipeline completed end to end on a large processed PLASO case.
- Typed SIFT execution worked through the `psort` adapter without timeout.
- SQLite-backed normalization handled 1,329,652 normalized events while keeping the report/analysis window bounded.
- Full accounting preserved the full exported row count separately from report scope.
- Object inventory completed from the SQLite normalized event store.
- SQL correlation scanned all 1,329,652 normalized rows and produced bounded support events and 500 findings.
- Validation passed with zero issues for the generated findings.
- Unknowns were recorded instead of hidden.
- Bounded LLM Reasoning ran only over bounded summaries and recorded provider/model/prompt metadata.
- Evidence maturity linked all 500 findings as traceable according to the audit checkpoint.
- Evidence hash preservation was recorded by the evidence maturity layer.
- Audit finalization and artifact manifest generation completed.

## What This Run Does Not Prove Yet

- It does not prove final real-world DFIR accuracy until ground truth or analyst expectations are documented.
- It does not prove false-positive or false-negative rates until findings are reviewed against expected attacker behavior.
- It does not prove full raw-disk coverage if the selected scope was a processed PLASO or EVTX-focused export rather than every artifact in the original image.
- It does not prove the OpenClaw or Claude agent path unless an agent execution log is captured and linked.
- It does not prove high-quality LLM reasoning; the run used `llama3.2:1b` and produced `hypothesis_count=0`.
- It does not replace adversarial tests for correlation, confidence, reasoning, and self-correction.
- It does not replace preserving the actual artifacts outside SIFT or copying key artifacts into the final submission evidence package.
- The pasted terminal progress display showed `Parser result extraction (0/1)`, but the captured `progress.final.json`, session `audit/progress.json`, `findings/parser_results.json`, and audit log all prove parsing completed with one parser result. This should be treated as a status-display issue, not a parser-layer failure.

## Known R1 Presentation Risks And Fix Status

R1 is preserved as evidence and should not be retroactively rewritten. The following presentation risks were found in the R1 artifacts:

- `500` finding rows but only `252` unique finding IDs.
- Most SQL event labels were generic: `SQL-correlated suspicious event: evt`.
- Bounded `llama3.2:1b` reasoning produced unsupported SQL-injection/database language, although it remained `INFERRED` and did not create findings.
- All findings were single-source PLASO with confidence `0.55` and `SINGLE_SOURCE_PENALTY`, which is conservative and expected for this scoped run.

Code fixes added on 2026-06-01:

- Deduplicate SQL correlation findings before candidate persistence.
- Deduplicate report findings defensively before report limits.
- Replace generic SQL labels with evidence-derived labels.
- Suppress non-JSON/freeform LLM narrative and record uncertainty instead.

Rerun requirement:

- Regenerate the PLASO proof run before using report findings as judge-facing accuracy output.
- If rerun is not possible, use R1 only for scale, traceability, evidence preservation, audit, and LLM containment proof, and manually score unique finding IDs.

## Required Follow-Up Before Accuracy Claim

- [x] Capture the exact command or launcher environment used for this run.
- [x] Confirm dataset source, license/permission, and whether it can be named publicly. User confirmed on 2026-06-01 that this is SANS Find Evil hackathon-provided case material and can be named publicly; raw evidence should not be redistributed unless SANS terms permit.
- [x] Record source evidence SHA256 after analysis as an explicit value: `evidence_maturity.json` observed SHA256 equals expected SHA256.
- [x] Copy or archive the final run proof artifacts from SIFT.
- [x] Complete preliminary finding-quality review in `docs/FINDING_REVIEW_20260531T203012Z.md`.
- [ ] Review representative findings against ground truth or analyst expectations.
- [ ] Record true positives, false positives, missed artifacts, unsupported claims, and limitations in `docs/ACCURACY_REPORT.md`.
- [x] Inspect `audit/progress.json` and `findings/parser_results.json` to explain the `Parser result extraction (0/1)` display.
- [ ] Fill `docs/REAL_CASE_WALKTHROUGH.md` from this run if it becomes the demo case.
- [ ] Add at least one repeat run or explicitly mark repeatability as pending.
- [ ] Capture OpenClaw or Claude Code agent execution logs if the final demo claims agent-driven execution.
- [ ] Rerun after the 2026-06-01 duplicate-label-reasoning fixes before using report findings as final judge-facing accuracy output.
