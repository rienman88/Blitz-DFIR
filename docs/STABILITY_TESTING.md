# Blitz DFIR Long Stability Testing

This runbook tests the deterministic Blitz pipeline without Protocol SIFT, OpenClaw, Claude Code, or any agent layer. It exercises the CLI pipeline, typed tool dispatch, parser normalization, full accounting, event store, validation, unknowns, reporting, audit state, artifact manifests, and timeout handling.

The purpose is engineering stability, not final incident accuracy scoring.

## Scope

Included:

- `python app.py analyze`
- manifest loading and evidence hash verification
- batch-plan generation
- tool discovery and evidence inventory artifacts
- SIFT-local forensic tool execution through Blitz typed adapters
- parser output handling
- full accounting and SQLite event-store preservation
- bounded normalized report generation
- timeout and partial-output handling
- report generation
- session state and artifact manifest hashing

Excluded:

- OpenClaw
- Claude Code
- Protocol SIFT agent workflow
- cloud LLM reasoning
- MITRE/ATT&CK mapping
- unrestricted full raw all-artifact execution

## Files

- `scripts/sift_long_stability_run.sh`: runs the long sequential stress ladder.
- `scripts/blitz_status.sh`: the only operator-facing live monitor. It shows the active process, selected session, layer progress, effective live/stale state, recent audit checkpoints, output sizes, memory, and disk.
- `scripts/sift_summarize_session.py`: creates per-session JSON summaries with row counts and artifact hashes.
- `scripts/sift_cleanup_case_outputs.sh`: preserves small receipts and safely deletes old session directories.

## Recommended Preflight

Run this on SIFT before a long run:

```bash
cd ~/src/Blitz_DFIR
source .venv/bin/activate

python -m pytest tests/test_inventory.py tests/test_batch_plan.py tests/test_correlation.py tests/test_reporting.py tests/test_app.py -q
python -m pytest -q
python -m compileall -q app.py blitz_dfir tests
python -m ruff check app.py blitz_dfir tests
python -m mypy app.py blitz_dfir tests
```

Confirm free disk and memory:

```bash
CASE=BLITZ-RD01-PLASO
df -h /cases/${CASE} /
free -h
```

Do not start the long run if `/cases` has less than 15 GB free.

## Cleanup Old Runs

Dry run first:

```bash
CASE=BLITZ-RD01-PLASO
KEEP=sess-20260526T122628Z-8e7e8775
bash ~/src/Blitz_DFIR/scripts/sift_cleanup_case_outputs.sh
```

Apply after reviewing the candidates:

```bash
CASE=BLITZ-RD01-PLASO
KEEP=sess-20260526T122628Z-8e7e8775
APPLY=1 bash ~/src/Blitz_DFIR/scripts/sift_cleanup_case_outputs.sh
```

The cleanup script preserves small receipts under:

```text
/cases/<CASE>/analysis/run_receipts/
```

It must never delete:

- `/cases/<CASE>/processed/case.plaso`
- `/cases/<CASE>/case.yaml`
- raw evidence
- manifests

## Long Stability Run

Start the long run with `nohup`:

```bash
cd ~/src/Blitz_DFIR
source .venv/bin/activate

CASE=BLITZ-RD01-PLASO
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
LOG=/cases/${CASE}/analysis/stability_${RUN_ID}.launcher.log

nohup bash ~/src/Blitz_DFIR/scripts/sift_long_stability_run.sh \
  > "$LOG" 2>&1 &

echo $!
echo "$LOG"
```

Optional disk-saving mode deletes completed non-timeout sessions after recording JSON summaries:

```bash
DELETE_PASSED_SESSIONS=1 nohup bash ~/src/Blitz_DFIR/scripts/sift_long_stability_run.sh \
  > "$LOG" 2>&1 &
```

Optional faster mode skips per-phase evidence hashing. Use this only after a known-good source hash has already been captured, and run a final evidence hash manually after the ladder:

```bash
HASH_EACH_PHASE=0 nohup bash ~/src/Blitz_DFIR/scripts/sift_long_stability_run.sh \
  > "$LOG" 2>&1 &
```

Low-memory profile for an 8 GB host / 4 GB SIFT VM:

```bash
STABILITY_PROFILE=lowmem HASH_EACH_PHASE=0 DELETE_PASSED_SESSIONS=1 \
nohup bash ~/src/Blitz_DFIR/scripts/sift_long_stability_run.sh \
  > "$LOG" 2>&1 &
```

This skips the intentional timeout probe and 100k normalized report phase. It runs:

1. `evtx_baseline_5k`
2. `evtx_normalized_25k`
3. `evtx_normalized_50k`
4. `evtx_repeat_5k`

Use this profile first when the VM has already shown signs of memory pressure or unexplained process termination.

## Stress Phases

The default ladder runs:

1. `timeout_probe_120s`
   - Expected to timeout.
   - Confirms timeout handling, unknowns, validation, partial-session labeling, and report survival.

2. `evtx_baseline_5k`
   - Expected clean completion.
   - Uses full accounting but keeps normalized report capped at 5,000 events.

3. `evtx_normalized_25k`
   - Expected clean completion if disk/RAM are healthy.
   - Tests larger normalized JSON/Markdown/HTML report generation.

4. `evtx_normalized_50k`
   - Middle stress point between the known-good 25k report and the known-risk 100k report.

5. `evtx_repeat_5k`
   - Reproducibility check against the baseline.

`evtx_normalized_100k` is intentionally not part of the default or low-memory profile because it is the current observed failure boundary on the 8 GB host. Treat 100k as a separate breakpoint experiment only after the 50k run is stable.

## Monitor

In a second terminal:

```bash
CASE=BLITZ-RD01-PLASO
unset SESSION
watch -n 15 'CASE=BLITZ-RD01-PLASO bash ~/src/Blitz_DFIR/scripts/blitz_status.sh'
```

To follow the current master log:

```bash
CASE=BLITZ-RD01-PLASO
LATEST="$(ls -td /cases/${CASE}/analysis/stability/* | head -n 1)"
tail -f "$LATEST/stability_run.log"
```

`Ctrl-C` stops only `tail`, not the background run.

## Acceptance Criteria

For each clean phase:

- `audit/session_state.json` has `status=COMPLETED`.
- Audit log contains `analysis_completed`.
- `findings/artifact_manifest.json` exists.
- Evidence SHA256 before and after matches.
- `stress_report.timed_out_tools` is empty.
- CSV line count equals SQLite `event_rows + 1` for PLASO CSV exports.
- `tool_discovery.json` and `evidence_inventory.json` exist.
- Reports contain `Why suspicious`.
- Reports do not contain MITRE/ATT&CK references.

For timeout phases:

- The process exits cleanly from Blitz.
- `stress_report.status` is `needs_review`.
- `timed_out_tools` lists the timed-out tool.
- `unknowns.json` records critical/high review items.
- The session is not treated as final accuracy evidence.

## Stop Rules

Stop the run manually if:

- `/cases` free disk drops below 10 GB.
- swap usage grows aggressively and the VM becomes unresponsive.
- a phase runs beyond its expected tool timeout plus reporting time.
- evidence hash changes.
- SQLite row count cannot be read after a supposedly complete phase.
- `artifact_manifest.json` is missing after `session_state.status=COMPLETED`.

## Review Summaries

Each phase summary is written as:

```text
/cases/<CASE>/analysis/stability/<RUN_ID>/<PHASE>.summary.json
```

The append-only overview is:

```text
/cases/<CASE>/analysis/stability/<RUN_ID>/phase_summaries.jsonl
```

If a phase exits unexpectedly before final reports are written, the harness writes:

```text
/cases/<CASE>/analysis/stability/<RUN_ID>/phase_status.jsonl
```

`scripts/blitz_status.sh` is the canonical status command. A session with `status=RUNNING` and `effective_status=ABANDONED_OR_PARTIAL` has no live Blitz process updating it and must not be treated as complete evidence.

Use these summaries for the stability section of the accuracy report and demo preparation.
