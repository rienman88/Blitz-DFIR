# Demo Video Checklist

Limit: 5 minutes maximum.

## Goal

Show a live terminal run against real case data and prove autonomous execution, self-correction, LLM-bounded reasoning, and traceability.

## Recommended Structure

### 0:00-0:30 - What Blitz Is

Say:

`Blitz DFIR is an autonomous SIFT-based incident response pipeline. It uses typed forensic tools, manifest-verified evidence, SQLite correlation, audit logs, and bounded LLM explanation. The LLM does not control tools and does not create findings.`

Show:

- Repo folder.
- `case.yaml`.
- `scripts/sift_rocba_memory_e01_ollama_clean_run.sh`.

### 0:30-1:30 - Run Command

Show the command:

```bash
cd /home/sansforensics/src/Blitz_DFIR

BLITZ_SQLITE_ANALYSIS_EVENT_MEMORY_LIMIT=50000 \
BLITZ_SQLITE_NORMALIZATION_CHECKPOINT_INTERVAL=100000 \
OLLAMA_BASE_URL=http://192.168.88.1:11434 \
LLM_TIMEOUT_SECONDS=600 \
LLM_MAX_TOKENS=800 \
OLLAMA_KEEP_ALIVE=30m \
OLLAMA_KEEPALIVE_INTERVAL_SECONDS=600 \
CASE=BLITZ-ROCBA-MEMORY-E01 \
bash scripts/sift_rocba_memory_e01_ollama_clean_run.sh
```

Narrate:

- Memory and E01 are referenced from existing folders.
- Raw evidence is not copied into the combined case.
- Output goes into the case output/session folder.

### 1:30-2:30 - Self-Correction Sequence

Show:

- `log2timeline` exit code `1`.
- Blitz fallback to disk triage.
- Final status still `COMPLETED`.

Use:

```bash
CASE=BLITZ-ROCBA-MEMORY-E01 bash scripts/blitz_status.sh
```

Narrate:

`This is the self-correction sequence. Plaso failed on VSS parsing, Blitz recorded the failure, switched to bounded Sleuth Kit disk triage, and preserved the limitation in validation and unknowns.`

### 2:30-3:30 - Results

Show:

- `reports/agent_journal.md`
- `findings/tool_results.json`
- `audit/progress.json`
- `findings/llm_report_verification.json`
- `reports/report.html`

Key numbers:

- `1,124,391` normalized events.
- `22,293` findings.
- `16` memory injection candidates.
- LLM verification `passed`.
- Validation issues `12`, caused by degraded E01 timeline coverage.

### 3:30-4:30 - Trust Boundaries

Show:

- `docs/ARCHITECTURE.md` or `submission_packet/04_ARCHITECTURE_DIAGRAM_AND_TRUST_BOUNDARIES.md`
- `tool_results.json`
- `llm_report_verification.json`

Narrate:

`The LLM received bounded summaries only. Raw evidence and raw tool output were not sent to the model. The model cannot execute tools or create findings. Generic shell is not exposed through the typed MCP boundary.`

### 4:30-5:00 - What Judges Should Review

Point to:

- Devpost: `blitz_dfir_devpost_FINAL_POLISHED.md`
- Dataset docs: `05_DATASET_DOCUMENTATION.md`
- Accuracy report: `06_ACCURACY_REPORT.md`
- Agent logs: `07_AGENT_EXECUTION_LOGS_INDEX.md`
- Try-it-out: `09_TRY_IT_OUT_INSTRUCTIONS.md`

Close with:

`Blitz does not hide uncertainty. It completes the investigation pipeline, reports what it found, and preserves what it could not prove.`

