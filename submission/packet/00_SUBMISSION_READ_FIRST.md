# Blitz DFIR Submission Packet - Read First

This folder is the judge-facing front door for the imported Rocba memory+E01 LLM run. It organizes the large Blitz output files into a concise packet without modifying the original forensic artifacts.

## Final Run Verdict

The combined memory+E01 run completed successfully at the Blitz pipeline level.

- Case: `BLITZ-ROCBA-MEMORY-E01`
- Session: `sess-20260615T073626Z-5118ee34`
- Run ID: `20260615T070127Z_rocba_memory_e01_ollama`
- Status: `COMPLETED`
- Phase: `analysis_completed`
- Analysis exit code: `0`
- Normalized events: `1,124,391`
- Full SQL findings: `22,293`
- LLM reasoning: enabled with Ollama `llama3.2:1b`
- LLM token usage: `4,895` total tokens
- LLM verification: `passed`
- Agent trace and agent journal: generated

## Important Limitation

This is not a perfect full-Plaso E01 run. Full `log2timeline.py` failed on the E01 because Plaso/dfVFS hit a `pyvshadow`/VSS parsing error. Blitz handled that as a self-correction sequence:

1. Typed timeline tool started for the E01.
2. `log2timeline.py` exited `1`.
3. Blitz recorded the failure as a coverage issue.
4. Blitz switched to bounded Sleuth Kit disk triage.
5. Disk triage completed successfully and produced fallback filesystem coverage.

This is a strong demo point because the system did not hide the failure or mark the disk clean. It continued with a bounded fallback and preserved the limitation in validation, unknowns, audit logs, and reports.

## Where To Start

Read these in order:

1. `01_INVESTIGATION_CONCLUSION.md`
2. `02_RUN_SUMMARY_COMPACT.json`
3. `03_SUBMISSION_REQUIREMENTS_MAP.md`
4. `04_ARCHITECTURE_DIAGRAM_AND_TRUST_BOUNDARIES.md`
5. `05_DATASET_DOCUMENTATION.md`
6. `06_ACCURACY_REPORT.md`
7. `07_AGENT_EXECUTION_LOGS_INDEX.md`
8. `08_DEMO_VIDEO_CHECKLIST.md`
9. `09_TRY_IT_OUT_INSTRUCTIONS.md`

## Original Imported Artifacts

The imported proof package is here:

`../BLITZ-ROCBA-MEMORY-E01_agent_logs_20260615T082911Z/`

The most useful original files are:

- `session/reports/agent_journal.md`
- `session/findings/agent_trace.json`
- `session/audit/collated_audit.md`
- `session/audit/progress.json`
- `session/audit/session_state.json`
- `session/audit/sess-20260615T073626Z-5118ee34.ndjson`
- `session/findings/artifact_manifest.json`
- `session/findings/llm_report_verification.json`
- `session/reports/report.md`
- `session/reports/report.html`
- `session/reports/report.json`
- `session/findings/tool_results.json`
- `session/findings/parser_results.json`
- `run/run_status.json`
- `run/launcher.log`
- `run/run_exit.txt`

## Why The Original Files Look Messy

They are machine-auditable outputs, not first-read documents. Some are intentionally large:

- `report.json`: about 130 MB
- `agent_trace.json`: about 65 MB
- `evidence_maturity.json`: about 114 MB
- `report.md`: about 28 MB
- `report.html`: about 36 MB

Use this submission packet for judge review. Use the original artifacts for verification and traceability.

