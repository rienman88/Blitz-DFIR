# Agent Execution Logs Index

## Primary Agent Log Package

Archive:

`../BLITZ-ROCBA-MEMORY-E01_agent_logs_20260615T082911Z.tar.gz`

Extracted folder:

`../BLITZ-ROCBA-MEMORY-E01_agent_logs_20260615T082911Z/`

Archive hash:

`../BLITZ-ROCBA-MEMORY-E01_agent_logs_20260615T082911Z.tar.gz.sha256`

## Best Files For Judges

Read in this order:

1. `../BLITZ-ROCBA-MEMORY-E01_agent_logs_20260615T082911Z/session/reports/agent_journal.md`
2. `../BLITZ-ROCBA-MEMORY-E01_agent_logs_20260615T082911Z/session/audit/progress.json`
3. `../BLITZ-ROCBA-MEMORY-E01_agent_logs_20260615T082911Z/session/findings/tool_results.json`
4. `../BLITZ-ROCBA-MEMORY-E01_agent_logs_20260615T082911Z/session/audit/sess-20260615T073626Z-5118ee34.ndjson`
5. `../BLITZ-ROCBA-MEMORY-E01_agent_logs_20260615T082911Z/session/findings/agent_trace.json`
6. `../BLITZ-ROCBA-MEMORY-E01_agent_logs_20260615T082911Z/session/findings/llm_report_verification.json`
7. `../BLITZ-ROCBA-MEMORY-E01_agent_logs_20260615T082911Z/run/run_status.json`
8. `../BLITZ-ROCBA-MEMORY-E01_agent_logs_20260615T082911Z/run/launcher.log`

## What Each File Proves

| File | Purpose |
| --- | --- |
| `agent_journal.md` | Human-readable reconstruction of the autonomous investigation flow |
| `agent_trace.json` | Structured trace connecting findings, tool actions, plan changes, and hypotheses |
| `tool_results.json` | Tool execution sequence, timestamps by audit context, exit codes, hashes, typed tool names |
| `parser_results.json` | Parser extraction counts and warnings |
| `progress.json` | Layer-by-layer pipeline completion status |
| `sess-20260615T073626Z-5118ee34.ndjson` | Append-only audit event log with hash chain |
| `run_status.json` | Final launcher-level status and analysis exit code |
| `launcher.log` | Terminal-adjacent execution log from the SIFT runner |
| `llm_report_verification.json` | Verification result for bounded LLM explanation |
| `artifact_manifest.json` | Generated artifact hashes and sizes |

## Self-Correction Evidence

The self-correction sequence is visible in:

- `agent_journal.md`: Plan Changes And Recovery section.
- `tool_results.json`: `log2timeline` exit code `1`, followed by `disk_triage` exit code `0`.
- `progress.json`: typed tool execution, parsing, normalization, correlation, validation, and report layers completed.
- `sess-20260615T073626Z-5118ee34.ndjson`: `disk_triage_fallback_started`, `plan_change`, and `disk_triage_fallback_completed`.

## Token Usage

The bounded LLM reasoning layer recorded:

- Provider: `ollama`
- Model: `llama3.2:1b`
- Prompt tokens: `4,095`
- Completion tokens: `800`
- Total tokens: `4,895`
- Raw evidence sent: `False`
- Raw tool output sent: `False`

## Important Note

These logs prove the Blitz internal autonomous investigation flow. If judges specifically require a client transcript from OpenClaw or Claude Code, capture that transcript separately. The Blitz logs remain the forensic audit source of truth.

