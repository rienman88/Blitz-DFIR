# Large Generated Artifacts Omitted From GitHub

The full Rocba LLM run produced two generated JSON artifacts larger than GitHub's practical repository limits:

- `session/reports/report.json`
- `session/findings/evidence_maturity.json`

They were omitted from the GitHub package to keep the repository pushable without Git LFS. The same investigation is still represented by the judge-readable and structured artifacts included here:

- `submission/packet/02_RUN_SUMMARY_COMPACT.json`
- `submission/packet/07_AGENT_EXECUTION_LOGS_INDEX.md`
- `submission/AGENT_EXECUTION_LOGS_ROCBA_LLM_SUCCESS_20260615.md`
- `submission/rocba_llm_agent_logs/run/launcher.log`
- `submission/rocba_llm_agent_logs/run/run_status.json`
- `submission/rocba_llm_agent_logs/session/audit/*.ndjson`
- `submission/rocba_llm_agent_logs/session/audit/progress.json`
- `submission/rocba_llm_agent_logs/session/audit/session_state.json`
- `submission/rocba_llm_agent_logs/session/findings/agent_trace.json`
- `submission/rocba_llm_agent_logs/session/findings/tool_results.json`
- `submission/rocba_llm_agent_logs/session/findings/parser_results.json`
- `submission/rocba_llm_agent_logs/session/findings/overall_findings.md`
- `submission/rocba_llm_agent_logs/session/reports/report.html`
- `submission/rocba_llm_agent_logs/session/reports/report.md`
- `submission/rocba_llm_agent_logs/session/reports/agent_journal.md`

No raw evidence is included in this repository.
