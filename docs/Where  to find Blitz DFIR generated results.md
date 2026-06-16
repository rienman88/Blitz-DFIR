## Where To Find Results

Every run writes results under:

```text
/cases/<CASE>/output/sess-*
```

### Reports

| File | Purpose |
| --- | --- |
| `reports/report.html` | Full browser-friendly report for judge review and screenshots. |
| `reports/report.md` | Markdown version of the main report. |
| `reports/report.json` | Structured report data, including findings, validation fields, and optional LLM reasoning fields. |
| `reports/case_objective.md` | The investigation objective Blitz used. |
| `reports/investigation_plan.md` | Planned artifact priorities and investigation direction. |
| `reports/evidence_triage.md` | Evidence priority and triage summary. |
| `reports/temporal_gap_analysis.md` | Time ranges where evidence is strong, weak, or missing. |
| `reports/attack_stage_timeline.md` | Findings grouped by attack-stage style timeline when supported. |
| `reports/evidentiary_weighting.md` | Explanation of stronger versus weaker evidence support. |
| `reports/contradiction_analysis.md` | Conflicts, contradictions, and caution areas. |
| `reports/evidence_maturity.md` | Traceability and maturity of findings. |
| `reports/finding_provenance.md` | Finding-to-evidence provenance map. |
| `reports/agent_journal.md` | Human-readable agent execution and investigation journal. |
| `reports/overall_reports.md` | Collated report sections in one judge-friendly document. |

Important `reports/report.json` sections:

| Section | Purpose |
| --- | --- |
| `findings` | Structured correlated findings. |
| `truth_validation` | Truth-set scoring if a labeled truth dataset is supplied; otherwise expect `not_run`. |
| `inferred_analyst_reasoning` | Optional bounded LLM explanation when `--enable-reasoning` is used. |

### Findings

| File | Purpose |
| --- | --- |
| `findings/overall_findings.md` | First review file. Collates findings, coverage, failures, unknowns, and validation state. |
| `findings/agent_trace.json` | Structured agent/tool decision trace for judging and audit. |
| `findings/tool_results.json` | Tool execution results, exit codes, stderr paths, output paths, and timeout state. |
| `findings/parser_results.json` | Parser extraction results and record counts. |
| `findings/normalized_events.json` | Exported normalized event sample for quick review. |
| `findings/event_store.sqlite` | SQLite event store for larger normalized events and correlation support. |
| `findings/full_accounting.json` | Accounting of rows, sources, parser outputs, and event handling. |
| `findings/coverage.json` | What Blitz could inspect and which routes were partial. |
| `findings/unknowns.json` | Unknowns and unresolved areas that must not be overclaimed. |
| `findings/validation.json` | Validation issues and pass/fail state for report safety. |
| `findings/signal_integrity.json` | Signal-quality warnings and integrity notes. |
| `findings/investigation_guidance.json` | Suggested next review steps. |
| `findings/temporal_gap_analysis.json` | Structured temporal gap findings. |
| `findings/attack_stage_timeline.json` | Structured attack-stage timeline. |
| `findings/llm_report_verification.json` | Verification of LLM reasoning safety and support. |
| `findings/evidence_maturity.json` | Structured evidence maturity and traceability. |
| `findings/artifact_manifest.json` | Output artifact inventory and hashes. |

### Audit

| File | Purpose |
| --- | --- |
| `audit/progress.json` | Layer-by-layer progress state. |
| `audit/session_state.json` | Final session state and high-level run metadata. |
| `audit/<session>.ndjson` | Append-only audit events with timestamps. |
| `audit/collated_audit.md` | Collated audit summary for judge review. |

### Tool Output Folders

| Folder | Purpose |
| --- | --- |
| `timelines/` | Plaso/log2timeline outputs, psort exports, and timeline stderr/stdout logs. |
| `findings/` | Parser outputs, normalized exports, SQLite stores, and analysis JSON. |
| `reports/` | Human-readable Markdown, HTML, and structured report JSON. |
| `audit/` | Progress, session state, audit events, collated audit, and hashes. |

## Beginner Review Order

1. Open `findings/overall_findings.md`.
2. Open `reports/overall_reports.md`.
3. Open `reports/report.html`.
4. Open `reports/agent_journal.md`.
5. Open `findings/agent_trace.json`.
6. Open `audit/collated_audit.md`.
7. Check `findings/validation.json`.
8. Check `findings/coverage.json` and `findings/unknowns.json`.
9. Check `findings/tool_results.json` and `findings/parser_results.json` for failed or partial tools.
10. Check `findings/artifact_manifest.json` for output hashes.

Do not treat a small normalized-event count as proof that nothing happened. It only means that the selected tools and parsers produced that many normalized records. Always review coverage, unknowns, validation issues, and tool results.
