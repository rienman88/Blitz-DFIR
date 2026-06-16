# Accuracy Report

## Accuracy Position

This run is an autonomous triage and correlation result, not a final courtroom-style attribution report. Blitz produced evidence-backed suspicious findings and preserved uncertainty where tool coverage degraded.

## Ground Truth Status

No independent ground-truth answer key was loaded into Blitz for this run.

The report's `truth_validation` status is therefore `not_run`. This means precision, recall, and F1 are not meaningful for this run and should not be presented as measured accuracy.

## What Appears Reliable

The following are reliable as system behaviors:

- Evidence hashes were verified before analysis.
- Six expected memory plugins ran successfully.
- Full Plaso E01 timeline extraction failed and was recorded.
- Bounded disk triage fallback ran successfully after Plaso failed.
- Normalization completed with `1,124,391` events.
- Full SQL correlation completed with `22,293` findings.
- LLM verification passed.
- Artifact hashes were generated.
- Agent trace and audit logs were generated.

The following are reliable as evidence-backed observations:

- Volatility `malfind` produced `16` memory injection candidate records.
- Several memory findings involved executable or read-write-execute memory regions in processes such as `MsMpEng.exe`, `SearchApp.exe`, `dllhost.exe`, `Teams.exe`, and `smartscreen.ex`.
- Disk fallback surfaced execution, persistence, scheduled task, PowerShell history, Windows prefetch, startup item, and suspicious path candidates.

## False Positive Risk

False positive risk is material.

Reasons:

- Many findings are single-source and receive a single-source limitation.
- Disk fallback uses filesystem metadata and path/risk heuristics, not full semantic event reconstruction.
- `malfind` can identify suspicious memory regions that require manual context review.
- Some process memory regions can be benign JIT, instrumentation, or legitimate application behavior.
- The full E01 Plaso timeline did not complete.

Blitz mitigates this by labeling findings as evidence-backed review candidates rather than final malicious conclusions.

## Missed Artifact Risk

Missed artifact risk is also material.

Reasons:

- Full Plaso timeline extraction failed.
- EVTX, Registry, SRUM, USB, Windows Timeline, and full timeline coverage were not fully observed.
- Only bounded fallback disk triage was available for disk coverage.
- LLM reasoning was bounded to summaries and cannot discover new evidence independently.

Blitz mitigates this by recording validation issues, unknown zones, coverage gaps, and recommended follow-up tools.

## Hallucination Controls

The LLM did not create findings.

Controls:

- Raw evidence sent to LLM: `False`
- Raw tool output sent to LLM: `False`
- LLM evidence type: `INFERRED`
- LLM invalid evidence references: `0`
- Unsupported hypotheses: `0`
- Blocked tool requests: `0`
- LLM verification status: `passed`

The model response also had structured-output limitations, but Blitz suppressed invalid model narrative and preserved the verified bounded explanation path.

## Evidence Integrity And Spoliation Controls

Blitz prevents original evidence modification through architecture, not prompts:

- Evidence must be listed in `case.yaml`.
- Evidence hashes are checked before analysis.
- Evidence paths are read as manifest-registered inputs.
- Raw evidence can be referenced from external folders without copying into the case root.
- Tool execution writes to session-scoped output folders.
- Subprocess execution uses typed adapters and argument arrays.
- Generic shell execution is not exposed as an MCP tool.
- Output artifacts are hashed in `artifact_manifest.json`.

Spoliation testing is represented by the manifest/integrity gate and path-safety design. The run used `external_absolute_paths_no_copy`, so the large memory and E01 evidence did not need to be duplicated into the combined case folder.

## Validation Result

Validation did not pass cleanly:

- Total issues: `12`
- High parser degradation or signal loss: `6`
- Medium missing evidence: `6`

Interpretation: the run completed, but the result must be read as degraded disk timeline coverage due to Plaso/dfVFS failure. This is an honest limitation and should be submitted as such.

