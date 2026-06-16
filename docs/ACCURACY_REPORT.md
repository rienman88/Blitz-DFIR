# Accuracy Report

Pending. This report must document false positives, missed artifacts, hallucinated claims, evidence integrity, and spoliation testing.

## Accuracy Position

Blitz DFIR will not claim submission-grade accuracy from partial smoke tests. Unit tests, parser tests, and smoke runs are engineering checks only. Accuracy evidence requires complete dataset execution after the core layers are functional enough to process, validate, correlate, correct, report, and audit the run end to end.

## Required Full Dataset Evidence

For each scored dataset, record:

- Dataset ID and source.
- Permission or license status.
- Artifact types and hashes where practical.
- Ground truth or analyst expectations.
- Exact command used.
- Tool versions and environment.
- Session output path.
- Whether the full selected dataset completed.
- Any timeout, manual interruption, parser degradation, retry, or bounded correction.
- True positives.
- False positives.
- Missed artifacts.
- Hallucinated or unsupported claims.
- Unknown zones.
- Evidence hash before analysis.
- Evidence hash after analysis.
- Audit log path proving tool sequence and finding traceability.
- Evidence maturity report path proving finding-to-event-to-parser-to-tool-to-audit linkage.
- Trust proof references from `docs/FIND_EVIL_TRUST_PROOF_PACKAGE.md` when used to support hallucination, guardrail, or traceability claims.

## Non-Credibility Cases

These results must not be presented as final accuracy evidence:

- Synthetic smoke tests.
- Partial runs without a declared scope boundary.
- Manually interrupted runs.
- Runs with zero normalized events unless the expected ground truth is also zero.
- Runs where evidence hashes were not checked before and after analysis.
- Runs where findings cannot be traced back to tool output and audit entries.
- Runs without `findings/evidence_maturity.json` or equivalent traceability artifact.
- Synthetic/adversarial trust scenarios by themselves. They prove layer behavior, not real-world accuracy.

## Trust Proof Addendum

Use this section when the final adversarial suite is executed. Keep it separate from real-dataset accuracy scoring.

- [x] Prompt-injection evidence scenario executed locally and linked: `tests/adversarial/test_llm_red_team_inputs.py`.
- [x] Poisoned or malformed parser-output scenario executed locally and linked: `tests/adversarial/test_llm_red_team_inputs.py`.
- [ ] Unsafe MCP/generic-shell/evidence-write rejection scenario executed and linked.
- [x] Contradiction/confidence-penalty scenario executed locally and linked: `tests/adversarial/test_evidence_weighting_and_contradictions.py`.
- [x] Unsupported LLM hypothesis containment scenario executed locally and linked: `tests/test_reasoning.py`; R2 also showed bounded model narrative did not create findings.
- [x] Selected finding provenance trace rendering tested locally: `tests/test_evidence_maturity.py`; real-case artifact still requires the next SIFT rerun.
- [ ] Trust proof outputs are described as layer-validation evidence, not formal true-positive/false-positive accuracy scoring.

## Current Status

- [ ] Full dataset accuracy testing has not passed yet because formal ground truth or analyst-reviewed true/false-positive scoring is still pending.
- [x] Large SIFT proof run completed for `BLITZ-RD01-PLASO-R1`: 1,329,652 normalized events, 500 findings, validation passed, unknowns=2, evidence maturity traceable findings=500, and artifact manifest written.
- [x] Post-fix SIFT rerun completed for `BLITZ-RD01-PLASO-R2`: 1,329,652 normalized events, 252 findings, validation passed, unknowns=2, duplicate finding IDs `0`, generic `evt` labels `0`, evidence maturity traceable findings `252/252`, and Bounded LLM Reasoning remained `INFERRED`.
- [x] Local trust-layer suite completed on 2026-06-01: 44 focused tests passed for prompt injection handling, malformed parser-output penalties, evidentiary weighting, contradiction confidence reduction, and provenance visualization.
- [x] Post-trust-layer SIFT rerun completed for `BLITZ-RD01-PLASO-R3`: 1,329,652 normalized events, 252 findings, validation passed, unknowns=2, `findings/evidentiary_weighting.json`, `findings/contradiction_analysis.json`, and `reports/finding_provenance.md` written; `e2e_ollama_check=passed`; `postrun_checks=passed`.
- [x] Parser progress stale counter fix and final SQLite WAL checkpoint fix were implemented after R3; they improve future judge-facing display/archive hygiene and do not change the R3 analytical findings.
- [ ] Known-good ground truth still needs to be selected or documented. Current fallback is analyst-expectation review for SANS Find Evil "find suspicious or unknown activity" triage.
- [x] Spoliation and bypass test code exists.
- [ ] Spoliation demo output still needs to be recorded for the final submitted run.
- [ ] Accuracy claims must remain conservative until full-capacity runs complete.

## Latest SIFT Proof Run

Run: `BLITZ-RD01-PLASO-R1`

Dataset source and permission:

- Source: SANS Find Evil hackathon-provided case material.
- Public naming: user confirmed on 2026-06-01 that this case can be described publicly as SANS-provided hackathon data.
- Redistribution boundary: raw evidence and proof archive remain local/private unless SANS terms explicitly permit redistribution.
- Formal ground truth: not currently known.
- Analyst expectation: identify suspicious, hidden, or unknown activity with traceable evidence and conservative claim language; do not inflate PLASO-only findings into multi-source proof.

Session:

```text
/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82
```

Observed from pasted SIFT status output:

- Status: `COMPLETED`.
- Final phase: `analysis_completed`.
- Typed tool: `psort`, exit code `0`, timed out `False`.
- Normalized events: `1,329,652`.
- Full accounting rows: `1,329,652`.
- SQL correlation rows scanned: `1,329,652`.
- SQL candidates: `17,880`.
- Findings: `500`.
- Validation: passed, `0` issues.
- Unknowns: `2`, with `0` critical and `0` high.
- Evidence maturity: `500` traceable findings out of `500`.
- Evidence hash preservation: recorded as `True` by the evidence maturity checkpoint.
- Bounded LLM Reasoning: completed with `ollama/llama3.2:1b` over bounded summaries only, `hypothesis_count=0`.
- Audit finalization and artifact manifest: completed.
- Exact command and launcher environment: captured in `docs/RUN_PROOF_SUMMARY_20260531T203012Z.md`.
- Before-analysis PLASO SHA256: `cd9a0ce596ecdda9100176ccc950ec9f539787c47ef3d421d32d7e9ebe0c1e55`.
- Parser-progress mismatch review: actual `progress.json`, `parser_results.json`, and audit entries show `parser_result_count=1`, `processed_count=1,329,652`, and `parser_completed`; the earlier `Parser result extraction (0/1)` display should be treated as a status-display issue, not parser failure.
- Preliminary finding review: see `docs/FINDING_REVIEW_20260531T203012Z.md`.
- Evidence hash check: `evidence_maturity.json` records `expected_sha256` and `observed_sha256` as `cd9a0ce596ecdda9100176ccc950ec9f539787c47ef3d421d32d7e9ebe0c1e55`, with `preserved=true`.

This is strong engineering and dataset-processing evidence. It is not final accuracy evidence until the following are completed:

- dataset source/license/permission documented
- ground truth or analyst expectations recorded
- representative findings reviewed for true positives and false positives
- missed artifacts and unsupported claims documented
- final artifacts archived from SIFT
- repeatability run recorded or marked as pending

Preliminary accuracy risks already identified:

- `500` report finding rows but only `252` unique finding IDs.
- All findings are single-source PLASO findings with confidence `0.55` and `SINGLE_SOURCE_PENALTY`.
- Most finding labels are generic: `SQL-correlated suspicious event: evt`.
- Bounded `llama3.2:1b` reasoning produced an unsupported SQL-injection/database narrative; it is useful only as containment proof because it remained `INFERRED` and did not create confirmed findings.

## Remediation Status For R1 Risks

The R1 archive is preserved exactly as produced. The following fixes were implemented after R1 and require a rerun to regenerate judge-facing artifacts:

- Duplicate finding IDs: SQL correlation now deduplicates findings before candidate persistence; report generation also deduplicates repeated finding IDs defensively.
- Generic SQL titles: PLASO/EVTX `evt` rows now receive evidence-derived labels such as living-off-the-land execution, persistence, credential/privileged-logon, warning, or selected-by-SQL-correlation.
- Non-JSON LLM narrative: bounded LLM reasoning now suppresses non-JSON/freeform model text instead of inserting it into the report narrative. The report records uncertainty that the model response was not valid structured output.

Judge-safe interpretation:

- The original R1 run is usable for scale, traceability, evidence preservation, audit, and LLM containment proof.
- R1 should not be used as the final accuracy narrative without either a rerun after these fixes or a manual analyst-reviewed subset.
- The single-source confidence score of `0.55` is still expected and correct for PLASO-only findings; higher confidence requires additional independent artifact families such as memory, PCAP, registry, or raw disk evidence.

## Post-Fix Rerun

Run: `BLITZ-RD01-PLASO-R2`

Session:

```text
/cases/BLITZ-RD01-PLASO/output/sess-20260601T010722Z-40b51cee
```

Observed proof:

- Status: `COMPLETED`.
- Analysis exit code: `0`.
- Normalized events: `1,329,652`.
- Full accounting rows: `1,329,652`.
- SQL correlation candidates: `17,880`.
- Findings: `252`.
- Unique finding IDs: `252`.
- Duplicate finding IDs: `0`.
- Generic `SQL-correlated suspicious event: evt` labels: `0`.
- Validation: passed, `0` issues.
- Unknowns: `2`, with `0` critical and `0` high.
- Evidence maturity traceability checkpoint: `252/252`.
- Reasoning evidence type: `INFERRED`.
- `sql injection` in reasoning narrative: `False`.
- `database` in reasoning narrative: `False`.
- All findings remain single-source PLASO findings with confidence `0.55` and `SINGLE_SOURCE_PENALTY`.

Judge-safe interpretation:

- R2 resolves the R1 presentation defects around duplicate finding rows, generic SQL event labels, and unsupported SQL/database narrative leakage.
- R2 is the current preferred PLASO proof candidate for scale, traceability, audit, conservative confidence, and LLM containment.
- R2 predates the 2026-06-01 trust-layer additions for evidentiary weighting, evidence contradiction analysis, and finding provenance visualization. Use it as the current clean PLASO baseline, then rerun after sync for final judge-facing trust artifacts.
- R2 still is not a multi-source confidence proof because it is scoped to one processed PLASO/EVTX-derived source.

## Post-Trust-Layer Rerun

Run: `BLITZ-RD01-PLASO-R3`

Session:

```text
/cases/BLITZ-RD01-PLASO/output/sess-20260601T113254Z-327c7a6a
```

Observed proof:

- Status: `COMPLETED`.
- Analysis exit code: `0`.
- Supervised launcher returned the SIFT prompt after completion.
- Normalized events: `1,329,652`.
- Full accounting rows: `1,329,652`.
- SQL correlation candidates: `17,880`.
- Findings: `252`.
- Validation: passed, `0` issues.
- Unknowns: `2`, with `0` critical and `0` high.
- Evidence maturity traceability checkpoint: `252/252`.
- New trust artifacts exist:
  - `findings/evidentiary_weighting.json`
  - `reports/evidentiary_weighting.md`
  - `findings/contradiction_analysis.json`
  - `reports/contradiction_analysis.md`
  - `reports/finding_provenance.md`
- Bounded LLM Reasoning remained `INFERRED`; raw evidence and raw tool output were not sent to the model.
- `e2e_ollama_check=passed`.
- `postrun_checks=passed`.
- Host proof archive verified before SIFT cleanup:
  - `Blitz_DFIR_Proof/sess-20260601T113254Z-327c7a6a_postfix_proof_full.tar`
  - size `9,856,256,000` bytes
  - SHA256 `1A8BB27CADB13DF89D4E29E8F5FECBBCF2E3CBD524D738720E551BA6B85744D8`
  - host hash matched the SIFT `.sha256` sidecar

R3 is the current preferred trust-layer proof candidate. It remains PLASO-only, so it proves conservative single-source analysis, evidence traceability, and LLM containment; it does not prove multi-source correlation confidence until memory, PCAP, registry, or raw disk artifacts are added.

R3 caveat: the status display still showed `Parser result extraction (0/1)`. The artifacts show this was a stale display counter, not parser failure: `parser_results.json` exists, parser output was normalized to 1,329,652 events, and downstream validation/reporting completed. A code fix was added after R3 so completed progress layers replace stale running counters.

R3 archive caveat: the session still listed SQLite `event_store.sqlite-wal` and `event_store.sqlite-shm` sidecars. Preserve them if archiving R3 exactly. A code fix was added after R3 to checkpoint the SQLite event store before final artifact-manifest hashing in future runs.
