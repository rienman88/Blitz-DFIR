# Finding Review: sess-20260531T203012Z-bff65d82

Purpose: preliminary accuracy and presentation review of the completed `BLITZ-RD01-PLASO` SIFT proof run.

This review is based on the extracted proof artifacts in:

```text
Blitz_DFIR_Proof/extracted_review/output/sess-20260531T203012Z-bff65d82/
```

## Review Status

- [x] Proof artifacts copied from SIFT and full archive SHA256 verified.
- [x] Exact command and launcher environment captured.
- [x] Parser-progress display mismatch investigated.
- [x] Evidence hash before/after value found in `evidence_maturity.json`.
- [x] Preliminary finding-quality review completed.
- [x] Dataset source/license/permission recorded from user confirmation.
- [x] Analyst expectations recorded because formal ground truth is not currently known.
- [ ] True-positive / false-positive / false-negative scoring is not complete.

## Evidence Hash Result

`findings/evidence_maturity.json` records:

```text
evidence_id: rd01-plaso
evidence_type: PLASO
expected_sha256: cd9a0ce596ecdda9100176ccc950ec9f539787c47ef3d421d32d7e9ebe0c1e55
observed_sha256: cd9a0ce596ecdda9100176ccc950ec9f539787c47ef3d421d32d7e9ebe0c1e55
preserved: true
status: preserved
```

Judge-safe claim:

> Blitz recorded the expected and observed PLASO SHA256 values and they matched after analysis.

## Parser Progress Mismatch Result

The pasted terminal display showed `Parser result extraction (0/1)`.

The preserved artifacts show parsing completed:

- `progress.final.json`: `parser_results=1`, `parser_result_count=1`, `parser_processed_count=1329652`.
- `audit/progress.json`: same parser counts.
- `findings/parser_results.json`: one parser result, parser `plaso`, `processed_count=1329652`.
- Audit log: `parser_completed`, `processed_count=1329652`, `malformed_count=0`, `warning_count=0`.
- Audit log: `batch_completed`, `parser_result_count=1`.

Conclusion: treat the pasted `0/1` line as a terminal/status display issue, not a parser-layer failure.

## Finding Statistics

- Reported findings: `500`
- Unique finding IDs: `252`
- Duplicate finding entries: `248`
- Evidence maturity traces: `500`
- Unique evidence maturity finding IDs: `252`
- Complete traces: `500`
- Validation issues: `0`
- Unknowns: `2`
- Critical/high unknowns: `0`
- Signal warnings: `2`
- Contradictions: `0`
- Source tool: `psort`
- Parser: `plaso`
- Evidence source: `rd01-plaso`

## Confidence And Scope

- All findings have confidence `0.55`.
- All findings carry `SINGLE_SOURCE_PENALTY`.
- This is correct conservative behavior for a PLASO-only scoped run.
- This run should not be presented as multi-source correlation proof because memory, PCAP, registry, and raw disk artifact families were not independently correlated in this run.

Judge-safe claim:

> The run demonstrates full-row SQL correlation over a large processed PLASO/EVTX-derived timeline, with conservative single-source confidence penalties.

Do not claim:

> Blitz proved a complete attack chain across memory, PCAP, registry, and disk.

## Finding Distribution

Finding labels:

- `SQL-correlated suspicious event: evt`: `497`
- `Long-horizon authentication activity`: `1`
- `Long-horizon credential activity`: `1`
- `Long-horizon persistence activity`: `1`

Attack-stage labels:

- `persistence`: `498`
- `privilege_or_credential_use`: `498`
- `execution`: `497`
- `initial_access_or_lateral_movement`: `494`

Top raw event sources:

- `NTFS:/Windows/System32/winevt/Logs/Security.evtx`: `166`
- `VSS2:NTFS:/Windows/System32/winevt/Logs/Security.evtx`: `166`
- `VSS1:NTFS:/Windows/System32/winevt/Logs/Security.evtx`: `153`
- `Windows [blocked tool request].evtx` variants: `12`

## Accuracy Risks Found

### Duplicate Finding Entries

The report has `500` finding entries but only `252` unique finding IDs. Many duplicated IDs appear exactly twice.

Interpretation:

- This does not break traceability because all 500 traces are complete.
- It is a presentation and scoring risk.
- For accuracy scoring, count unique finding IDs or deduplicate before judge presentation.

Recommended action:

- [x] Add or run a deduplication check before final demo/report review. Code fix added on 2026-06-01.
- [ ] Rerun the PLASO case after the fix and verify report count, evidence maturity count, and validation still agree.
- [ ] If code is not changed before submission, explicitly score unique findings, not raw displayed finding rows.

### Generic Finding Labels

Most findings are labeled `SQL-correlated suspicious event: evt`, which is technically traceable but not analyst-friendly.

Interpretation:

- This is acceptable for engineering proof of full SQL scanning and traceability.
- It is weak for a judge-facing investigation story.

Recommended action:

- [x] Improve deterministic SQL finding labels before the next judge-facing run. Code fix added on 2026-06-01.
- [ ] Select a small number of representative findings and manually review their event content before using them in the demo.
- [ ] Prefer showing evidence maturity traceability, row accounting, and conservative confidence over claiming a polished investigation narrative from these generic labels.

### Bounded LLM Reasoning Is Not Judge-Safe As Narrative

The bounded Ollama `llama3.2:1b` reasoning section recorded:

- `raw_evidence_sent=false`
- `raw_tool_output_sent=false`
- `evidence_type=INFERRED`
- `hypothesis_count=0`
- `analysis_limits` includes `model response was not JSON`

However, the generated narrative incorrectly talks about SQL injection vulnerabilities and database issues. That is not supported by the DFIR evidence.

Interpretation:

- This is a successful containment proof: bad LLM reasoning stayed inferred and did not create confirmed findings.
- This is not a good reasoning-quality proof.

Recommended action:

- [x] Do not use this Bounded LLM narrative as judge-facing analytical output.
- [ ] Use this run to prove deterministic layers and LLM containment only.
- [x] Require clean JSON/grounded narrative before model output can influence the report narrative. Code fix added on 2026-06-01 to suppress non-JSON freeform text.
- [ ] For the demo, either disable bounded LLM reasoning or use a stronger, logged model and require clean JSON/grounded narrative.
- [ ] Keep emphasizing: AI reasoning is `INFERRED`, never evidence.

### Single-Source Evidence

All findings come from `rd01-plaso` through `psort/plaso`.

Interpretation:

- Strong proof for processed timeline handling.
- Weak proof for multi-source correlation/confidence.

Recommended action:

- [ ] Use the proposed memory dataset as a second artifact-family proof.
- [ ] Build adversarial correlation/confidence scenarios for multi-source behavior.
- [ ] Do not claim full multi-source DFIR correlation from this PLASO-only run.

## What This Run Is Strong For

- Large processed PLASO handling.
- Safe `psort` typed tool execution.
- Full accounting row preservation.
- SQLite-backed normalization and SQL correlation at 1.3M-row scale.
- Evidence maturity traceability.
- Audit lifecycle proof.
- Evidence hash preservation.
- Conservative single-source confidence behavior.
- LLM containment: poor reasoning did not become evidence.

## What This Run Is Weak For

- Final accuracy scoring.
- Ground-truth attacker reconstruction.
- Multi-source correlation.
- Reasoning-quality demonstration.
- Self-correction demonstration, because correction status was `SKIPPED`.
- Polished investigation narrative, because most finding labels are generic.

## Recommended Presentation

Use this run for:

1. Scale proof.
2. Traceability proof.
3. Evidence safety proof.
4. Full accounting proof.
5. Conservative confidence proof.

Do not use this run alone for:

1. Final attack-chain accuracy.
2. High-quality LLM reasoning.
3. Multi-artifact correlation.
4. Self-correction proof.

## Required User Input

User input received on 2026-06-01:

- [x] Dataset can be publicly named as SANS Find Evil hackathon-provided case material.
- [x] Source/permission statement: provided by SANS for the hackathon. Do not redistribute raw evidence unless SANS terms explicitly permit it.
- [x] Formal ground truth is not currently known.
- [x] Analyst expectation: because this is a "Find Evil" case, Blitz should surface suspicious, hidden, or unknown activity while minimizing hallucinated/unsupported claims.

Still required to complete accuracy scoring:

- [ ] Whether the August/September 2018 Windows EVTX activity corresponds to known attacker activity, benign test activity, or unknown.
- [ ] Whether `Windows [blocked tool request].evtx` is expected sanitized evidence content, suspicious artifact naming, or a parser/report sanitization side effect.

## Post-Review Code Fixes

Implemented after this R1 review:

- SQL correlation deduplicates repeated finding IDs before candidate persistence.
- Report building deduplicates repeated finding IDs defensively before applying report limits.
- SQL finding labels no longer emit the generic `SQL-correlated suspicious event: evt` pattern for `evt` rows.
- Bounded LLM Reasoning suppresses non-JSON/freeform model narrative and records uncertainty instead.

These fixes do not alter the preserved R1 proof archive. They require a rerun before claiming the submitted artifacts are clean of the duplicate/generic-label/non-JSON-narrative risks.
