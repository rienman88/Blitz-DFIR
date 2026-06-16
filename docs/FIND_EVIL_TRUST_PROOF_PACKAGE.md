# Find Evil Trust Proof Package

Purpose: align the adversarial trust-layer recommendations with the existing all-layer test plan and the Devpost organizer requirements.

This is not a replacement architecture. Blitz keeps the current flow:

```text
Evidence
-> Integrity
-> Typed execution
-> Parser validation and sanitization
-> Normalization
-> Correlation
-> Validation and bounded correction
-> Evidence maturity
-> Reporting and audit
```

The recommendation becomes a judge-facing proof overlay:

```text
Can the evidence be trusted?
Can the conclusion be trusted?
Can both be demonstrated under adversarial pressure?
```

## Official Submission Anchors

Source: `https://findevil.devpost.com/rules`, checked on 2026-06-01.

- [ ] Submission deadline: 2026-06-15 11:45 PM EDT.
- [ ] Project must run on or integrate with SANS SIFT Workstation.
- [ ] Project must use Claude Code, OpenClaw, or a comparable agentic architecture.
- [ ] Demo video must show live terminal execution against real evidence.
- [ ] Demo video must include at least one self-correction sequence.
- [ ] Repository must be public and open source with MIT or Apache 2.0 license.
- [ ] README must include setup and run instructions.
- [ ] Submission must include architecture diagram.
- [ ] Submission must include evidence dataset documentation.
- [ ] Submission must include accuracy report with false positives, missed artifacts, and hallucinated claims.
- [ ] Submission must include agent execution logs with timestamps, tool sequence, and token usage where available.
- [ ] Judges must be able to trace any finding back to the specific tool execution that produced it.

## Winning Thesis

Blitz should be presented as:

> A Protocol SIFT-compatible controlled forensic reasoning layer that computes trust instead of assuming it.

Do not lead with "more parsers" or "more agents." Lead with:

- evidence remains data, not instruction
- raw, derived, and inferred content stay separated
- findings must prove themselves through evidence maturity
- contradictions and unknown zones reduce confidence
- unsupported LLM output remains `INFERRED`
- every submitted claim is tied to audit-backed artifacts

## Trust Layer 1: Adversarial Evidence Validation

Purpose: prove Blitz cannot be manipulated by hostile evidence text, poisoned parser output, malformed rows, or unsafe agent requests.

Mapped Blitz layers:

- parser validation
- sanitization boundary
- signal integrity
- controlled typed MCP boundary
- reasoning containment
- audit hardening
- reporting escaping

Required proof checklist:

- [x] `ADV-EVID-PROMPT-001`: prompt injection text inside evidence is neutralized or bounded before reasoning. Local proof: `tests/adversarial/test_llm_red_team_inputs.py`.
- [x] `ADV-EVID-PROMPT-002`: role-changing language, tool-request language, and "report clean" instructions remain evidence data, not agent instruction. Local proof: `tests/adversarial/test_llm_red_team_inputs.py`.
- [ ] `ADV-EVID-HTML-001`: malicious HTML/Markdown/control characters are escaped in reports.
- [x] `ADV-EVID-POISON-001`: malformed CSV/JSON/parser output creates parser warnings and confidence penalties. Local proof: `tests/adversarial/test_llm_red_team_inputs.py`.
- [x] `ADV-EVID-TIME-001`: shifted or inconsistent timestamps create signal-integrity warnings or contradictions. Local proof: `tests/adversarial/test_evidence_weighting_and_contradictions.py`.
- [ ] `ADV-EVID-MUTATE-001`: attempted evidence mutation is rejected and before/after evidence hashes remain unchanged.
- [ ] `ADV-MCP-ESCAPE-001`: generic shell, path escape, unregistered tool, and evidence-write attempts are rejected.
- [ ] `ADV-LLM-EXFIL-001`: raw evidence, raw stdout, memory strings, and sensitive local paths are not sent to the LLM.

Minimum organizer-facing artifacts:

- [ ] test output or eval output for each adversarial scenario
- [ ] `findings/signal_integrity.json`
- [ ] `findings/validation.json`
- [ ] `findings/evidence_maturity.json`
- [ ] `reports/report.html`
- [ ] `audit/*.ndjson`
- [ ] before/after evidence SHA256 proof
- [ ] short demo clip or terminal transcript showing one rejected unsafe request

Judge-safe claim:

> Blitz treats evidence-derived text as hostile data. Prompt injection, malformed output, unsupported tool requests, and mutation attempts are either sanitized, rejected, downgraded, or recorded as limitations before any conclusion is produced.

## Trust Layer 2: Evidence-To-Conclusion Verification

Purpose: force every conclusion to prove itself through evidence references, parser output, typed tool execution, audit trail, confidence modifiers, contradictions, and alternative explanations.

Mapped Blitz layers:

- deterministic normalization
- correlation
- confidence scoring
- evidentiary weighting
- contradiction detection
- evidence contradiction analysis
- validation
- bounded self-correction
- evidence maturity
- reporting
- audit chain

Required proof checklist:

- [x] `ADV-CONC-PROVENANCE-001`: one finding traces from report finding ID to normalized event, evidence ID, parser result, typed tool output, and audit entry hash. Local proof: `tests/test_evidence_maturity.py`; future run artifact: `reports/finding_provenance.md`.
- [ ] `ADV-CONC-MISSING-LINK-001`: incomplete trace is marked incomplete and not hidden.
- [x] `ADV-CONC-SINGLE-001`: single-source finding receives a visible confidence penalty. R2/R3 PLASO-only findings remain conservative with single-source penalties.
- [x] `ADV-CONC-MULTI-001`: multi-source agreement improves confidence only when independent evidence supports the same claim. Local proof: `tests/adversarial/test_evidence_weighting_and_contradictions.py`.
- [x] `ADV-CONC-CONTRADICTION-001`: cross-source disagreement creates a contradiction object and confidence penalty. Local proof: `tests/adversarial/test_evidence_weighting_and_contradictions.py`.
- [ ] `ADV-CONC-UNKNOWN-001`: missing artifact families create unknown zones and avoid full-coverage claims.
- [ ] `ADV-CONC-ALT-001`: final report includes alternative explanations or analyst-review notes for non-confirmed findings.
- [ ] `ADV-CONC-LLM-001`: unsupported LLM hypothesis remains `INFERRED`, low-confidence, or unsupported.

Minimum organizer-facing artifacts:

- [x] `findings/evidence_maturity.json` generated in R3.
- [x] `reports/evidence_maturity.md` generated in R3.
- [x] `findings/evidentiary_weighting.json` generated in R3.
- [x] `reports/evidentiary_weighting.md` generated in R3.
- [x] `findings/contradiction_analysis.json` generated in R3.
- [x] `reports/contradiction_analysis.md` generated in R3.
- [x] `reports/finding_provenance.md` generated in R3.
- [ ] selected finding trace excerpt
- [ ] `findings/validation.json`
- [ ] `findings/unknowns.json`
- [ ] `findings/coverage.json`
- [ ] `reports/report.json`
- [ ] `reports/report.html`
- [ ] `audit/*.ndjson`
- [ ] agent execution log that links the agent request to Blitz typed tool execution

Judge-safe claim:

> Blitz does not allow conclusions to stand alone. Each submitted finding carries evidence references, confidence modifiers, validation status, and an evidence-maturity trace back to parser/tool/audit artifacts where available.

## Under-Five-Minute Demo Sequence

The video must be direct. No marketing intro.

1. `0:00-0:30` State the architecture and role split: SIFT tools extract, OpenClaw or Claude Code requests typed actions, Blitz enforces trust and audit.
2. `0:30-1:15` Show manifest, evidence hash, and selected real SIFT case run.
3. `1:15-2:00` Show terminal output: normalized events, findings, validation, report path, audit path, evidence maturity path.
4. `2:00-2:45` Open one report finding and trace it through `evidence_maturity.json` or `evidence_maturity.md`.
5. `2:45-3:30` Show adversarial evidence validation: prompt-injection evidence or unsafe shell/mutation request is detected, rejected, sanitized, or downgraded.
6. `3:30-4:15` Show self-correction: parser degradation, timeout, contradiction, or low confidence triggers bounded recovery or an honest unresolved limitation.
7. `4:15-5:00` Show final proof bundle: dataset docs, accuracy report, agent logs, audit, report, and hash preservation.

If no organic self-correction occurs in the real dataset, use a clearly labeled adversarial scenario that operates through the same Blitz pipeline. Do not pretend that a synthetic adversarial result is real-world accuracy proof.

## Organizer Proof Bundle

Recommended final local staging path:

```text
Blitz_DFIR_Proof/final_submission/
  README_FOR_JUDGES.md
  devpost_links.txt
  architecture/
  datasets/
  accuracy/
  agent_logs/
  demo/
  proof_runs/
  adversarial_evals/
  hashes/
```

Required bundle checklist:

- [ ] Public repo URL and commit hash.
- [ ] License verified as MIT or Apache 2.0.
- [ ] README setup path verified on SIFT or documented SIFT-equivalent environment.
- [ ] Devpost project description drafted.
- [ ] Demo video URL recorded.
- [ ] Architecture diagram included or linked.
- [ ] Dataset documentation copied from `docs/DATASETS.md`.
- [ ] Accuracy report copied from `docs/ACCURACY_REPORT.md`.
- [ ] Real case walkthrough copied from `docs/REAL_CASE_WALKTHROUGH.md`.
- [ ] Agent execution logs copied from the selected OpenClaw or Claude Code run.
- [ ] Blitz audit logs copied from selected session.
- [ ] Evidence maturity artifacts copied from selected session.
- [ ] Report artifacts copied from selected session.
- [ ] Artifact manifest copied from selected session.
- [ ] Proof archive SHA256 recorded.
- [ ] Public scrub completed: no raw private evidence, no secrets, no private provider harness outputs.

## Submission Story Map

| Judging criterion | Blitz proof artifact | Demo moment |
| --- | --- | --- |
| Autonomous Execution Quality | Agent log, correction history, validation report | Self-correction segment |
| IR Accuracy | Accuracy report, evidence maturity, false-positive review | Finding trace segment |
| Breadth and Depth | Dataset docs, batch plan, full accounting, selected artifact families | Real case run segment |
| Constraint Implementation | MCP rejection, allowlist, no generic shell, spoliation demo | Adversarial evidence segment |
| Audit Trail Quality | Audit NDJSON, artifact manifest, evidence maturity | Traceability segment |
| Usability and Documentation | README, Protocol SIFT integration docs, run commands | Final proof bundle segment |

## Hard Rules

- [ ] Do not claim final DFIR accuracy without ground truth or analyst-reviewed expected behavior.
- [ ] Do not submit raw SANS evidence unless the rules or dataset license explicitly allow redistribution.
- [ ] Do not include private provider keys, local harnesses, secrets, or raw sensitive tool output.
- [ ] Do not call Bounded LLM Reasoning evidence.
- [ ] Do not claim disk offsets unless the evidence source and parser actually provide them.
- [ ] Do not add broad new features unless they close a specific judging proof gap.
- [ ] Do not hide failures; convert them into validation, unknown-zone, confidence, or limitation proof.

## Immediate Execution Checklist

- [x] Archive and host-verify the current post-trust R3 proof package: `Blitz_DFIR_Proof/sess-20260601T113254Z-327c7a6a_postfix_proof_full.tar`, SHA256 `1A8BB27CADB13DF89D4E29E8F5FECBBCF2E3CBD524D738720E551BA6B85744D8`.
- [ ] Clean generated SIFT sessions/runs and remote proof tar archives before the memory-dataset intake using `scripts/sift_clean_generated_for_rerun.sh` and `scripts/sift_clean_remote_proof_archives.sh`.
- [ ] Select the final demo run.
- [ ] Build the minimal adversarial trust suite from this document and `docs/ADVERSARIAL_EVALUATION_PLAN.md`.
- [ ] Capture an OpenClaw or Claude Code tool-call log linked to the selected Blitz session.
- [ ] Fill `docs/ACCURACY_REPORT.md` with true positives, false positives, missed artifacts, hallucinated claims, and limitations.
- [ ] Fill `docs/REAL_CASE_WALKTHROUGH.md` with evidence-backed claims only.
- [ ] Update `docs/DEMO_SCRIPT.md` with exact final paths.
- [ ] Create the final organizer proof bundle.
