# Submission Checklist

Source of truth for the eight required Devpost components. Missing any one component is an elimination risk.

Current organizer-facing proof alignment: `docs/FIND_EVIL_TRUST_PROOF_PACKAGE.md`.

## Required Components

- [ ] Public GitHub repository with MIT or Apache 2.0 license.
- [ ] Demo video, 5 minutes max, showing live terminal execution against real case data and at least one self-correction sequence.
- [x] Architecture diagram created in `docs/ARCHITECTURE.md`.
- [ ] Devpost project story: what it does, how it was built, challenges, what was learned, what is next.
- [ ] Dataset documentation in `docs/DATASETS.md`, updated with real tested data.
- [ ] Accuracy report in `docs/ACCURACY_REPORT.md`.
- [ ] Try-it-out instructions in README and Protocol SIFT integration docs.
- [ ] Agent execution logs with timestamps, tool sequence, agent communication, and token usage.
- [ ] Evidence maturity artifact: `findings/evidence_maturity.json` and `reports/evidence_maturity.md` from the submitted demo run.
- [ ] Organizer proof bundle staged with final reports, audit logs, hashes, accuracy report, dataset docs, demo links, and agent logs.

## Judging Evidence

- [ ] Autonomous execution: real agent run with next-step reasoning and self-correction.
- [ ] IR accuracy: full selected dataset execution, evidence-backed findings, false positives, missed artifacts, hallucination handling.
- [ ] Breadth and depth: focused depth on tested artifact types before broad claims.
- [ ] Constraint implementation: typed MCP, allowlists, no generic shell, evidence immutability, bypass tests.
- [ ] Audit trail: every finding traceable to tool execution and audit entry.
- [ ] Evidence maturity: at least one finding is traced from report finding to normalized event, parser result, typed tool output, and audit entry.
- [ ] Adversarial evidence validation: prompt-injection evidence, poisoned output, unsafe requests, and mutation attempts are detected, sanitized, rejected, downgraded, or recorded.
- [ ] Evidence-to-conclusion verification: every selected demo claim shows supporting evidence, confidence modifiers, contradictions or unknowns, and provenance.
- [ ] Usability: SIFT setup, dependency install, manifest, run commands, report review.
- [ ] SIFT/Protocol SIFT positioning: explicitly state that Blitz does not replace or bundle SIFT tools. SIFT provides the forensic utilities, Protocol SIFT/OpenClaw/Claude Code provides the agent workflow, and Blitz provides typed safety controls, batch planning, accounting, validation, unknowns, and audit-backed reports.
- [ ] Batch execution evidence: show `findings/batch_plan.json`, explain `max_parallel_tools=1`, and demonstrate that broad analysis is split into artifact-family batches instead of unbounded continuous execution.
- [ ] Full accounting evidence: show row count alignment between exported CSV and `event_store.sqlite`, and explain why reports stay bounded while full exported rows are preserved.
- [ ] Evidence-first planning evidence: show `findings/case_objective.json`, `findings/investigation_plan.json`, `findings/evidence_triage.json`, and matching Markdown reports; explain that objectives and plans guide priority but do not create findings.

## Full Dataset Credibility Gate

- [x] Core layers are complete enough for end-to-end testing before final accuracy scoring.
- [x] At least one large SIFT proof run completed without manual interruption: `BLITZ-RD01-PLASO-R1`.
- [ ] Ground truth or analyst expectations are recorded before scoring.
- [x] Evidence hashes are checked before and after the complete run as explicit values for `BLITZ-RD01-PLASO-R1`.
- [ ] Failures, timeouts, parser degradation, bounded reruns, and unknown zones are recorded.
- [ ] Partial tests remain labeled as engineering validation, not submission-grade accuracy.
- [x] Exact command/launcher for `BLITZ-RD01-PLASO-R1` is captured.
- [x] Final artifacts from `BLITZ-RD01-PLASO-R1` are archived on the Windows host and SHA256 verified.
- [x] Parser progress mismatch `Parser result extraction (0/1)` is inspected and explained before judge presentation; actual progress/parser/audit artifacts show parser result count `1`.
- [ ] Optional memory dataset `BLITZ-MEMORY-001` is tested or explicitly deferred.
- [x] Preliminary finding-review risks are disclosed: duplicate finding rows, single-source confidence, generic labels, and weak Bounded LLM narrative.
- [x] Code fixes added for duplicate finding rows, generic SQL labels, and non-JSON Bounded LLM narrative suppression.
- [x] Rerun selected judge-facing case after the 2026-06-01 fixes: `BLITZ-RD01-PLASO-R2`, session `sess-20260601T010722Z-40b51cee`.
- [x] Post-fix R2 quality capture copied to host and SHA256 verified: `Blitz_DFIR_Proof/postfix_session_quality.txt`, hash `753FB447AE7C89BCD827A814A36CBDCCCE612538FCD55F2732455BB540AFD005`.
- [x] Host helper added for the remaining R2 proof archive transfer: `scripts/blitz_fetch_postfix_proof_archive.ps1`.
- [x] SIFT Ollama launcher hardening added: `scripts/sift_e2e_ollama_run.sh` now defaults to supervised completion, returns the prompt after the analysis PID exits, runs post-run checks on success, and keeps detached mode available with `WAIT_FOR_COMPLETION=0`.
- [x] Evidentiary weighting, evidence contradiction analysis, and finding provenance visualization added locally with adversarial tests.
- [x] Rerun selected SIFT case after the 2026-06-01 trust-layer additions. R3 session: `/cases/BLITZ-RD01-PLASO/output/sess-20260601T113254Z-327c7a6a`; includes `evidentiary_weighting`, `contradiction_analysis`, and `finding_provenance` artifacts.
- [x] Post-trust R3 E2E and post-run checks passed: `e2e_ollama_check=passed`, `postrun_checks=passed`.
- [x] Parser progress display issue identified as stale completed-layer counter state, not parser failure; code fix added after R3.
- [x] SQLite event-store final checkpoint fix added after R3 so future completed runs settle WAL sidecars before artifact manifest hashing.
- [x] Evidence-first planning architecture added locally: optional `--case-objective` input, case objective artifact, investigation plan artifact, evidence triage artifact, report sections, progress/monitor layers, and focused tests.
- [x] Judge-facing monitor clarity added: `blitz_status.sh` separates analysis progress from supervised run completion and lists report/LLM/safety/provenance/audit/postrun readiness explicitly.
- [x] High-volume stress capability added locally for next SIFT validation: normalized cap supports 5M, psort filter can be disabled for full PLASO export, and `scripts/sift_high_volume_stress_ladder.sh` records current-ceiling 1M/2M/3M/4M/5M target verification.
- [x] Archive and host-verify the `BLITZ-RD01-PLASO-R3` proof package before deleting SIFT outputs or copying the 17G memory dataset. Host archive: `Blitz_DFIR_Proof/sess-20260601T113254Z-327c7a6a_postfix_proof_full.tar`; size `9,856,256,000` bytes; SHA256 `1A8BB27CADB13DF89D4E29E8F5FECBBCF2E3CBD524D738720E551BA6B85744D8`; host hash matched the SIFT `.sha256` sidecar.
- [ ] Clean generated SIFT run/output/proof tar data after confirming no Blitz/psort process is active. Use `scripts/sift_clean_generated_for_rerun.sh` for sessions/runs and `scripts/sift_clean_remote_proof_archives.sh` for remote proof tar archives. Preserve `/cases/BLITZ-RD01-PLASO/case.yaml`, `/cases/BLITZ-RD01-PLASO/processed/case.plaso`, small `.sha256` proof sidecars if useful, and the Windows host proof archive.
- [ ] After syncing, rerun one evidence-first proof pass and preserve the new monitor/readiness output as judge-facing evidence.
- [ ] Rerun EVTX-focused evidence before the large memory dataset so event-log routing and report readiness remain freshly validated.
- [ ] Run high-volume stress after the proof pass only if SIFT has enough free disk. Do not claim 1M/2M/3M/4M/5M unless `stage_status.jsonl` shows `target_met=true` for each target.
- [ ] Run the 17G memory dataset after the EVTX rerun and stress ladder, unless disk or Volatility profile limitations require deferral.

## Trust Proof Gate

These items merge the external trust-layer recommendation with the all-layer proof plan.

- [x] `ADV-EVID-PROMPT-001` or equivalent prompt-injection evidence proof executed locally.
- [x] `ADV-EVID-POISON-001` or equivalent malformed/poisoned parser-output proof executed locally.
- [ ] `ADV-MCP-ESCAPE-001` or equivalent generic shell/evidence-write rejection proof executed.
- [x] `ADV-CONC-PROVENANCE-001` or equivalent full finding trace proof executed locally.
- [x] `ADV-CONC-CONTRADICTION-001` or equivalent contradiction/confidence penalty proof executed locally.
- [x] `ADV-CONC-LLM-001` or equivalent unsupported LLM hypothesis containment proof executed locally and observed in R2.
- [ ] Selected trust proofs are copied or summarized into the final organizer proof bundle.
- [ ] Demo script references the selected trust proofs by exact file path or command.

## Current Recommended Demo Flow

1. Show architecture diagram and state the pattern: Custom MCP Server with Protocol SIFT-compatible typed boundary.
2. State the role split: SIFT tools, Protocol SIFT agent workflow, Blitz safety/accounting layer.
3. Run `python app.py analyze` on real processed PLASO or another documented case artifact.
4. Run one mixed-source manifest with up to six inputs, including at least two processed tool outputs such as `VOLATILITY_JSON`, `YARA_MATCHES`, or `STRINGS_OUTPUT`, and preserve `report.json.correlation_scope` plus audit event `correlation_scope_recorded`.
5. Show `findings/batch_plan.json` and explain stepwise artifact-family routing.
6. Show full accounting row counts and `event_store.sqlite`.
7. Show audit log lifecycle events.
8. Show `report.html` in the browser.
9. Trace one finding through `findings/evidence_maturity.json` or `reports/evidence_maturity.md`.
10. Show validation/correction/unknowns and explain conservative claim handling.
11. Show prompt-injection, poisoning, MCP rejection, or spoliation proof.
12. Show evidence hash before/after to prove no spoliation.
13. Show MCP typed tool smoke or live OpenClaw/Claude tool call if available.

## Private Provider Rule

Private OpenAI-compatible provider tests under `local/` are developer-only. Do not include those harnesses, outputs, keys, or provider-specific setup as required public submission steps.
