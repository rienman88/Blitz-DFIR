# Two-Week Test Completion Plan

Purpose: focus the remaining submission window on proof packaging, high-value dataset tests, and adversarial layer validation.

Current date: 2026-06-01 Singapore time.

Organizer-facing trust-proof alignment is now tracked in `docs/FIND_EVIL_TRUST_PROOF_PACKAGE.md`. Treat that file as the submission packaging bridge between this schedule, `docs/ADVERSARIAL_EVALUATION_PLAN.md`, `docs/JUDGE_LAYER_PROOF_CHECKLIST.md`, and `docs/SUBMISSION_CHECKLIST.md`.

## Current Position

Blitz now has three useful PLASO proof runs and one local trust-layer proof suite:

- Case: `BLITZ-RD01-PLASO`
- Session: `/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82`
- Normalized events: `1,329,652`
- Full accounting rows: `1,329,652`
- SQL correlation rows scanned: `1,329,652`
- Findings: `500`
- Validation: passed with `0` issues
- Evidence maturity: `500/500` traceable findings
- Artifact manifest and audit finalization: completed

Post-fix preferred PLASO run:

- Case: `BLITZ-RD01-PLASO`
- Session: `/cases/BLITZ-RD01-PLASO/output/sess-20260601T010722Z-40b51cee`
- Normalized events: `1,329,652`
- Findings: `252`
- Duplicate finding IDs: `0`
- Generic `evt` labels: `0`
- LLM SQL/database narrative leakage: `False`
- Evidence maturity: `252/252` traceable findings

Post-trust-layer PLASO run:

- Case: `BLITZ-RD01-PLASO`
- Session: `/cases/BLITZ-RD01-PLASO/output/sess-20260601T113254Z-327c7a6a`
- Normalized events: `1,329,652`
- Findings: `252`
- New trust artifacts: `evidentiary_weighting`, `contradiction_analysis`, and `finding_provenance`
- E2E check: `passed`
- Post-run checks: `passed`

Local trust-layer proof suite:

- Prompt injection in evidence is sanitized before reasoning.
- Malformed parser output creates warnings and confidence penalties.
- Multi-source agreement receives higher evidentiary weight.
- Cross-source contradictions reduce confidence.
- Finding provenance visualization renders a traceable `flowchart LR` diagram.
- Focused local test result after parser-display and SQLite-checkpoint fixes: `48 passed` on 2026-06-01.

This is strong engineering and dataset-processing proof. It is not final accuracy proof until source permission, exact command, artifact archive, ground truth or analyst expectations, finding review, and selected proof outputs are copied into the final organizer package.

## Priority Order

### Priority 0: Align The Trust Proof Story

This is documentation and proof packaging, not a replacement architecture.

- [x] Merge the two judge-facing trust layers into the all-layer testing plan:
  - Adversarial Evidence Validation: can hostile evidence manipulate the investigator?
  - Evidence-To-Conclusion Verification: can every conclusion prove itself?
- [x] Create organizer-facing trust proof package plan at `docs/FIND_EVIL_TRUST_PROOF_PACKAGE.md`.
- [ ] Cross-check the final demo, accuracy report, dataset docs, agent logs, and proof archive against that package plan.
- [ ] Make every demo claim point to one artifact: report, audit log, evidence maturity trace, validation file, signal integrity file, unknowns file, or agent execution log.
- [ ] Keep the submission story focused on computed trust, not more parsers or more agents.

### Priority 1: Preserve The Completed PLASO Proof Run

- [x] Copy or archive the full session from SIFT:
  - `audit/`
  - `findings/`
  - `reports/`
  - `timelines/`
  - `psort-*.log.gz`
- [x] Capture the exact launcher command or run environment from `/cases/BLITZ-RD01-PLASO/analysis/runs/20260531T202550Z`.
- [x] Capture source evidence SHA256 before and after analysis as explicit values.
- [ ] Preserve `artifact_manifest.json`, `evidence_maturity.json`, `report.html`, `report.json`, `audit/*.ndjson`, and `progress.json`.
- [x] Verify host proof archive SHA256 against SIFT hash file.
- [x] Inspect `audit/progress.json` and `findings/parser_results.json` to explain the pasted `Parser result extraction (0/1)` display.
- [ ] Run or preserve final SIFT quality gates:
  - `python -m pytest -q`
  - `python -m compileall -q app.py blitz_dfir tests`
  - `python -m ruff check app.py blitz_dfir tests`
  - `python -m mypy app.py blitz_dfir tests`
  - `pip-audit -r requirements.txt -r requirements-dev.txt`

### Priority 2: Document Dataset Legitimacy And Accuracy Limits

- [x] Confirm whether `BLITZ-RD01-PLASO` can be named publicly. User confirmed on 2026-06-01 that it can be named as SANS Find Evil hackathon-provided case material.
- [x] Confirm source/license/permission for the processed PLASO. Authorized for hackathon testing/submission as SANS-provided case material; do not redistribute raw evidence unless SANS terms permit.
- [ ] Record whether the PLASO was internally generated from `base-rd-01-cdrive.E01` or obtained as processed evidence.
- [ ] Record original evidence hash and processed PLASO hash.
- [ ] Define ground truth, if available.
- [x] If no formal ground truth exists, write analyst expectations before reviewing findings.
- [ ] Review a representative finding set:
  - top 10 high-confidence findings
  - sample of medium-confidence findings
  - any low-confidence or warning-heavy findings
  - all unique finding categories/stages
- [ ] Record true positives, false positives, unknown/needs-review findings, missed expected artifacts, and unsupported claims.
- [x] Complete preliminary mechanical finding review from extracted artifacts.
- [x] Add code fixes for preliminary finding-review risks: duplicate finding IDs, generic SQL labels, and non-JSON LLM narrative suppression.
- [x] Rerun `BLITZ-RD01-PLASO` after the 2026-06-01 fixes if it will be used for judge-facing accuracy output. R2 session: `/cases/BLITZ-RD01-PLASO/output/sess-20260601T010722Z-40b51cee`.
- [x] Preserve the R2 quality capture on the Windows host with matching SHA256: `Blitz_DFIR_Proof/postfix_session_quality.txt`.
- [x] Add `scripts/blitz_fetch_postfix_proof_archive.ps1` to automate the remaining full R2 proof package archive/copy/verification step.
- [x] Harden the SIFT Ollama run operator flow so the default launcher is supervised, reports periodic status, executes post-run checks, and returns the shell prompt with the analysis exit code.
- [x] Add local trust-layer proof code for evidentiary weighting, evidence contradiction analysis, and finding provenance visualization.
- [x] Add focused adversarial tests for prompt injection, malformed parser output, evidentiary weighting, contradiction penalties, and provenance rendering.
- [x] Rerun `BLITZ-RD01-PLASO` after the trust-layer additions so the real session contains `findings/evidentiary_weighting.json`, `findings/contradiction_analysis.json`, and `reports/finding_provenance.md`. R3 session: `/cases/BLITZ-RD01-PLASO/output/sess-20260601T113254Z-327c7a6a`.
- [x] Fix stale parser progress display after R3 so future completed parser layers show completed counters instead of `(0/1)`.
- [x] Add final SQLite event-store checkpoint after R3 so future proof archives do not depend on live WAL sidecars.
- [x] Archive and copy the R3 proof package to the Windows host before memory-dataset intake: `Blitz_DFIR_Proof/sess-20260601T113254Z-327c7a6a_postfix_proof_full.tar`, size `9,856,256,000` bytes, SHA256 `1A8BB27CADB13DF89D4E29E8F5FECBBCF2E3CBD524D738720E551BA6B85744D8`, verified against the SIFT sidecar.
- [ ] Clean generated SIFT sessions/runs and remote proof tar archives before copying the 17G memory dataset. Use `scripts/sift_clean_generated_for_rerun.sh` and `scripts/sift_clean_remote_proof_archives.sh`; keep `case.yaml`, `processed/case.plaso`, run receipts, failed-run receipts, and the host-verified proof archive.
- [x] Add evidence-first planning architecture locally: optional case objective, investigation plan, evidence triage, report sections, progress/monitor layers, SIFT launcher `CASE_OBJECTIVE`, and focused tests.
- [x] Add truthful monitor/readiness split after the planning refactor: analysis progress, supervised run status, post-run manifest, report readiness, LLM readiness, safety readiness, trust artifacts, audit attribution, and postrun readiness are now reported separately.
- [x] Prepare high-volume stress ladder for 1M/2M/3M/4M/5M normalized-event targets: launcher supports full PLASO export via `PSORT_FILTER=`, normalized cap supports 5M, and the stress script fails if the source produces fewer rows than claimed.
- [ ] Run one evidence-first SIFT proof pass after sync so `findings/case_objective.json`, `findings/investigation_plan.json`, `findings/evidence_triage.json`, and matching Markdown reports exist in a real SIFT session.
- [ ] Run one post-monitor-fix evidence-first SIFT proof pass and capture `run_status.json`, `postrun_manifest.json`, `blitz_status.sh` output, and `blitz_monitor_until_done.sh` completion text.
- [ ] Run the high-volume stress ladder on SIFT after cleaning disk space. Pass criteria: stages reach actual normalized event counts of at least 1M, 2M, 3M, 4M, and 5M, or the script stops with `source_under_target` so no false scale claim is made.
- [ ] Rerun EVTX-focused evidence before the 17G memory test so event-log parsing, reporting, and audit attribution remain freshly verified.
- [ ] Fill `docs/ACCURACY_REPORT.md`.
- [ ] Fill `docs/REAL_CASE_WALKTHROUGH.md` only with evidence-backed claims.

### Priority 3: Add The Memory Dataset Candidate

The user has a pure memory file. This is worth testing because it adds artifact breadth beyond PLASO/timeline evidence.

Memory test goals:

- prove the typed `memory` route works against real memory evidence
- prove Volatility execution is allowlisted and bounded
- prove parser output becomes normalized events
- prove memory coverage/unknowns are recorded
- prove Blitz can handle a second evidence family
- optionally combine memory with PLASO later for stronger correlation/confidence proof

Required intake data:

- [ ] Local or SIFT path to the memory file.
- [ ] File size.
- [ ] SHA256.
- [ ] Source/license/permission.
- [ ] Operating system family if known.
- [ ] Expected profile/symbol notes if known.
- [ ] Acquisition tool if known.
- [ ] Whether this can be named publicly.
- [ ] Whether ground truth or analyst expectations exist.

Suggested manifest shape:

```yaml
case_id: BLITZ-MEMORY-001
evidence_root: evidence
output_root: output
evidence:
  - id: memory-image
    path: memory.raw
    type: MEMORY
    sha256: <SHA256>
    internally_generated: false
    description: Memory image for Blitz typed Volatility route validation.
```

Suggested first command on SIFT:

```bash
python app.py analyze \
  --manifest /cases/BLITZ-MEMORY-001/case.yaml \
  --mode timeline \
  --tool-config /home/sansforensics/src/Blitz_DFIR/config/tools.yaml \
  --tool-timeout 1800
```

Expected Blitz route:

- evidence type `MEMORY`
- typed tool `memory`
- Volatility executable `vol`
- allowlisted plugin `windows.pslist`
- output parser `volatility`
- report/audit/evidence maturity artifacts written under the session output

Risks:

- Volatility may fail if the memory image OS/symbol requirements are not satisfied.
- A memory-only run may produce process inventory but weak correlation because EVTX/PCAP/registry context is absent.
- If the file is very large, timeout or memory pressure may occur; this is still useful if Blitz records warnings and unknowns honestly.

Judge-safe claim if it passes:

> Blitz processed a real memory image through an allowlisted Volatility route and converted bounded memory-process output into normalized, audited, reportable evidence.

Judge-safe claim if it fails safely:

> Blitz attempted memory analysis through the typed Volatility route, recorded the tool failure/degradation, preserved evidence integrity, and reported the limitation instead of fabricating findings.

### Priority 4: Build Minimal Adversarial Layer Suite

Do not try to build every adversarial scenario first. Build the few that prove the riskiest judge-facing trust claims from `docs/FIND_EVIL_TRUST_PROOF_PACKAGE.md`.

- [ ] MCP escape/rejection scenario: generic shell and evidence-write attempts are rejected.
- [x] Prompt injection scenario: hostile evidence text is sanitized and cannot affect reasoning.
- [x] Artifact poisoning scenario: malformed parser output or shifted timestamps creates signal warnings and confidence penalties.
- [x] Confidence scenario: single-source finding scores lower than multi-source finding.
- [x] Correlation contradiction scenario: timestamp or lineage disagreement produces contradiction/penalty.
- [ ] Self-correction scenario: timeout or parser degradation triggers scoped correction and respects retry cap.
- [x] Evidence maturity/provenance scenario: finding trace renders through event, evidence, parser/tool, and audit references where available.
- [x] Unsupported LLM hypothesis scenario: model overclaim remains `INFERRED`, low-confidence, or unsupported.

### Priority 5: Final Demo Package

- [ ] Demo case selected.
- [ ] Demo command captured.
- [ ] Demo artifacts archived.
- [ ] Demo script updated with exact paths.
- [ ] One finding selected for traceability demonstration.
- [ ] One adversarial evidence validation scenario selected for the demo.
- [ ] One evidence-to-conclusion verification trace selected for the demo.
- [ ] One limitation/unknown selected for honesty demonstration.
- [ ] One safety proof selected: spoliation demo or MCP rejection.
- [ ] One self-correction sequence selected; if synthetic/adversarial, label it clearly as layer-validation proof.
- [ ] Agent path selected:
  - OpenClaw/Claude live tool call if available, or
  - direct MCP smoke plus clearly documented agent-access limitation.
- [ ] Organizer proof bundle staged under `Blitz_DFIR_Proof/final_submission/` or an equivalent documented path.

## Recommended Two-Week Schedule

### Days 1-2

- Preserve PLASO artifacts.
- Capture exact command/launcher. Completed for `BLITZ-RD01-PLASO-R1`.
- Inspect parser progress mismatch. Completed; actual progress/parser/audit artifacts show parser result count `1`.
- Run final SIFT quality gates.

### Days 3-4

- Fill dataset documentation.
- Review findings for accuracy report.
- Create real case walkthrough draft.

### Days 5-6

- Run memory dataset test.
- Decide whether memory becomes demo-supporting evidence or engineering validation only.

### Days 7-9

- Build minimal adversarial layer suite. First focused suite completed locally on 2026-06-01.
- Generate judge-facing adversarial evaluation summary. Initial summary exists at `docs/ADVERSARIAL_TEST_RESULTS_20260601.md`; update it again after the SIFT rerun.

### Days 10-11

- Repeat one selected run or document repeatability limitation.
- Finalize accuracy report and repeatability matrix.

### Days 12-14

- Record demo.
- Scrub public repo.
- Verify no private provider artifacts, secrets, evidence files, or raw sensitive data are committed.
- Package final proof story.

## Hard Rule

Do not add random new features during this two-week window unless they directly close a judge proof gap.

Allowed:

- proof artifacts
- test scenarios
- docs
- minor bug fixes discovered during proof review
- artifact preservation scripts

Avoid:

- new UI
- new broad parser integrations
- new dashboards
- new cloud features
- new auth/user systems
- unplanned refactors
