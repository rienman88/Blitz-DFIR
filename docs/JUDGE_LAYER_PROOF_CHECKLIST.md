# Judge Layer Proof Checklist

Purpose: give judges a clear proof map for what each Blitz DFIR layer does, what evidence already exists, and what still must be captured before making final accuracy claims.

This checklist is intentionally conservative. Unit tests and smoke runs prove engineering behavior. They do not, by themselves, prove final incident-response accuracy on real evidence. Final accuracy requires a documented dataset, repeatable commands, before/after evidence hashes, traceable findings, and false-positive / false-negative review.

## Proof Status Legend

- [x] Strong engineering proof exists in this repo and was locally re-verified.
- [~] Implemented and documented, but judge-grade run artifact still needs to be captured or copied into the submission package.
- [ ] Proof gap remains before making a judge-facing claim.

## Current Verification Snapshot

- [x] `python -m pytest -q` passed locally on 2026-05-31.
- [x] `python -m pytest --collect-only -q` collected 128 tests across 32 test files.
- [x] `python -m compileall -q app.py blitz_dfir tests` passed locally on 2026-05-31.
- [x] Spoliation demo passed locally on 2026-05-31: mutation request rejected and the evidence SHA256 stayed unchanged before analysis, after analysis, and after rejected mutation attempt.
- [~] `ruff`, `mypy`, and `pip-audit` are documented as previously passing on SIFT, but they were not locally re-verified in this Windows Python environment because the modules are not installed here.
- [~] Pasted SIFT proof run `sess-20260531T203012Z-bff65d82` is documented: 1,329,652 normalized events, 500 findings, validation passed, full SQL correlation scanned 1,329,652 rows, evidence maturity traced 500/500 findings, evidence hashes preserved, artifact manifest written, and audit finalized.
- [~] `docs/ADVERSARIAL_EVALUATION_PLAN.md` now records the next proof track: every layer must receive either adversarial failure-injection coverage or a documented alternative proof.
- [x] Focused trust-layer suite passed locally on 2026-06-01: 48 tests covering prompt-injection sanitization, malformed parser-output penalties, evidentiary weighting, contradiction confidence reduction, reasoning containment, provenance visualization, parser progress display cleanup, and SQLite event-store checkpointing.
- [~] Post-fix SIFT rerun `sess-20260601T010722Z-40b51cee` resolved duplicate finding IDs, generic `evt` labels, and unsupported SQL/database bounded reasoning leakage.
- [x] Post-trust-layer SIFT rerun `sess-20260601T113254Z-327c7a6a` completed with `findings/evidentiary_weighting.json`, `findings/contradiction_analysis.json`, `reports/finding_provenance.md`, `e2e_ollama_check=passed`, and `postrun_checks=passed`; host archive verification passed with SHA256 `1A8BB27CADB13DF89D4E29E8F5FECBBCF2E3CBD524D738720E551BA6B85744D8`.
- [x] Parser progress display stale counter and SQLite event-store WAL checkpoint issues were fixed after R3 for cleaner future judge-facing runs and proof archives.
- [ ] Final submission still needs dataset source/permission, ground truth or analyst expectations, accuracy scoring, real case walkthrough, repeatability/rerun evidence, and agent execution logs.

## Trust-Layer Overlay

The external recommendation is now merged as a proof overlay, not a new pipeline. Organizer-facing alignment is tracked in `docs/FIND_EVIL_TRUST_PROOF_PACKAGE.md`.

### Layer 1: Adversarial Evidence Validation

Judge question: can hostile evidence manipulate the investigator?

- [x] Existing engineering proof: sanitization tests, parser validation tests, reasoning containment tests, report escaping, MCP boundary tests, spoliation demo.
- [~] Judge-complete proof: local prompt injection, poisoned parser output, and timestamp inconsistency proofs exist; unsafe tool request and evidence mutation still need final preserved proof outputs.
- [ ] Required artifacts: scenario output, `signal_integrity.json`, `validation.json`, `evidence_maturity.json`, report output, audit log, before/after evidence hashes.
- [ ] Demo moment: show one hostile evidence or unsafe request sequence being neutralized, rejected, downgraded, or recorded as a limitation.

### Layer 2: Evidence-To-Conclusion Verification

Judge question: can every conclusion prove itself?

- [x] Existing engineering proof: evidence maturity trace, confidence modifiers, contradiction detection, validation, audit hash chain, conservative reporting language.
- [~] Judge-complete proof: provenance rendering is locally tested and generated in R3; select one R3 finding and trace it from report to normalized event, evidence ID, parser result, typed tool output, and audit entry hash after copying the proof package.
- [ ] Required artifacts: `findings/evidence_maturity.json`, `reports/evidence_maturity.md`, `validation.json`, `unknowns.json`, `coverage.json`, `report.json`, audit log, agent execution log.
- [ ] Demo moment: show one finding, its support chain, confidence modifier, contradiction or unknown status, and why the report does not overclaim.

## Layer Proof Map

| Layer | What it does | Existing proof | Judge-safe claim | Remaining proof work |
| --- | --- | --- | --- | --- |
| Case objective | Records the evidence-first investigation objective, success criteria, constraints, and evidence IDs in scope. | `tests/test_evidence_planning.py`; `tests/test_app.py` verifies `findings/case_objective.json`, report section, and audit event `case_objective_defined`. | Blitz can accept analyst intent without letting intent create findings or override evidence controls. | Preserve `findings/case_objective.json`, `reports/case_objective.md`, and monitor readiness from the next SIFT proof run. |
| Investigation planning | Converts manifest evidence and tool discovery into prioritized artifact families and investigation phases. | `tests/test_evidence_planning.py`; monitor/progress layer added as `investigation_planning`; report artifact `reports/investigation_plan.md`. | Blitz can explain what evidence families should be processed first before broad execution begins. | Preserve `findings/investigation_plan.json`, `reports/investigation_plan.md`, and batch-plan ordering from the next SIFT proof run. |
| Evidence triage | Ranks actual manifest evidence by forensic value, tool status, resource risk, and recovery limitations. | `tests/test_evidence_planning.py`; `tests/test_app.py` verifies `findings/evidence_triage.json`, report section, and audit event `evidence_triage_completed`. | Blitz can show which evidence was prioritized, which routes were blocked, and which evidence requires caution. | Preserve `findings/evidence_triage.json`, `reports/evidence_triage.md`, and monitor readiness from the next SIFT proof run. |
| Evidence sources | Supplies raw or processed case artifacts through a manifest. | Manifest and dataset scaffolds exist; tests cover manifest loading, duplicate IDs, path traversal, schema rejection, hash mismatch, and evidence type routing. | Blitz requires manifest-registered evidence and does not accept arbitrary paths as evidence. | Final dataset source, license/permission, hashes, and ground truth still need to be recorded in `docs/DATASETS.md`. |
| Integrity layer | Loads the manifest, verifies SHA256, resolves evidence IDs, enforces evidence roots, and keeps source evidence read-only. | `tests/test_manifest.py`, `tests/test_integrity.py`, `tests/test_evidence.py`, `tests/test_session.py`, and local spoliation demo. | Blitz can prove evidence hash verification and read-only access inside its execution boundary. | Capture before/after hashes from the final demo run and preserve them in `findings/evidence_maturity.json` plus the demo video. |
| Protocol SIFT case workflow | Provides the SIFT-oriented agent workflow around Blitz. | `docs/PROTOCOL_SIFT_INTEGRATION.md` documents setup and tested SIFT state. Direct MCP smoke is documented. | Blitz is Protocol SIFT-compatible and can be launched in a SIFT case workflow. | Capture one final OpenClaw or Claude Code driven tool call, or explicitly disclose that only direct MCP smoke was demonstrated. |
| Agent orchestrator | Requests the next typed forensic action and explains next steps. | OpenClaw/Ollama compatibility and Claude Code installation notes are documented. Bounded reasoning tests exist. | Bounded LLM reasoning is outside the security boundary and cannot create confirmed findings. | Agent execution logs are still required: framework/version, timestamps, tool calls, model metadata, token usage if available, and link to Blitz session artifacts. |
| Typed MCP server | Exposes typed tools such as `psort`, `pcap`, `events`, `memory`, `strings`, and `yara`; no generic shell tool. | `tests/test_mcp_stdio_server.py`, `tests/test_dispatcher.py`; direct MCP smoke documented in the checklist. | Blitz exposes a typed MCP surface and rejects generic shell-style requests. | Capture the final MCP audit log showing `mcp_server_started`, `tool_request_validated`, and `tool_request_completed`. |
| Controlled execution boundary | Validates schema, evidence ID, allowed tool, compatible evidence type, argument arrays, timeout, and output path. | Dispatcher, sandbox, and adapter tests cover allowlist rejection, unknown evidence rejection, string-command rejection, shell metacharacter handling, timeout handling, and output path escape rejection. | The AI/agent cannot directly run arbitrary subprocesses through Blitz. | Final demo should show one rejected unsafe request or the spoliation demo result. |
| SIFT tooling | Runs forensic utilities such as Plaso/psort, Volatility, Chainsaw, tshark, YARA, and strings. | Tool adapter tests prove safe command construction, metadata, hashes, structured failures, and allowlisting. SIFT tool availability is documented. | Blitz wraps SIFT tools safely; it does not claim to replace or prove the forensic correctness of SIFT tools. | Capture actual tool versions, tool hashes/provenance, and external-tool output paths from the final SIFT run. |
| Batch planning | Converts broad case analysis into ordered artifact-family batches with `max_parallel_tools=1`. | `tests/test_batch_plan.py`; `findings/batch_plan.json` documented as judge evidence. | Blitz breaks broad analysis into bounded, sequential forensic work instead of unbounded all-at-once execution. | Show `findings/batch_plan.json` from the final run and explain skipped/unsupported batches. |
| Tool discovery and evidence inventory | Records tool availability, disabled/missing tools, recommended batch/tool, resource risk, and controls. | `tests/test_inventory.py`; artifacts `tool_discovery.json` and `evidence_inventory.json` are documented. | Blitz records what tools/evidence are available before relying on them. | Include these artifacts from the final run, especially if any tool or artifact is missing. |
| Recovery planner | Records primary and fallback extraction routes, including blocked routes such as non-integrated Velociraptor. | `tests/test_recovery_planner.py`; artifact `findings/recovery_plan.json` documented. | Blitz makes unsupported recovery paths visible instead of allowing the agent to improvise unsafe commands. | Show recovery plan from final run and explain any blocked/unchecked route as a limitation, not a hidden failure. |
| Parser validation and sanitization | Parses tool output, validates compatibility, sanitizes external/derived data, detects malformed rows, bounds fields, and neutralizes prompt injection. | `tests/test_parsers.py`, `tests/test_sanitization.py`, `tests/test_spoliation.py`; local spoliation demo. | Evidence text is treated as data, not instruction, and raw stdout is not sent to the LLM. | Final demo should show parser warnings or explicitly state if no parser degradation occurred. |
| Signal integrity and coverage | Tracks timeouts, truncation, parser degradation, missing artifacts, partial extraction, hash mismatch, retry exhaustion, abnormal density, coverage, and unknown zones. | `tests/test_signal_integrity.py`, `tests/test_unknowns.py`; reports include `signal_integrity.json`, `coverage`, and `unknowns`. | Blitz lowers confidence and records unknown zones instead of pretending full coverage. | Show `findings/signal_integrity.json`, coverage, and `unknowns.json` from final run. |
| Deterministic normalization | Converts parser output into stable normalized events with IDs, timestamps, categories, evidence refs, trust, parser warnings, and stable ordering. | `tests/test_normalization.py`, `tests/test_sqlite_normalization.py`; SQLite-backed large-run normalization is documented. | Same input produces stable normalized events, and RAW/DERIVED/INFERRED categories remain separated. | Final run should include normalized count, export limits, and whether SQLite-backed normalization was used. |
| Full accounting and event store | Preserves complete exported rows in SQLite/accounting while keeping reports bounded. | `tests/test_full_accounting.py`, `tests/test_sqlite_normalization.py`; documented SIFT run had 1,329,652 rows scanned. | Report size can be bounded without silently discarding the full exported accounting record. | Show row alignment: exported CSV lines, `full_accounting.json`, and SQLite row count from the final run. |
| Object inventory | Extracts observed users, process images, PIDs, files, registry keys, hashes, network indicators, unsupported evidence, and evidence with no normalized events. | `tests/test_object_inventory.py`; `findings/object_inventory.json` documented. | Blitz can summarize what entities were observed and what evidence produced no normalized events. | Include object inventory from the final run and use it to explain coverage limits. |
| Correlation engine | Builds deterministic timeline ordering, process lineage, persistence findings, attack-chain stages, confidence modifiers, and contradiction notes. | `tests/test_correlation.py`, `tests/test_sqlite_correlation.py`; SQL correlation scans full normalized store and loads bounded support events. | Findings must be anchored to evidence references, and single-source findings carry a penalty. | Final accuracy review must compare correlated findings against expected attacker behavior or ground truth. |
| Evidentiary weighting | Computes an explicit evidence weight per finding from source trust tier, parser/signal penalties, contradiction penalties, and source diversity. | `tests/adversarial/test_evidence_weighting_and_contradictions.py`; R3 wrote `findings/evidentiary_weighting.json` and `reports/evidentiary_weighting.md`. | Judges can see mathematically why a finding has high, medium, or low evidentiary support. | Copy and preserve the R3 proof package; review a selected finding's evidence weight for the walkthrough. |
| Evidence contradiction analysis | Formalizes cross-source field disagreement and timestamp skew, computes a contradiction score, and reduces impacted finding confidence. | `tests/adversarial/test_evidence_weighting_and_contradictions.py`; R3 wrote `findings/contradiction_analysis.json` and `reports/contradiction_analysis.md`. | Blitz can show that conflicting evidence reduces confidence instead of being ignored. | Copy and preserve the R3 proof package; explain that a zero/low contradiction count is expected for a PLASO-only run. |
| Validation and self-correction | Checks evidence support, confidence thresholds, contradictions, parser integrity, bounded retries, and approved recovery actions. | `tests/test_correction.py`; reports and audit include correction history. | Blitz can downgrade unsupported claims and keep failed correction honest instead of inventing certainty. | Final demo still needs one real or representative self-correction or an honest limitation sequence. |
| Bounded LLM reasoning | Produces bounded explanations and hypotheses from normalized summaries only; output is labeled `INFERRED`. | `tests/test_reasoning.py`; provider-neutral client and metadata recording are documented. | LLM reasoning is explainability, not evidence, and cannot create confirmed findings. | Capture final provider/model/prompt hash/token metadata if reasoning is enabled, or mark reasoning skipped. |
| Reporting | Writes JSON, Markdown, HTML, evidence references, confidence modifiers, coverage, unknowns, validation, correction history, and approved conservative language. | `tests/test_reporting.py`; report artifacts documented. | Reports are evidence-backed and escape malicious evidence-derived content. | Include final `reports/report.html`, `reports/report.json`, and `reports/report.md` in the proof package. |
| Evidence maturity and provenance visualization | Links finding -> normalized event -> evidence ID/raw reference -> parser result -> typed tool output/hash -> audit entry, then renders a judge-readable provenance diagram. | `tests/test_evidence_maturity.py`; R3 wrote `findings/evidence_maturity.json`, `reports/evidence_maturity.md`, and `reports/finding_provenance.md`. | Judges can pick a finding and trace it through the investigation chain where session-produced tool output exists. | Copy and preserve the R3 proof package, then select one finding for the final walkthrough. |
| Audit hardening and session integrity | Writes hash-chained NDJSON audit records, session state, progress, artifact manifest, sanitized paths, and tamper-evident hashes. | `tests/test_audit_log.py`, `tests/test_audit_hardening.py`, `tests/test_session_integrity.py`; local tests prove chain tamper detection. | Blitz audit logs are tamper-evident and traceable, not tamper-proof against a user who can rewrite all local files. | Preserve the final audit log, artifact manifest, and report hashes outside the mutable working directory after the run. |
| Stress and stability reporting | Records timeout status, artifact inventory, accounting totals, validation/signal status, and partial-session detection. | `tests/test_stress_report.py`, `docs/STABILITY_TESTING.md`; stability scripts exist. | Blitz can label partial, timed-out, or interrupted runs as needing review. | Run and preserve the final bounded stability or E2E checker output on SIFT. |
| Private provider harness | Developer-only provider experiments. | Gitignored `local/` path documented as private-only. | Private provider tests are not public judge dependencies and not part of the security boundary. | Do not include private harnesses, keys, provider-specific claims, or private outputs in the public submission. |

## Proofs That Are Already Strong

- [x] Manifest safety and evidence integrity behavior.
- [x] Case objective, investigation planning, and evidence triage engineering behavior.
- [x] Read-only evidence enforcement inside Blitz.
- [x] Typed MCP allowlist and generic shell rejection.
- [x] Safe subprocess argument arrays and bounded output handling.
- [x] Tool adapter metadata, output hashing, provenance warnings, and path escape rejection.
- [x] Parser validation, prompt-injection sanitization, malformed data warnings, and field bounds.
- [x] Signal integrity warnings, confidence penalties, coverage, and unknown-zone handling.
- [x] Deterministic normalization and category separation.
- [x] Correlation logic, lineage traceability, confidence modifiers, and contradiction detection.
- [x] Validation and bounded self-correction rules.
- [x] Report escaping, evidence-backed report fields, and conservative claim language.
- [x] Audit hash-chain creation and tamper detection.
- [x] Evidence maturity traceability artifact.
- [x] Spoliation demo proving rejected mutation through the typed dispatcher and unchanged evidence hash.

## Proofs That Are Not Yet Judge-Complete

- [x] Build the first adversarial evaluation suite from `docs/ADVERSARIAL_EVALUATION_PLAN.md`, covering prompt injection, corrupted parser output, evidentiary weighting, contradiction penalties, and provenance visualization.
- [x] Preserve SIFT/full-run outputs for the new adversarial/provenance artifacts after syncing the latest code. R3 generated them and the host proof archive was SHA256 verified.
- [x] Final candidate real/representative proof run recorded as `BLITZ-RD01-PLASO-R1`.
- [ ] Dataset source, license/permission, ground truth/expectations, and remaining accuracy notes completed in `docs/DATASETS.md`.
- [ ] Ground truth or analyst expectations recorded before scoring.
- [ ] `docs/ACCURACY_REPORT.md` filled with true positives, false positives, false negatives, unsupported claims, hallucination handling, and limitations.
- [x] `docs/REPEATABILITY_MATRIX.md` includes the first `BLITZ-RD01-PLASO` proof run.
- [x] `docs/REPEATABILITY_MATRIX.md` records R1, R2, and R3 repeatability/proof runs.
- [ ] `docs/REAL_CASE_WALKTHROUGH.md` filled from the selected completed run.
- [ ] OpenClaw or Claude Code agent execution logs captured and linked to Blitz MCP/audit artifacts.
- [ ] Final SIFT quality-gate output preserved: `pytest`, `compileall`, `ruff`, `mypy`, and `pip-audit`.
- [ ] Final run artifacts preserved: `batch_plan.json`, `tool_discovery.json`, `evidence_inventory.json`, `recovery_plan.json`, `full_accounting.json`, `event_store.sqlite`, `object_inventory.json`, `validation.json`, `signal_integrity.json`, `unknowns.json`, `evidence_maturity.json`, reports, audit log, progress, session state, and artifact manifest.
- [ ] Final evidence-first planning artifacts preserved: `findings/case_objective.json`, `findings/investigation_plan.json`, `findings/evidence_triage.json`, and matching Markdown reports.
- [ ] Evidence hash before/after final run shown in the video or attached proof artifacts.
- [ ] Any unsupported, skipped, timed-out, degraded, partial, or scoped evidence area documented plainly.

## Recommended Judge Demonstration Scenario

1. Show the architecture diagram and role split: SIFT tools do extraction, Protocol SIFT/OpenClaw or Claude Code provides the agent workflow, and Blitz enforces typed safety, accounting, validation, unknowns, and audit-backed reports.
2. Show the case manifest: evidence IDs, SHA256, evidence root, output root, and type.
3. Run `python app.py analyze --manifest ... --mode timeline --tool-config ... --full-sql-correlation` on the selected real/representative dataset.
4. Show terminal output: normalized events, findings, validation status, audit path, report path, and evidence maturity path.
5. Show `findings/batch_plan.json`: broad request became artifact-family batches.
6. Show `full_accounting.json` and SQLite row count: full exported data is accounted even when reports are bounded.
7. Show one finding in `reports/report.html`.
8. Trace the same finding in `findings/evidence_maturity.json` from finding ID to event ID, evidence ID, parser result, tool output/hash, and audit entry hash.
9. Show `signal_integrity.json` and `unknowns.json`: Blitz documents what it could not safely know.
10. Show before/after evidence hash preservation.
11. Run or show `scripts/blitz_spoliation_demo.py`: mutation request rejected and hash unchanged.
12. Show one validation/correction/unknown sequence. If no real correction triggered, say so and present the honest limitation rather than forcing a fake correction story.

## Adversarial Evaluation Track

After the current final test, the next recommended workstream is the adversarial layer evaluation suite in `docs/ADVERSARIAL_EVALUATION_PLAN.md`.

Rules for that suite:

- [ ] Every architecture layer receives a proof path.
- [ ] Correlation, confidence, reasoning, validation, and self-correction receive adversarial scenarios because they are high-risk DFIR trust layers.
- [ ] Layers where adversarial data is a weak fit receive alternative proof: deterministic invariant tests, boundary rejection tests, traceability proof, repeatability proof, operator logs, artifact hashes, or real/reference dataset proof.
- [ ] Layer proof is classified using four levels: functional/manual, adversarial/failure-injection, representative DFIR dataset, and full investigation scenario.
- [ ] Fixtures avoid real malware by default; AV-detected harmless artifacts such as EICAR-style tests are isolated and never required for the normal judge path.
- [ ] Synthetic adversarial scenarios are labeled as layer-validation evidence, not real-world accuracy evidence.
- [ ] Real/reference dataset results remain required before making final accuracy claims.

## Brutal Audit Conclusion

- [x] The core architecture has real engineering proof.
- [x] The safety boundary is the strongest part of the system: manifest, evidence IDs, typed MCP, allowlist, no generic shell, session-scoped outputs, read-only evidence, audit chain, and spoliation demo.
- [x] The evidence-maturity layer now gives the right judge-facing proof index.
- [~] The large-run SIFT evidence is promising but must be preserved as final artifacts, not only described in the checklist.
- [ ] The biggest remaining risk is not missing code. It is missing final proof packaging: dataset documentation, accuracy report, repeatability, real walkthrough, and agent execution logs.
- [ ] Do not claim final DFIR accuracy until the selected dataset run is completed, scored, and documented.
