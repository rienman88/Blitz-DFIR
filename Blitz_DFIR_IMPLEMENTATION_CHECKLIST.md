# Blitz DFIR Implementation Checklist

Purpose: this is the working checklist before implementation starts. It is the reference point for scope, phase order, safety gates, and acceptance criteria. Update this file as phases move from planned to implemented and verified.

## Current Implementation Log - 2026-06-11 E01 Fallback And Deployment

- [x] Kept full `log2timeline` as the primary E01/DD extraction path; no existing Plaso/psort reporting flow was removed.
- [x] Added automatic `disk_triage` fallback for E01/DD when `log2timeline` cannot produce usable PLASO output.
- [x] Implemented bounded Sleuth Kit fallback script: `scripts/tsk_e01_triage.py`.
- [x] Added typed adapter, parser compatibility, parser, MCP registry, allowlist, accounting mapping, and recovery-plan candidate for `disk_triage`.
- [x] Updated diagnostics/status/runner scripts to show `disk_triage`, `fls`, and `mmls` activity.
- [x] Updated README with Volatility symbols, external evidence/no-copy runs, collated outputs, and E01 fallback behavior.
- [x] Added tests for disk triage adapter/parser and verified focused pipeline-adjacent tests.
- [x] Built SIFT deploy zip: `Blitz_DFIR_Proof/blitz_dfir_deploy_20260611.zip`.
- [x] Verified deploy zip SHA256: `8AF7913A465ECF9B1CB61F03623DB7814D3DC205A589BE38D77386F231FE2C4C`.
- [x] Reviewed the Rocba combined run result and confirmed `disk_triage` worked but was coverage-limited by the old 200,000-entry cap.
- [x] Reworked `disk_triage` output to write a small summary JSON plus streamed JSONL entries, avoiding multi-million-entry Python memory retention.
- [x] Added SQLite-backed batch normalization for streamed `disk_triage` rows while preserving non-streamed parser outputs such as Volatility memory rows in the same event store.
- [x] Raised the default disk-triage cap to 3,000,000 entries and made `DISK_TRIAGE_TRUNCATED` explicit when the fallback reaches its configured limit.
- [x] Verified local quality gates after streamed disk-triage patch: `python -m compileall -q app.py blitz_dfir tests scripts\tsk_e01_triage.py`, focused pytest suite, and full `python -m pytest -q` passed.
- [x] Rebuilt SIFT deploy zip after streamed disk-triage patch: `Blitz_DFIR_Proof/blitz_dfir_deploy_20260611.zip`.
- [x] Recorded streamed disk-triage deploy SHA256 in `Blitz_DFIR_Proof/SIFT_DEPLOY_20260611.md` outside the zip to avoid a self-changing package hash.
- [ ] Deploy updated package to SIFT.
- [ ] Run no-LLM combined Rocba memory plus E01 test and verify `disk_triage` streams beyond 200,000 without dropping memory events.
- [ ] If no-LLM combined run completes, run LLM-enabled combined test and import results to Windows host for review.
- [ ] After the interrupted SIFT run, collect latest status using `CASE=BLITZ-ROCBA-MEMORY-E01 bash scripts/blitz_status.sh`, preserve the selected session path, and inspect `audit/session_state.json`, `audit/progress.json`, `findings/tool_results.json`, `findings/parser_results.json`, and `audit/audit.ndjson` before deciding whether to resume or clean-rerun.
- [x] Reviewed interrupted SIFT status: core extraction, parsing, SQLite normalization, object inventory, full accounting, SQL correlation, validation, unknowns, LLM verification, and report generation completed; interruption occurred late during evidence maturity traceability at about 97.1% overall.
- [x] Added `windows-light` artifact profile for lightweight Windows coverage through Plaso: `winevtx`, `prefetch`, `lnk`, `text/setupapi`, `sqlite/windows_timeline`, `esedb/srum`, `winreg/amcache`, `winreg/bam`, `winreg/windows_usb_devices`, and `winreg/windows_usbstor_devices`.
- [x] Kept `mft` and `usnjrnl` excluded from the default profile because they are high-volume and should remain optional deep-run artifacts.
- [x] Wired `windows-light` into batch planning, runtime tool params, CLI, E01/mixed/external SIFT runners, coverage labels, README, and tests.
- [x] Validated `windows-light` locally: compileall passed, focused tests passed, edited SIFT runners passed `bash -n`, and full `python -m pytest -q` passed.
- [x] Rebuilt SIFT deploy zip for 2026-06-12: `Blitz_DFIR_Proof/blitz_dfir_deploy_20260612.zip`.
- [x] Recorded 2026-06-12 deploy SHA256 in `Blitz_DFIR_Proof/SIFT_DEPLOY_20260612.md` outside the zip to avoid a self-changing package hash.
- [x] Reviewed 2026-06-12 no-LLM Rocba memory+E01 run: session `sess-20260612T014428Z-243ae27d` reached `status=COMPLETED`, `phase=analysis_completed`, 1,124,391 normalized rows, 500 findings, 7/7 typed tools, 7/7 parser results, completed evidence maturity, collated outputs, and artifact manifest.
- [x] Noted no-LLM wrapper caveat: outer `run_status.json` remained `RUNNING`/`postrun=UNKNOWN` because the terminal closed before supervised launcher finalization; session audit/progress/artifacts are complete.
- [x] Raised SQLite correlation export capacity from the old 500-finding operational default to 25,000 findings and 50,000 support events by default, with bounded environment overrides up to 100,000 findings and 250,000 support events.
- [x] Wired SQL correlation capacity knobs through the memory, E01, memory+E01, and external-evidence SIFT runners so users/judges can raise or lower correlation output without code edits.
- [x] Updated `scripts/blitz_status.sh` to report `COMPLETED_FROM_SESSION_STATE` when progress/session artifacts completed but the launcher `run_status.json` was left stale by terminal interruption.
- [x] Added validation issue summaries to `scripts/blitz_status.sh` so `passed=False issues=N` now shows severity, issue type, message, and linked finding/event IDs.
- [x] Updated README with detached `nohup` run guidance, SQL correlation capacity controls, stale launcher interpretation, and validation-flow explanation.
- [x] Added README artifact purpose map for the judge-facing report, findings, audit, validation, coverage, SQLite, parser, and tool-result documents.
- [x] Built refreshed SIFT deploy zip for the clean LLM test: `Blitz_DFIR_Proof/blitz_dfir_deploy_20260613_v2.zip`.
- [x] Recorded 2026-06-13 deploy SHA256 `D03F4EC33A9B653B85558EF54193A31106F2BF640E0518FE775DAFCFBF480732` in `Blitz_DFIR_Proof/SIFT_DEPLOY_20260613.md`.
- [x] Fixed runtime LLM provider failure handling after the SIFT Ollama timeout: `ReasoningProviderError` now records `reasoning_provider_failed`, marks LLM verification `not_run`, and continues deterministic reporting, evidence maturity, agent trace, collated outputs, and artifact hashes.
- [x] Added regression coverage proving an enabled but unavailable LLM provider no longer aborts `app.py analyze`.
- [x] Hardened SIFT LLM reliability for the required hackathon agent run: Ollama runners now time `/api/tags`, `/api/generate`, and `/v1/chat/completions`, start a lightweight keep-alive loop during long forensic processing, pass `LLM_TIMEOUT_SECONDS`, `LLM_MAX_TOKENS`, and JSON response-mode flags into the actual Blitz process, and log these values for post-run diagnosis.
- [x] Fixed the normalization-to-SQL-correlation memory regression: full SQL mode now scans the complete SQLite event store while bounding only the Python in-memory analysis/report window through `BLITZ_SQLITE_ANALYSIS_EVENT_MEMORY_LIMIT` defaulting to 50,000 on SIFT runners.
- [ ] Deploy the refreshed 2026-06-13 package to SIFT and run a clean LLM-enabled combined Rocba memory+E01 test with detached `nohup`/log monitoring so terminal closure does not stop the analysis.
- [ ] After the LLM run, import the completed session artifacts to Windows and verify `findings/llm_report_verification.json`, `reports/report.json -> inferred_analyst_reasoning`, validation issue summary, artifact manifest hashes, and overall/collated documents.

## 0. Source Review And Authority

- [x] Read `One Source of Truth.md`.
- [x] Read and extracted `Blitz_DFIR_README_v1.docx`.
- [x] Read and extracted `Blitz_DFIR_SSOT_v2.1.docx`.
- [x] Scanned and extracted `Blitz_DFIR_SSOT_v2.docx`.
- [x] Compared `Blitz_DFIR_SSOT_v2.docx` against `Blitz_DFIR_SSOT_v2.1.docx`.
- [x] Confirmed `Blitz_DFIR_SSOT_v2.docx` and `Blitz_DFIR_SSOT_v2.1.docx` are identical by hash and extracted text, so there are no v2.0-only missing requirements to merge.
- [x] Checked the Find Evil Devpost overview and rules for hackathon-specific requirements.
- [x] Confirmed this folder currently contains documentation only, not an existing app/package tree.
- [x] Treat `Blitz_DFIR_SSOT_v2.1.docx` as authoritative when it conflicts with earlier drafts, notes, or discussions.
- [x] Treat `Blitz_DFIR_README_v1.docx` as secondary support for capability comparison, demo behavior, and acceptance checks.
- [x] Treat `One Source of Truth.md` as the cleaned current authoritative SSOT after this update.
- [x] Treat Devpost requirements as submission gates that the architecture must satisfy.

Source hashes recorded during review:

| Source | SHA256 | Note |
| --- | --- | --- |
| `One Source of Truth.md` | `507087A0C6FA0074A5B506EA948817FA7B30A8C1DFDA4B34613AED75B3DC4719` | Updated to current authoritative SSOT and verified with PowerShell. |
| `Blitz_DFIR_README_v1.docx` | `6C14BE006B2EC875F6D0FEE822D37FCAE8D4F5775BDBEB46673D31119FE06D3D` | Verified with PowerShell and Python extraction. |
| `Blitz_DFIR_SSOT_v2.docx` | `36D94975147B299309276EA714EC567AA64986BFD0E1CC76D376F817086D4562` | Identical to v2.1 by hash and extracted text. |
| `Blitz_DFIR_SSOT_v2.1.docx` | `36D94975147B299309276EA714EC567AA64986BFD0E1CC76D376F817086D4562` | Recorded via Python extraction; PowerShell hash read was blocked by an external file lock. |
| `https://findevil.devpost.com/` and `/rules` | N/A | Hackathon requirements source: Protocol SIFT, SIFT Workstation, submission artifacts, judging criteria. |

## 1. Pre-Implementation Approval Gate

- [x] Confirm `One Source of Truth.md` has been updated into the current authoritative SSOT.
- [x] Confirm `Blitz_DFIR_SSOT_v2.docx` and `Blitz_DFIR_SSOT_v2.1.docx` are identical, with no v2.0-only requirements missing.
- [x] Confirm implementation starts from the SSOT v2.1 architecture, not from earlier draft structure.
- [x] Confirm the first implementation target is Phase 1 foundation only unless explicitly expanded.
- [x] Confirm no existing working feature is being removed. Current folder has no code features to remove.
- [x] Confirm target platform remains SANS SIFT Workstation with Python 3.11, venv, and uv or pip-tools.
- [x] Confirm package/root folder name: `blitz_dfir/`.
- [x] Confirm CLI MVP command: `python app.py analyze --manifest case.yaml --mode timeline`.
- [x] Confirm initial report formats: HTML, Markdown, and JSON findings.
- [x] Confirm Protocol SIFT-compatible positioning must be documented from the start.
- [x] Confirm the primary hackathon architecture pattern is Custom MCP Server plus Protocol SIFT-compatible agent integration.
- [x] Confirm judge-facing agent path: OpenClaw primary, with Claude Code compatibility documented as secondary.
- [x] Confirm PCAP handling scope: implement bounded MVP PCAP triage now, `tshark` first and optional Zeek if available on SIFT.
- [x] Confirm provider strategy: provider-agnostic adapter; public repo remains provider-neutral.
- [x] Confirm actual `.env` files must not be committed; use `.env.example` and `.gitignore` instead.
- [x] Confirm private provider testing is not the public submission path; public code and docs stay provider-neutral.

## 2. Hackathon Alignment Gate

The Find Evil submission is not only a local DFIR tool. It must improve how Protocol SIFT processes case data and must demonstrate autonomous execution, accuracy validation, evidence integrity, and traceability.

- [ ] Project runs on or integrates with the SANS SIFT Workstation Linux terminal environment.
- [ ] Project extends Protocol SIFT's autonomous incident response capability.
- [ ] Project uses OpenClaw as the primary judge-facing agentic execution path.
- [ ] Project documents Claude Code compatibility as a secondary Protocol SIFT-oriented path.
- [ ] Project architecture pattern is clearly declared in docs and diagram.
- [x] Preferred pattern for Blitz DFIR is Custom MCP Server with structured, type-safe functions.
- [ ] Do not rely on generic `execute_shell_cmd` for judge-facing analysis.
- [ ] MCP server exposes structured functions instead of destructive shell primitives.
- [ ] MCP server handles raw tool output natively and parses before returning to the LLM.
- [ ] Protocol SIFT integration is real and testable, not only a diagram claim.
- [ ] README includes Protocol SIFT installation assumptions and integration steps.
- [ ] README includes how to register or launch the Blitz MCP server with the agent framework.
- [ ] README includes SIFT Workstation setup and local run instructions for judges.
- [ ] Document compatibility with the official Protocol SIFT install layout: `~/.claude/CLAUDE.md`, `~/.claude/settings.json`, `~/.claude/settings.local.json`, `~/.claude/skills/`, case templates, and analysis scripts.
- [ ] Do not overwrite Protocol SIFT global files without backup instructions.
- [ ] Do not broaden Protocol SIFT write permissions into evidence directories.
- [ ] Blitz must enforce its own allowlist and evidence protections even if Protocol SIFT settings already include guardrails.
- [ ] Document whether Blitz is installed as a case-local MCP server, a companion server, or an extension to the Protocol SIFT agent workflow.
- [ ] Document how judges launch OpenClaw from the case directory and connect it to Blitz.
- [ ] Document how a private OpenAI-compatible provider can be configured for local testing.
- [ ] Document why the LLM provider is not the agent framework.
- [ ] Document that raw evidence and raw tool output are never sent to any cloud LLM provider.
- [ ] Document that the public repo must not depend on any private provider subscription or hardcoded key.
- [ ] Document that gitignored local/private provider harnesses are for developer testing only and are excluded from judge setup.
- [ ] Provide a smoke test proving Protocol SIFT or the selected agent can call Blitz typed tools.
- [ ] Provide a demo command that runs on SIFT or a documented SIFT-equivalent test environment.
- [ ] Document any gap between local Windows development and SIFT Linux execution.
- [ ] Document the novel contribution created for the hackathon.
- [ ] Confirm the work is substantially new for the hackathon submission.
- [ ] Use only authorized third-party SDKs, APIs, datasets, and open-source licenses.
- [ ] Repository license is MIT or Apache 2.0.
- [ ] Submission materials are in English.

## 2A. Devpost Elimination Gate - Required Eight Components

Source verified from the public Devpost challenge page on 2026-05-24. Treat this as a hard gate: missing any one component means elimination.

- [ ] 1. Public GitHub repository exists, is public, and contains only allowed source/materials.
- [x] 1. Repository has top-level open-source license file.
- [ ] 1. Confirm license is acceptable for final submission: MIT or Apache 2.0.
- [ ] 2. Demo video is recorded and is 5 minutes max.
- [ ] 2. Demo video shows live terminal execution on SIFT or clearly documented SIFT-equivalent environment.
- [ ] 2. Demo video uses real case data, not fake smoke files or synthetic-only data.
- [ ] 2. Demo video shows at least one self-correction sequence.
- [x] 3. Architecture diagram exists in `docs/ARCHITECTURE.md`.
- [x] 3. Architecture diagram explicitly names the supported pattern: Custom MCP Server with Protocol SIFT-compatible typed tool boundary.
- [x] 3. Architecture diagram shows agent, Protocol SIFT/OpenClaw or Claude Code path, Blitz MCP server, SIFT tools, evidence sources, output pipeline, and reports.
- [x] 3. Architecture diagram distinguishes architectural guardrails from prompt-based guardrails.
- [x] 3. Architecture diagram identifies where evidence integrity is enforced.
- [x] 3. Architecture diagram explicitly shows the Agent Orchestrator as a separate layer outside the Blitz security boundary.
- [x] 3. Architecture diagram and flow place deterministic validation and bounded self-correction before bounded LLM reasoning.
- [x] 3. Architecture documentation includes a Who Does What table showing which layers are AI, Blitz, Protocol SIFT, SIFT tools, and private provider testing.
- [ ] 4. Written Devpost project story exists with What it does, How it was built, Challenges, What was learned, and What's next.
- [ ] 4. Project story explains autonomous execution design decisions and tradeoffs.
- [x] 5. Dataset documentation file exists at `docs/DATASETS.md`.
- [ ] 5. Dataset documentation identifies each tested dataset, source/license, artifact types, hashes where practical, and what Blitz found.
- [ ] 5. Dataset documentation includes reproducibility instructions.
- [ ] 6. Accuracy report exists.
- [ ] 6. Accuracy report includes false positives, missed artifacts, hallucinated claims, validation results, and known limitations.
- [ ] 6. Accuracy report includes evidence integrity and spoliation testing.
- [ ] 6. Accuracy report documents what happens when a model ignores read-only rules.
- [x] 7. Try-it-out instructions exist in README and `docs/PROTOCOL_SIFT_INTEGRATION.md`.
- [ ] 7. Try-it-out instructions let judges run locally on downloadable SIFT Workstation.
- [ ] 7. Try-it-out instructions document required tools/dependencies and exact setup commands.
- [ ] 8. Agent execution logs exist.
- [ ] 8. Agent execution logs show full tool execution sequence with timestamps.
- [ ] 8. Agent execution logs show agent communication and token usage for the judge-facing agent run.
- [ ] 8. Execution logs allow every finding to be traced back to specific tool execution.
- [ ] 8. If persistent/self-correction loop is shown, logs include iteration-over-iteration traces and hard max-iteration cap.

Current elimination blockers before submission:

- [x] RESOLVED: at least one large real case proof run completed: `BLITZ-RD01-PLASO-R1`.
- [x] RESOLVED: duplicate-label-reasoning fixes were rerun in `BLITZ-RD01-PLASO-R2`.
- [ ] BLOCKER: the selected PLASO case still needs a post-trust-layer rerun so final judge artifacts include evidentiary weighting, evidence contradiction analysis, and finding provenance visualization.
- [ ] BLOCKER: full-capacity accuracy testing has not passed. Do not treat partial smoke tests, one-off parser tests, or manually interrupted runs as accuracy evidence for submission.
- [ ] BLOCKER: demo video has not been recorded.
- [ ] BLOCKER: live judge-facing agent path is not yet proven through OpenClaw or Claude Code.
- [x] RESOLVED: required architecture diagram is written in `docs/ARCHITECTURE.md`.
- [x] RESOLVED: initial dataset documentation exists in `docs/DATASETS.md`.
- [ ] BLOCKER: dataset documentation still needs final ground truth or analyst-review scoring.
- [ ] BLOCKER: accuracy report and spoliation test report are not complete.
- [ ] BLOCKER: public GitHub scrub and push have not been completed.
- [ ] BLOCKER: agent execution logs with token usage for judge-facing run have not been produced.

## 2B. Judging Criteria Evidence Map

Judges score proof, not intent. Each criterion must have a concrete artifact.

## 2B-0. Trust Proof Strategy

This merges the adversarial evidence validation and evidence-to-conclusion verification recommendation into the existing all-layer test plan. It does not replace the current Blitz architecture.

- [x] Decide that the two trust layers are proof overlays, not a new pipeline.
- [x] Create organizer-facing trust proof package plan: `docs/FIND_EVIL_TRUST_PROOF_PACKAGE.md`.
- [x] Align `docs/ADVERSARIAL_EVALUATION_PLAN.md` with the two trust questions:
  - can hostile evidence manipulate the investigator?
  - can every conclusion prove itself?
- [x] Align `docs/JUDGE_LAYER_PROOF_CHECKLIST.md` with the trust-layer overlay.
- [x] Align `docs/SUBMISSION_CHECKLIST.md` with organizer-facing proof artifacts.
- [x] Align `docs/DEMO_SCRIPT.md` with an adversarial evidence segment and a finding trace segment.
- [x] Implement or preserve `ADV-EVID-PROMPT-001` proof. Local proof: `tests/adversarial/test_llm_red_team_inputs.py`.
- [x] Implement or preserve `ADV-EVID-POISON-001` proof. Local proof: `tests/adversarial/test_llm_red_team_inputs.py`.
- [ ] Implement or preserve `ADV-MCP-ESCAPE-001` proof.
- [x] Implement or preserve `ADV-CONC-PROVENANCE-001` proof. Local proof: `tests/test_evidence_maturity.py`; generated run artifact: `reports/finding_provenance.md`.
- [x] Implement or preserve `ADV-CONC-CONTRADICTION-001` proof. Local proof: `tests/adversarial/test_evidence_weighting_and_contradictions.py`.
- [x] Implement or preserve `ADV-CONC-LLM-001` proof. Local proof: `tests/test_reasoning.py` plus R2 containment review.
- [x] Add evidentiary weighting layer that computes per-finding evidence weight from source trust, warnings, contradictions, and source diversity.
- [x] Add evidence contradiction analysis layer that records contradiction impact and confidence reduction.
- [x] Add finding provenance visualization that renders judge-readable trace diagrams.
- [x] Focused trust-layer local verification passed on 2026-06-01: `44 passed`.
- [ ] Preserve SIFT artifacts for the new trust layers after syncing and rerunning the selected PLASO case.
- [ ] Copy selected trust proof outputs into the final organizer proof bundle.
- [ ] Reference selected trust proof paths in the demo script before recording.

## 2B-1. Full Dataset Credibility Gate

This is a real-world DFIR validation requirement, not a normal hackathon shortcut. Unit tests and smoke tests prove that layers are wired correctly. They do not prove investigative credibility. Credibility requires complete evidence-dataset execution after the core layers are finished enough to process, validate, correlate, correct, report, and audit the run end to end.

Reference model: NIST CFTT documents forensic tool testing around test procedures, test criteria, test sets, and public testing reports. Blitz should follow the same spirit: defined datasets, expected results, repeatable commands, observed failures, and documented limitations.

- [ ] Complete the core layers before treating full dataset results as final: evidence manifest, hashing, read-only posture, typed tool execution, parser validation, normalization, correlation, bounded correction, reporting, and audit chain.
- [ ] Run full-capacity dataset tests after layer completion, not only partial artifact tests.
- [ ] Record every full dataset command, tool version, timeout, failure mode, retry, and session output path.
- [ ] Capture known ground truth or analyst expectations before scoring accuracy.
- [ ] Document true positives, false positives, missed artifacts, hallucinated or unsupported claims, and unknown zones.
- [ ] Prove evidence hashes remain unchanged before and after the complete run.
- [ ] Treat any parser timeout, empty normalized event set, unsupported artifact type, or manual interruption as a finding that must be fixed or explicitly documented before submission.
- [ ] Do not claim broad DFIR coverage unless representative datasets for those artifact types have completed end-to-end testing.

- [ ] Autonomous Execution Quality: produce a live agent run where the agent chooses next steps, handles a failure or degraded parser/tool output, and triggers bounded self-correction without manual intervention.
- [x] Autonomous Execution Quality: deterministic bounded correction engine exists with hard caps (`MAX_RETRIES = 2`, `MAX_CORRECTIONS = 2`, `MAX_PERSISTENT_ITERATIONS = 3`).
- [ ] Autonomous Execution Quality: judge-facing OpenClaw/Claude run must show at least one real self-correction sequence in logs and demo.
- [ ] IR Accuracy: test against known-good or well-documented case data and record true positives, false positives, missed artifacts, and hallucinated/inferred claims.
- [x] IR Accuracy: reports distinguish RAW/DERIVED/INFERRED evidence categories and label LLM reasoning as `INFERRED`.
- [x] IR Accuracy: fenced/prose-wrapped JSON recovery prevents valid model output from being discarded as non-JSON.
- [ ] IR Accuracy: accuracy report must cite specific evidence references for every claim and identify unknown zones.
- [ ] Breadth and Depth: pick a focused first-depth target for real data testing; current recommendation is one small PCAP first, then EVTX, then memory/disk only after gates pass.
- [x] Breadth and Depth: MVP supports EVTX, PCAP, memory, PLASO/timeline, strings, YARA, and disk-to-timeline routing through typed tools.
- [ ] Breadth and Depth: do not claim broad forensic coverage until each artifact type has a real or representative dataset run.
- [x] Constraint Implementation: architectural guardrails exist through manifest-registered evidence IDs, typed MCP tools, allowlists, argument-array subprocesses, session-scoped outputs, and read-only evidence posture.
- [ ] Constraint Implementation: bypass tests must be documented, including model attempts to request generic shell, evidence mutation, or non-allowlisted tools.
- [ ] Constraint Implementation: spoliation test must prove original evidence hashes remain unchanged after adversarial/prompt-injection instructions.
- [x] Audit Trail Quality: audit chain is hash chained and records manifest/evidence/tool/parser/normalization/correlation/validation/report/completion lifecycle events.
- [ ] Audit Trail Quality: report must explicitly map each finding to event IDs, raw references, parser, source tool, and the exact tool execution/audit event that produced it.
- [ ] Audit Trail Quality: agent execution logs must include timestamps and token usage for the agent run submitted to judges.
- [x] Usability and Documentation: README now includes analyze command, output/report locations, and architecture doc pointer.
- [ ] Usability and Documentation: README must still include complete SIFT setup, Protocol SIFT/OpenClaw or Claude Code path, dependencies, case manifest, MCP registration, and troubleshooting.
- [ ] Usability and Documentation: docs must explain how to disable/uninstall Blitz without damaging Protocol SIFT global files.

Required project demonstrations:

- [ ] Self-correction: agent detects and resolves errors or inconsistencies without human intervention.
- [ ] Accuracy validation: findings trace to specific artifacts, files, offsets, or log entries.
- [ ] Analytical reasoning: output is a structured investigative narrative, not only a raw execution log.
- [ ] Autonomous sequencing is bounded: the agent may recommend or request approved typed actions, but dispatcher, schemas, allowlists, and validation gates decide what executes.
- [ ] Evidence integrity: architecture prevents original evidence modification through enforcement, not just prompts.
- [x] Constraint implementation: diagram distinguishes architectural guardrails from prompt guardrails.
- [ ] Constraint implementation: report must also distinguish architectural guardrails from prompt guardrails.
- [ ] Audit trail: every finding can be traced to the exact tool execution that produced supporting evidence.
- [ ] Usability: another practitioner can install, run, and build on the project.

Required submission artifacts:

- [ ] Public GitHub repository.
- [ ] MIT or Apache 2.0 license visible at repo top level.
- [ ] README with setup, SIFT/Protocol SIFT integration, dependencies, and run instructions.
- [ ] Demo video, 5 minutes max target, with live terminal execution and audio narration.
- [ ] Demo video shows real case data, not slides or marketing-only content.
- [ ] Demo video shows at least one self-correction sequence.
- [x] Architecture diagram showing agent, Protocol SIFT, Blitz MCP server, SIFT tools, evidence sources, security boundaries, and output pipeline.
- [ ] Written Devpost project description: what it does, how it was built, challenges, what was learned, and what is next.
- [ ] Dataset documentation: tested data, source of data, what the agent found, and reproducibility notes.
- [ ] Accuracy report: false positives, missed artifacts, hallucinated claims, and validation results.
- [ ] Accuracy report includes evidence integrity approach and spoliation testing.
- [ ] Accuracy report states what happens if the model ignores read-only rules.
- [ ] Try-it-out instructions: live deployment URL or step-by-step local SIFT instructions.
- [ ] Agent execution logs: structured logs with timestamps for tool execution and agent communication.
- [ ] Single-agent logs include tool execution timestamps and token usage.
- [ ] Persistent loop logs include iteration-over-iteration traces if persistent learning loop is used.
- [ ] Multi-agent logs include agent-to-agent messages only if a multi-agent approach is used.

Judging criteria coverage:

- [ ] Autonomous execution quality: next-step reasoning, failure handling, and real-time self-correction.
- [ ] IR accuracy: correct findings, hallucinations caught, confirmed findings distinguished from inferences.
- [ ] Breadth and depth: depth on high-value evidence types before shallow broad support.
- [ ] Constraint implementation: architectural controls are enforced and tested for bypass.
- [ ] Audit trail quality: findings are traceable to specific tool executions.
- [ ] Usability and documentation: another practitioner can deploy and extend the system.
- [ ] Tie-breaker priority: autonomous execution quality receives extra attention.

## 2C. Seven-Component Forensic Agent Gap Audit

This section maps the plain-language forensic agent requirements to the current implementation. Treat unchecked items here as priority gaps before public submission.

1. Orchestrator

- [x] Deterministic pipeline orchestrator exists in `blitz_dfir/pipeline/analyze.py`.
- [x] Orchestrator routes evidence by manifest type to typed tools and direct processed parsers.
- [x] Tool failures are converted to warnings and audit events instead of crashing the whole case.
- [ ] Missing: live judge-facing agent orchestration through OpenClaw or Claude Code is not yet proven.
- [ ] Missing: autonomous agent must choose follow-up typed tool calls in a real case, not only deterministic CLI routing.

2. Evidence-Aware Memory / Chain Of Custody

- [x] Manifest verifies evidence hashes before analysis.
- [x] Audit log is hash chained and records case/session/tool/parser/report lifecycle events.
- [x] Outputs are session scoped under the case output root.
- [ ] Missing: formal chain-of-custody document/export is not yet written.
- [ ] Missing: report must map every finding to exact tool execution/audit event, not only event IDs.
- [ ] Missing: case-level provenance ledger for copied/processed external evidence is not complete.

3. Dynamic Tool Selection

- [x] Static deterministic evidence-type routing exists for EVTX, PCAP, MEMORY, PLASO, CSV, JSON, and raw disk/timeline-capable artifacts.
- [x] MCP exposes typed tools instead of shell.
- [ ] Missing: agent-driven dynamic mid-investigation tool choice must be demonstrated through MCP.
- [ ] Missing: follow-up typed calls based on findings, such as string hit -> yara or process -> memory plugin, are not yet implemented as a proven agent loop.

4. Multi-Source Correlation

- [x] Normalized events feed timeline stitching, process lineage, persistence detection, contradiction detection, and attack-stage inference.
- [x] Coverage and unknown-zone reporting exist.
- [ ] Missing: real multi-source dataset run has not passed yet.
- [ ] Missing: cross-source correlation must be demonstrated with at least two evidence types from the same case.
- [ ] Missing: no validated browser/email/registry-depth parser path is proven yet beyond broad routing and PLASO-derived events.

5. Structured Reporting

- [x] JSON, Markdown, and HTML reports are generated.
- [x] Reports include findings, timeline, coverage, unknown zones, validation, self-correction, credibility, and inferred reasoning sections.
- [ ] Missing: legal-quality narrative is not complete enough for a judge/jury/non-technical reader.
- [ ] Missing: accuracy report, spoliation report, dataset documentation, demo script, and judge Q&A are still incomplete.
- [ ] Missing: report needs stronger claim language controls: confirmed vs inferred vs unknown must be visible in every major section.

6. Read-Only Evidence Integrity

- [x] Architecture uses manifest-registered evidence IDs and session-scoped outputs.
- [x] Tool adapter output path escape checks are implemented.
- [x] Evidence hash unchanged checks were manually verified in smoke tests.
- [ ] Missing: OS-level read-only mount/write-blocker instructions are not complete for raw evidence.
- [ ] Missing: automated spoliation/bypass test is not implemented and documented.
- [ ] Missing: SIFT runbook must prove Blitz writes only to output/analysis/reports and never evidence/processed directories.

7. Self-Correcting Loop

- [x] Bounded correction trigger/history logic exists with hard caps.
- [x] Correction history is included in audit/report payloads.
- [x] Large PLASO timeout/degradation produced a real correction requirement and the checklist records the fix.
- [ ] Missing: correction currently records planned remediation more than it performs real scoped reruns.
- [ ] Missing: demo must show at least one actual self-correction sequence with before/after improvement.
- [ ] Missing: agent execution logs must show iteration-over-iteration traces and token usage for the judge-facing run.

Blunt priority order from this audit:

- [ ] P0: get one real dataset run to produce nonzero normalized events and a report.
- [ ] P0: prove live OpenClaw or Claude Code can call Blitz typed tools through MCP.
- [ ] P0: produce agent execution logs with timestamps and token usage.
- [ ] P1: implement and document spoliation/bypass tests.
- [ ] P1: strengthen report traceability from finding -> event -> parser -> tool result -> audit event.
- [ ] P1: write the submission documents: accuracy report, dataset docs, demo script, judge Q&A, spoliation testing.

## 3. Non-Negotiable Architecture Rules

- [ ] Typed MCP execution is required for tool access.
- [ ] Evidence manifest is required before any analysis starts.
- [ ] No arbitrary shell execution.
- [ ] Every subprocess call uses argument arrays and `shell=False`.
- [ ] No dynamic AI-generated scripts.
- [ ] No dynamic AI-generated command chains.
- [ ] No evidence mutation.
- [ ] No writes to evidence paths; evidence access is `rb` or OS-level read-only only.
- [ ] No auto-remediation or autonomous system action.
- [ ] No self-modifying logic.
- [ ] No unbounded retries.
- [ ] `MAX_RETRIES = 2`.
- [ ] `MAX_CORRECTIONS = 2`.
- [ ] No raw tool stdout, CSV, JSON, memory strings, or raw dumps are sent directly to the LLM.
- [ ] LLM never controls execution flow.
- [ ] LLM never performs parsing, normalization, evidence storage, correlation truth, or tool execution.
- [ ] No absolute truth language in reports.
- [ ] No silent evidence truncation; every truncation creates an audit warning.
- [ ] Every finding carries evidence references and confidence modifiers.
- [ ] RAW, DERIVED, and INFERRED evidence categories stay separate.
- [ ] Trust is computed, not assumed.

## 4. Target Architecture Checklist

- [ ] Raw Evidence Pipeline supports E01, DD, raw memory, EVTX, PCAP, registry hives, and filesystem artifacts.
- [ ] PCAP support is included in MVP as bounded triage, not full packet-forensic reconstruction.
- [x] Processed Evidence Pipeline supports `.plaso`, CSV timelines, JSON exports, Volatility JSON, YARA matches, strings output, and preprocessed EVTX.
- [x] Mixed-source analysis accepts up to six manifest evidence inputs per run and reports the correlation participation scope.
- [ ] Raw and processed pipelines converge at deterministic normalization.
- [ ] Processed evidence is treated as lower-trust DERIVED evidence, never ground truth.
- [ ] External processed evidence receives lower trust weighting and full validation.
- [ ] The architecture is documented as Protocol SIFT-compatible, not a Protocol SIFT replacement.
- [ ] Correct positioning statement is included: "Blitz DFIR operates as a Protocol SIFT-compatible controlled forensic reasoning layer."
- [ ] Architecture diagram shows the correct relationship: Agent -> Protocol SIFT or Blitz MCP Server -> Controlled Typed Tool Boundary -> SIFT tools -> parsed normalized outputs.
- [ ] Documentation says Blitz makes Protocol SIFT safer, more deterministic, and more analyst-grade; it does not replace SIFT or Protocol SIFT.
- [ ] Case state is the core object and progressively accumulates evidence, normalized artifacts, correlations, findings, warnings, coverage, audit logs, and correction history.
- [ ] The system behaves like a controlled forensic reasoning appliance, not an autonomous cyber AGI platform.

## 5. Repository Scaffold

- [x] Create `app.py` CLI entrypoint.
- [x] Create `pyproject.toml`.
- [x] Create pinned dependency management: `requirements.txt`, `uv.lock`, or pip-tools output.
- [x] Create `.gitignore` with `.env`, output artifacts, temporary sessions, and forensic data excluded.
- [x] Create `.env.example`; do not commit real secrets.
- [x] Create `README.md`.
- [x] Create `LICENSE` using MIT or Apache 2.0 for Devpost eligibility.
- [x] Create `config/settings.yaml`.
- [x] Create `config/tools.yaml`.
- [x] Create `config/scoring.yaml`.
- [x] Create package folders with `__init__.py` where needed.
- [x] Create `output/reports/`, `output/audit/`, `output/findings/`, and `output/timelines/` placeholders only if safe for repo hygiene.
- [x] Add docs folder: `docs/ARCHITECTURE.md`, `docs/DEMO_SCRIPT.md`, `docs/ACCURACY_REPORT.md`, `docs/DATASETS.md`, `docs/JUDGE_QA.md`.
- [x] Add tests folder with phase-aligned test files.
- [x] Decide whether input routing lives in `core/manifest.py`, `sanitization/provenance.py`, `mcp/dispatcher.py`, or a new module before adding new architecture surface.

## 6. Phase 1 - Foundation

Build first. Do not start the AI/reasoning layer here.

- [x] Implement `core/manifest.py`.
- [x] Manifest loads `case.yaml`.
- [x] Manifest validates schema strictly.
- [x] Manifest registers evidence IDs.
- [x] Manifest records evidence type, path, size, hash, provenance, and selected pipeline.
- [ ] Manifest records expected parser/tool route for later adapters.
- [x] Manifest scopes evidence roots.
- [x] Manifest rejects unknown paths.
- [x] Manifest rejects duplicate evidence IDs.
- [x] Input routing classifies E01/DD, memory, EVTX, PCAP, registry hives, `.plaso`, CSV, JSON, Volatility JSON, YARA matches, strings output, and preprocessed EVTX before any tool dispatch.
- [x] Input routing selects raw pipeline or processed pipeline deterministically.
- [x] Input routing records the selected pipeline in case state and audit logs.
- [x] Implement `core/integrity.py`.
- [x] Compute SHA256 for evidence.
- [x] Verify evidence hash before analysis.
- [ ] Re-verify evidence hash before tool execution.
- [ ] Hash raw tool outputs.
- [ ] Hash generated reports.
- [x] Implement `core/validation.py`.
- [x] Validate file existence, allowed type/extension, size, and declared evidence class.
- [ ] Add deeper MIME/file signature checks where practical.
- [x] Reject evidence whose declared type and detected type conflict unless explicitly overridden and audited.
- [x] Implement `core/evidence.py`.
- [x] Resolve paths with `Path.resolve()`.
- [x] Enforce `is_relative_to(EVIDENCE_ROOT)` or equivalent safe fallback.
- [x] Reject path traversal.
- [x] Reject symlink escape.
- [x] Enforce read-only evidence access.
- [x] Reject writes to evidence paths with a security error.
- [x] Implement `core/session.py`.
- [x] Generate stable session IDs.
- [ ] Generate correlation IDs.
- [x] Create per-session working directory outside evidence roots.
- [x] Store output only under controlled session/output paths.
- [x] Implement base normalized schemas needed by later phases.
- [x] Implement audit log skeleton early so all later steps can log.

Phase 1 acceptance checks:

- [x] Invalid manifest fails closed.
- [x] Missing evidence file fails closed.
- [x] SHA256 mismatch fails closed or downgrades trust based on configured mode.
- [x] Path traversal attempt is rejected.
- [x] Symlink escape attempt is rejected.
- [x] Evidence write attempt is rejected.
- [x] Session output cannot be written inside evidence root.
- [x] Audit entries are created for successful manifest load and hash verification.
- [ ] Audit entries are created for manifest/integrity failures before session creation.

## 7. Phase 2 - Sandbox And MCP Boundary

- [x] Implement `sandbox/runner.py`.
- [x] Implement `sandbox/limits.py`.
- [ ] Implement `sandbox/user_isolation.py`.
- [ ] Use subprocess boundaries for all tools and parsers.
- [x] Use argument arrays only; never command strings.
- [x] Enforce `shell=False`.
- [x] Enforce `TOOL_TIMEOUT = 300` seconds.
- [x] Capture stdout and stderr into controlled files or bounded buffers.
- [x] Enforce controlled working directory: `/tmp/blitz/<session_id>/` on SIFT or safe platform equivalent.
- [ ] Prepare support for running as dedicated `blitzsvc` user on Linux/SIFT.
- [ ] Never run tools as root unless explicitly overridden for a documented SIFT requirement.
- [ ] Restrict or document no-internet analysis mode.
- [ ] Enforce plugin allowlisting for Volatility and YARA.
- [ ] Block dangerous file auto-processing: executables, scripts, office macros, HTML, JS.
- [ ] Use `filelock` for concurrent write protection.
- [x] Implement `mcp/allowlist.py`.
- [x] Allow only `timeline`, `memory`, `events`, `pcap`, `strings`, `yara`, and `psort` handlers initially.
- [x] Implement `mcp/tool_registry.py`.
- [x] Register typed handlers only.
- [x] Block dynamic tool discovery.
- [x] Implement `mcp/dispatcher.py`.
- [x] Validate tool request schema.
- [x] Validate tool is allowlisted.
- [x] Validate evidence ID exists.
- [x] Validate evidence type is compatible with the tool.
- [x] Validate selected input route is compatible with the requested tool.
- [x] Validate timeout/resource limits.
- [x] Dispatch only to typed adapters.
- [x] Implement `mcp/server.py` when CLI dispatcher behavior is stable.
- [x] Add Protocol SIFT-compatible MCP server launch path.
- [x] Add agent integration config or instructions for Claude Code/OpenClaw.
- [x] Add typed MCP functions that map to high-level DFIR tasks such as timeline extraction, memory triage, EVTX analysis, strings scan, YARA scan, and psort extraction.
- [x] Add typed MCP function for bounded PCAP triage.
- [x] Return structured, bounded results from MCP calls; never return massive raw dumps.
- [ ] Log MCP request ID, agent/tool caller, typed function name, sanitized args, token usage if available, and result hash.
- [ ] Provide an integration smoke test from a Protocol SIFT case directory, not only from the Blitz repo root.
- [ ] Confirm Blitz writes only to approved case output paths such as analysis, reports, exports, or Blitz-controlled output folders, never evidence folders.

Phase 2 acceptance checks:

- [x] Disallowed tool request is rejected and audited.
- [x] Malicious filename containing shell metacharacters is passed safely as data, not executed.
- [ ] Timeout generates structured warning.
- [x] Tool execution failure produces bounded error, not crash cascade.
- [x] Dispatcher cannot execute unregistered handler.
- [ ] LLM-facing layer cannot call subprocess directly.

## 8. Phase 3 - Tool Adapters

- [x] Implement `tools/log2timeline_tool.py`.
- [x] Implement `tools/psort_tool.py`.
- [x] Implement `tools/volatility_tool.py`.
- [x] Implement `tools/chainsaw_tool.py`.
- [x] Implement `tools/pcap_tool.py` using bounded `tshark` first and optional Zeek when available.
- [x] Implement `tools/yara_tool.py`.
- [x] Implement `tools/strings_tool.py`.
- [x] Each adapter builds safe command arrays.
- [x] Each adapter writes output only to session output paths.
- [x] Each adapter returns structured metadata: tool, version, args hash, output path, output hash, exit code, duration, warnings.
- [x] Each adapter enforces bounded output.
- [x] Each adapter refuses direct evidence mutation.
- [x] Each adapter integrates with tool provenance verification.
- [x] Tool versions and expected hashes are configurable in `config/tools.yaml`.
- [x] Tool integrity mismatch downgrades findings or blocks execution according to policy.
- [x] YARA rules are allowlisted.
- [x] Volatility plugins are allowlisted.

Phase 3 acceptance checks:

- [x] Mocked successful adapter returns deterministic metadata.
- [x] Mocked failed adapter returns structured failure.
- [x] Hash mismatch creates critical warning.
- [x] Output path escape is rejected.
- [x] Adapter tests prove `shell=False`.

## 9. Phase 4 - Parsers And Sanitization

- [x] Implement `parsers/plaso_parser.py`.
- [x] Implement `parsers/evtx_parser.py`.
- [x] Implement `parsers/volatility_parser.py`.
- [x] Implement `parsers/pcap_parser.py`.
- [x] Implement `parsers/yara_parser.py`.
- [x] Implement parser handling for strings output if strings results are used in findings.
- [x] Implement `parsers/parser_validation.py`.
- [x] Implement `sanitization/sanitizer.py`.
- [x] Implement `sanitization/schema_enforcer.py`.
- [x] Implement `sanitization/provenance.py`.
- [x] Validate parser compatibility with source type and tool output type.
- [x] Validate coverage metadata for processed evidence before normalization.
- [x] All parsed records use strict Pydantic models.
- [x] Unknown fields are rejected, stripped, or quarantined by explicit policy.
- [x] External/derived inputs are sanitized before normalization.
- [x] Prompt-injection patterns are stripped or quarantined.
- [x] Strip or neutralize `ignore instructions`, `system prompt`, `assistant:`, `you are ChatGPT`, markdown control tokens, XML wrappers, hidden unicode, bidi override characters, null bytes, escape sequences, and ANSI codes.
- [x] Enforce `MAX_FIELD_LENGTH = 2048`.
- [x] Enforce `MAX_EVENTS = 5000` per normalized batch.
- [x] Length truncation creates warning object.
- [x] Malformed rows create warning object.
- [x] Invalid timestamps create warning object.
- [x] Encoding corruption creates warning object.
- [x] Parser degradation creates warning object.
- [x] Raw stdout never reaches LLM context.

Phase 4 acceptance checks:

- [x] Malicious CSV field with prompt injection is neutralized.
- [x] Poisoned JSON cannot inject arbitrary fields.
- [x] Volatility output containing instruction-like text is not sent to LLM.
- [x] Oversized field is bounded and audited.
- [x] Malformed parser row is counted and warned.
- [x] External `.plaso` is classified as low-trust DERIVED.

## 10. Phase 5 - Signal Integrity And Coverage

- [x] Implement `signal/integrity.py`.
- [x] Implement `signal/warnings.py`.
- [x] Implement `signal/coverage.py`.
- [x] Track tool timeouts.
- [x] Track event truncation.
- [x] Track parser degradation.
- [x] Track encoding corruption.
- [x] Track missing artifacts.
- [x] Track partial extraction.
- [x] Track hash mismatches.
- [x] Track retry exhaustion.
- [x] Track parser crashes.
- [x] Track abnormal event density.
- [x] Produce structured warning objects with type, tool, artifact, severity, impact, and confidence penalty.
- [x] Compute coverage per artifact type: EVTX, registry, memory, browser artifacts, timeline, and PCAP.
- [x] Compute overall case coverage.
- [x] Create analysis gap objects for unknown zones.
- [x] Feed signal warnings into confidence scoring.
- [x] Surface coverage and unknown zones in the signal integrity report; final HTML/Markdown rendering remains Phase 10.

Phase 5 acceptance checks:

- [x] Partial memory extraction creates analysis gap.
- [x] Event cap creates truncation warning.
- [x] Missing source in `.plaso` reduces coverage.
- [x] Timeout warning reduces confidence.
- [x] No signal degradation is silently dropped.

## 11. Phase 6 - Deterministic Normalization

- [x] Implement `core/normalization.py`.
- [x] Define canonical artifact/event model.
- [x] Include `event_id`.
- [x] Include `timestamp_utc`.
- [x] Include `category`.
- [x] Include `source_tool`.
- [x] Include `source_parser`.
- [x] Include `evidence_id`.
- [x] Include `evidence_type`.
- [x] Include `trust_level`.
- [x] Include `raw_reference`.
- [x] Include `confidence`.
- [x] Include parser warnings and provenance.
- [x] Normalize timestamps to UTC deterministically.
- [x] Normalize paths deterministically.
- [x] Normalize hashes consistently.
- [x] Normalize usernames consistently.
- [x] Normalize event categories consistently.
- [x] Generate stable event IDs.
- [x] Sort events deterministically.
- [x] Never allow INFERRED content to become RAW or DERIVED evidence.
- [x] Normalize PCAP triage records such as conversations, DNS, HTTP metadata, TLS/SNI metadata where available, unusual ports, byte counts, and timestamps.

Phase 6 acceptance checks:

- [x] Same input produces same normalized output.
- [x] Timestamp conversion is deterministic.
- [x] Event IDs are stable across reruns.
- [x] RAW, DERIVED, and INFERRED categories remain separate.
- [x] Normalized batch cap behavior creates structured `EVENT_TRUNCATION` signal; audit-log persistence remains Phase 11.

## 12. Phase 7 - Correlation Engine

- [x] Implement `correlation/timeline.py`.
- [x] Implement `correlation/lineage.py`.
- [x] Implement `correlation/persistence.py`.
- [x] Implement `correlation/attack_chain.py`.
- [x] Implement or finalize `correlation/confidence.py`.
- [x] Build temporal sequencing.
- [x] Build event stitching.
- [x] Build process parent-child lineage.
- [x] Build persistence detection for autoruns, services, scheduled tasks, and registry persistence.
- [x] Build attack-chain stage inference.
- [x] Build multi-source agreement scoring.
- [x] Build contradiction indicators for cross-source disagreement.
- [x] Anchor major findings to raw artifact references where available.
- [x] Never allow one parser/tool to become authoritative by itself.

Phase 7 acceptance checks:

- [x] Timeline order is deterministic.
- [x] Process lineage is traceable to supporting events.
- [x] Persistence finding requires evidence reference.
- [x] Single-source finding carries confidence penalty.
- [x] Cross-source disagreement raises contradiction.

## 13. Phase 8 - Reasoning Layer

- [x] Implement `reasoning/analyst.py`.
- [x] Implement `reasoning/hypotheses.py`.
- [x] Implement `reasoning/contradiction.py`.
- [x] Implement `reasoning/narrative.py`.
- [x] LLM receives only normalized summaries, structured findings, contradictions, warnings, coverage, and confidence scores.
- [x] LLM does not receive raw stdout, raw CSV, raw JSON, memory dumps, or raw evidence.
- [x] Cloud/private providers receive only bounded normalized summaries and never raw evidence, raw tool output, memory strings, or sensitive local paths.
- [x] Provider metadata and token usage are recorded where available.
- [x] Provider adapter allows swapping cloud/local/private inference without changing core DFIR logic.
- [x] Provider config supports environment variables for `LLM_BASE_URL`, `LLM_API_KEY`, and `LLM_MODEL`.
- [ ] Final demo video, execution logs, and accuracy report are captured while the selected demo provider account is available.
- [x] LLM can generate hypotheses.
- [x] LLM can explain uncertainty.
- [x] LLM can generate analyst-readable narrative.
- [x] LLM can help describe contradictions only within deterministic evidence boundaries.
- [x] LLM output is labeled INFERRED.
- [x] LLM output never modifies evidence state directly.
- [x] LLM output never creates tool execution plans directly.
- [x] Reasoning layer records why each next step was chosen, what it expected to find, and what it actually found.
- [x] Reasoning layer supports analyst-training transparency in reports without exposing raw evidence to the prompt.

Phase 8 acceptance checks:

- [x] Reasoning prompt excludes raw tool output.
- [x] Unsupported hypothesis is flagged as unsupported.
- [x] Narrative uses approved confidence language.
- [x] LLM cannot request arbitrary tool command.

## 14. Phase 9 - Validation And Self-Correction

- [x] Implement `correction/validator.py`.
- [x] Implement `correction/triggers.py`.
- [x] Implement `correction/rerun_engine.py`.
- [x] Implement `correction/bounded_retry.py`.
- [x] Validate evidence support for every finding.
- [x] Validate confidence threshold.
- [x] Validate contradiction count.
- [x] Validate parser integrity.
- [x] Trigger correction only for approved reasons.
- [x] Approved trigger: missing evidence or broken lineage.
- [x] Approved trigger: low confidence score.
- [x] Approved trigger: parser degradation or signal loss.
- [x] Approved trigger: timeline gaps or contradictions.
- [x] Approved trigger: contradiction count exceeds threshold.
- [x] Recovery actions are scoped, not full autonomous reruns.
- [x] Too many EVTX events -> narrow time range extraction.
- [x] Huge strings output -> filter to executable regions only.
- [x] Volatility timeout -> run specific plugin only.
- [x] Large plaso timeline -> scoped psort filtering.
- [x] Memory exhaustion -> chunked extraction.
- [x] Corrupted parser output -> alternate parser fallback.
- [x] Missing artifacts -> fallback correlation from available sources.
- [x] Tool integrity mismatch -> downgrade confidence and flag unverified.
- [x] Track correction ID, trigger, action, result, confidence delta, and final status.
- [x] Persistent loop behavior, if enabled, has a hard max-iteration cap separate from bounded correction.
- [x] Each iteration records what changed from the prior approach and why.

Phase 9 acceptance checks:

- [x] Retry count cannot exceed 2.
- [x] Correction cannot invent new unapproved tool chain.
- [x] Confidence delta is recorded.
- [x] Failed correction still produces honest low-confidence output.
- [x] Correction history appears in audit and report-section payload for Phase 10 rendering.

## 15. Phase 10 - Reporting

- [x] Implement `reporting/findings.py`.
- [x] Implement `reporting/report_builder.py`.
- [x] Implement `reporting/html_export.py`.
- [x] Implement `reporting/markdown_export.py`.
- [x] Implement JSON findings export.
- [x] Use Jinja2 with `autoescape=True` for HTML.
- [x] Escape all evidence-derived content.
- [x] Include findings.
- [x] Include evidence references.
- [x] Include confidence score.
- [x] Include confidence modifiers.
- [x] Include timeline.
- [x] Include contradictions.
- [x] Include self-correction logs.
- [x] Include audit trail reference.
- [x] Include coverage section.
- [x] Include unknown zones / analysis gaps.
- [x] Include evidence credibility section.
- [x] Include tool integrity status.
- [x] Include cross-validation results.
- [x] Include parser consensus score.
- [x] Include global case trust score.
- [x] Use approved language: "Evidence strongly supports", "High-confidence reconstruction suggests", "Coverage X percent; analysis gaps documented", and "Tool output is evidence candidate".
- [x] Never use forbidden language: "confirmed beyond doubt", "definitively malicious", "I saw everything", "tool output proves", "certain", or "guaranteed".
- [x] Reports explicitly separate confirmed evidence, evidence-supported findings, and INFERRED analyst reasoning.

Required finding fields:

- [x] `finding`
- [x] `evidence_source`
- [x] `source_tool`
- [x] `parser`
- [x] `parser_version`
- [x] `timestamp`
- [x] `confidence`
- [x] `confidence_modifiers`
- [x] `correlation_path`
- [x] `evidence_type`
- [x] `recovery_notes`

Phase 10 acceptance checks:

- [x] HTML report escapes malicious evidence content.
- [x] Markdown report is readable and evidence-backed.
- [x] JSON findings validate against schema.
- [x] Every finding has evidence references.
- [x] Report includes evidence credibility and coverage.
- [x] Report language avoids absolute truth claims.

## 16. Phase 11 - Audit Hardening

- [x] Implement `audit/audit_log.py`.
- [x] Implement `audit/execution_trace.py`.
- [x] Implement `audit/integrity_log.py`.
- [x] Use `.ndjson` storage.
- [x] Record session ID.
- [x] Record correlation ID.
- [x] Record tool executed and version.
- [x] Record tool hash.
- [x] Record ISO 8601 UTC timestamp.
- [x] Record sanitized arguments.
- [x] Record duration.
- [x] Record output hash.
- [x] Record exit code.
- [x] Record warnings.
- [x] Record agent messages or agent decisions where available.
- [x] Record token usage where available.
- [x] Record rerun triggers and reason.
- [x] Record validation failures.
- [x] Record parser warnings.
- [x] Record correction outcomes.
- [x] Record integrity checks.
- [x] Record confidence adjustments with delta.
- [x] Record coverage scores.
- [x] Implement tamper-evident hash chain.
- [x] Hash every audit entry.
- [x] Chain each entry to previous entry hash.
- [x] Make tampering visible without claiming it is impossible.

Phase 11 acceptance checks:

- [x] Audit log is deterministic and grep-friendly.
- [x] Removing or editing prior entry breaks chain verification.
- [x] Sensitive paths are sanitized where required.
- [x] Every phase writes audit events.
- [x] Audit chain path is shown in terminal output and report.

## 16A. SIFT-Native Test Environment Gate

Purpose: validate Blitz on the same class of Linux/SIFT environment judges are expected to use, while keeping the Windows host as the development machine and using shared folders only for controlled dataset transfer.

- [x] Decide primary test topology: Windows host for development, SIFT VMware guest for runtime and judge-facing tests.
- [x] Decide primary runtime style: native SIFT VM execution, not Docker-first.
- [x] Decide shared folder policy: use shared folders for dataset staging only; prefer copying evidence into a SIFT-local case directory before analysis.
- [x] Decide repository location on SIFT: clone or copy Blitz into a SIFT-local path such as `~/src/blitz-dfir`, not inside the dataset share.
- [x] Decide case layout on SIFT: evidence, processed data, outputs, reports, and audit logs live in separate case directories.
- [x] Decide LLM approach on SIFT: OpenClaw remains the judge-facing agent path; provider remains OpenAI-compatible and swappable.
- [x] Decide Docker posture: optional later for CI or clean dependency checks, but not the primary judge-facing runtime.
- [ ] Take a VMware snapshot before installing Protocol SIFT, OpenClaw, or additional Blitz dependencies.
- [ ] Confirm SIFT VM has outbound HTTPS only when cloud reasoning is required.
- [ ] Confirm a no-internet or restricted-internet analysis mode is documented for evidence processing.
- [x] Install or verify Protocol SIFT on SIFT using the official current install command.
- [x] Protocol SIFT installed global config, settings, skills, analysis script, and case template under `~/.claude/`.
- [x] Claude Code verified on SIFT: `/home/sansforensics/.nvm/versions/node/v24.15.0/bin/claude`, version `2.1.132`.
- [x] Protocol SIFT optional WeasyPrint PDF install failed because Ubuntu system Python is externally managed by PEP 668; do not use `--break-system-packages`.
- [x] Protocol SIFT optional WeasyPrint apt install attempted; `python3-weasyprint` has no installation candidate in the current SIFT/Ubuntu repositories. Defer PDF dependency handling unless demo explicitly needs PDF export.
- [x] Blitz tests and compile check still pass after Protocol SIFT installation.
- [ ] Install or verify OpenClaw on SIFT using the official current install method.
- [ ] Configure the selected private provider without committing secrets: `.env`, shell exports, or local agent config only.
- [x] Verify SIFT tool availability against `config/tools.yaml`: `log2timeline.py`, `psort.py`, `vol`, `chainsaw`, `tshark`, `yara`, and `strings`.
- [x] SIFT tool availability observed: `log2timeline.py`, `psort.py`, `vol`, and `strings` are present.
- [x] SIFT tool gap resolved: `chainsaw`, `tshark`, and `yara` are now present on SIFT.
- [x] SIFT quality gate observed on Python 3.12.3: `pytest`, `compileall`, `ruff`, and `pip-audit` passed before local mypy cleanup.
- [x] SIFT `mypy` failure analyzed: strict type errors only, no runtime test failures.
- [x] SIFT troubleshooting note recorded: deleting `~/src/Blitz_DFIR` also deletes `.venv`; recreate or reclone the repo before running Python quality gates again. Do not install project packages into Ubuntu's externally managed system Python.
- [x] Create a Python virtual environment on SIFT.
- [x] Install Blitz runtime and test dependencies on SIFT.
- [x] Run `python -m pytest -q` on SIFT.
- [x] Run `python -m compileall -q app.py blitz_dfir tests` on SIFT.
- [x] Run `python -m ruff check app.py blitz_dfir tests` on SIFT.
- [x] Run `python -m mypy app.py blitz_dfir tests` on SIFT.
- [x] Run `pip-audit -r requirements.txt -r requirements-dev.txt` on SIFT.
- [x] SIFT quality gate confirmed after Protocol SIFT install: `mypy`, `ruff`, and `pip-audit` all pass.
- [x] Private OpenAI-compatible provider direct API smoke passed from SIFT with `/chat/completions`; provider account, base URL, model, and API key were confirmed valid outside Blitz.
- [x] Private provider Python harness failure isolated to client-side request/env handling, not SIFT networking or provider reachability.
- [x] Private provider HTTP failure identified as Cloudflare 1010 `browser_signature_banned` against Python `urllib`; direct `curl` API smoke still succeeds.
- [x] Local-only private provider harness switched to a curl-backed OpenAI-compatible shim for SIFT testing only. This is not part of the public judge dependency path.
- [x] Re-sync local-only private provider harness to SIFT and rerun one E2E iteration.
- [x] SIFT private provider E2E timing recorded: one iteration completed in 12,054 ms with 656 tokens.
- [x] SIFT private provider three-iteration run completed in 37,782 ms; iterations took 12,160 ms, 13,456 ms, and 12,165 ms with 710 tokens each.
- [x] SIFT private provider run exposed a reasoning parser gap: model returned JSON inside Markdown fences, causing `model response was not JSON` fallback.
- [x] Public reasoning parser updated to recover fenced or prose-wrapped JSON while still treating conclusions as `INFERRED`.
- [x] Re-sync reasoning parser fix to SIFT and rerun private provider E2E until `model response was not JSON` disappears.
- [x] SIFT private provider rerun after fenced-JSON parser fix completed in 10,566 ms with 658 tokens; JSON recovery passed.
- [x] Run `python app.py analyze --manifest case.yaml --mode timeline` against a small SIFT-local test case.
- [x] Confirm evidence hashes are verified before analysis on SIFT.
- [x] Confirm outputs and audit logs are written outside the evidence directory.
- [x] Confirm original evidence hashes are unchanged after analysis.
- [x] Protocol SIFT-style case smoke test passed at `/cases/BLITZ-SMOKE-001`; audit chain written to `/cases/BLITZ-SMOKE-001/output/sess-20260524T060255Z-de10bca2/audit/sess-20260524T060255Z-de10bca2.ndjson`.
- [ ] Confirm PCAP MVP path runs with `tshark` if test PCAP is available.
- [ ] Confirm OpenClaw or Protocol SIFT can call a Blitz typed tool, not generic shell.
- [ ] Document exact SIFT VM version/date, Protocol SIFT install method, OpenClaw version, Python version, and tool versions used for testing.
- [ ] Record any Windows-to-SIFT differences that require code or documentation changes.
- [x] Record observed SIFT runtime difference: this SIFT test VM uses Python 3.12, while the original SSOT target mentioned Python 3.11. Accept Python 3.12 if tests, lint, type checks, and smoke tests pass.
- [x] Update README and `docs/PROTOCOL_SIFT_INTEGRATION.md` with the tested SIFT-native runbook after the smoke test passes.

## 16B. Phase 12A - Protocol SIFT / Blitz Typed Tool Integration

- [x] Fix `app.py` audit metadata so top-level `case_id` and `session_id` are populated.
- [x] Add `app.py mcp-serve --manifest ... --tool-config ...` launch path.
- [x] Add stdio JSON-RPC MCP server for Claude Code / Protocol SIFT.
- [x] Add MCP `initialize`, `tools/list`, and `tools/call` handlers.
- [x] Register typed Blitz tools through the existing allowlist and dispatcher.
- [x] Map `timeline`, `memory`, `events`, `pcap`, `strings`, `yara`, and `psort` MCP tools to typed SIFT adapters.
- [x] Return bounded MCP summaries with hashes and relative output paths, not raw tool stdout.
- [x] Keep tool execution behind manifest evidence IDs and session-scoped output directories.
- [x] Add tests proving MCP can list and call a typed tool.
- [x] Add tests proving generic shell tool requests are rejected by the MCP path.
- [x] Update `docs/PROTOCOL_SIFT_INTEGRATION.md` with case layout, MCP registration, direct MCP smoke, and Claude smoke instructions.
- [x] Update `README.md` to stop claiming Phase 1-only implementation status.
- [x] Sync Phase 12A files to SIFT.
- [x] Run SIFT quality gates after Phase 12A sync.
- [x] Run direct MCP stdio smoke from `/cases/BLITZ-SMOKE-001`.
- [x] Direct MCP stdio smoke listed typed tools and executed `strings` against `smoke-evtx` with `raw_output_returned=false`, output hashes, and relative output paths.
- [ ] Register Blitz MCP server with Claude Code using `claude mcp add`.
- [ ] Confirm Claude/Protocol SIFT can call the Blitz `strings` typed tool.
- [ ] Confirm Claude/Protocol SIFT cannot call generic shell through Blitz.
- [x] Claude Code project MCP registration file was created at `/cases/BLITZ-SMOKE-001/.mcp.json`.
- [x] Claude Code live smoke is blocked by account availability: current user does not have Claude subscription, Anthropic Console billing, Bedrock, Foundry, or Vertex access. This is not a Blitz MCP failure.
- [x] Continue with OpenClaw or Claude Code as the primary judge-facing agent path; keep private OpenAI-compatible provider testing local-only.
- [x] Eligibility check recorded: any authorized third-party LLM/API provider may be used only if the project still runs on/integrates with SIFT using OpenClaw, Claude Code, or a comparable agentic framework, and the Blitz custom MCP server remains the architectural guardrail. The provider must not be described as the agentic framework.
- [x] Local-only private provider E2E harness added under gitignored `local/`; do not include it in the public GitHub submission.
- [x] Private provider harness now lets the local env file override stale exported shell values.
- [x] OpenAI-compatible provider client now sends explicit JSON accept and user-agent headers and reports sanitized HTTP error details without exposing API keys.
- [x] Cloudflare 1010 from the private provider confirms that direct Python HTTP clients may be blocked even when credentials and model are valid; use curl-backed local harness for private smoke testing.
- [ ] Capture the MCP audit log showing `mcp_server_started`, `tool_request_validated`, and `tool_request_completed`.
- [x] Wire full `python app.py analyze --manifest ... --mode timeline` beyond foundation-only behavior.

## 16B-Submission Path Freeze

- [x] Public judge-facing architecture is frozen as: SIFT Workstation -> Protocol SIFT-compatible case workflow -> OpenClaw primary or Claude Code secondary -> Blitz typed MCP server -> allowlisted SIFT tools -> deterministic parsers/normalizers/correlation/validation/reports.
- [x] Submission framing sentence is frozen: Blitz DFIR uses a Custom MCP Server architecture running on SIFT, integrated with a Protocol SIFT-compatible agent path using OpenClaw or Claude Code. The LLM provider is swappable and not part of the security boundary.
- [x] Public architecture docs now show validation before bounded LLM reasoning; AI explains bounded validated summaries and cannot create confirmed findings.
- [x] Custom MCP Server is the primary Devpost architectural pattern to claim; Direct Agent Extension compatibility may be documented for Claude Code/OpenClaw, but it is not the core security boundary.
- [x] Claude Code status: installed and verified on SIFT, MCP project config generated, but live Claude tool-call smoke is blocked until a Claude subscription, Anthropic Console billing, Bedrock, Foundry, or Vertex login is available.
- [x] Claude Code account blockage is not a Blitz failure and must be documented as an environment/account limitation in internal notes until resolved.
- [x] If a Claude subscription is purchased before submission, use the existing `.mcp.json`/`claude mcp add` path and record one live Blitz typed-tool call; no provider-specific code changes should be needed.
- [x] If Claude access is not available, use OpenClaw as the primary judge-facing agent path and document equivalence/gap against Protocol SIFT's Claude Code-oriented starter workflow.
- [x] Private OpenAI-compatible provider status: verified only as a local developer E2E reasoning/timing harness under gitignored `local/`.
- [x] Private provider harness proved transport, timing, JSON recovery, and bounded-summary privacy; it is not a judge dependency, not an agent framework, and not part of the public setup path.
- [x] Public GitHub must not include private provider keys, provider-specific instructions, private local harness outputs, or any required paid private provider subscription.
- [x] Public docs may say "OpenAI-compatible provider" for bounded LLM reasoning, but must not require or optimize around the private testing provider.
- [x] Raw evidence and raw tool output must never be sent to any cloud/private LLM provider; only bounded normalized summaries are allowed.
- [x] Demo/video path should show deterministic `app.py analyze` and/or MCP typed tool calls first; Bounded LLM Reasoning can be shown only after deterministic evidence/report outputs are already proven.
- [x] Minimal-code-change rule before submission: do not fork separate public/private implementations. Keep one provider-neutral product path plus ignored local developer harnesses.
- [x] Pre-GitHub scrub commands required: search for private provider names outside `local/`, verify `local/` is ignored, verify no `.env` or API keys are staged, and run full quality gates.
- [x] Submission README should favor judge reproducibility over private convenience: SIFT setup, Protocol SIFT/OpenClaw or Claude Code MCP registration, sample case manifest, `app.py analyze`, expected reports, and audit log locations.
- [x] 2026-05-26 OpenClaw/Ollama path decision recorded: use OpenClaw as the judge-facing agent framework and Windows-hosted Ollama as the free local model backend; Blitz MCP remains the forensic security boundary.
- [x] 2026-05-26 SIFT VM can reach Windows Ollama at `http://192.168.88.1:11434/api/tags` after setting Windows `OLLAMA_HOST=0.0.0.0:11434` and adding a VMware-subnet firewall allow rule.
- [x] 2026-05-26 `gemma4:latest` was visible through Ollama but failed to load from SIFT with `model failed to load`, consistent with host resource pressure: about 8 GB RAM, about 1.2 GB free RAM, and less than 1 GB free C: space.
- [x] 2026-05-26 `llama3.2:1b` downloaded successfully on Windows Ollama and replaced the previously failing `gemma4:latest` local model.
- [x] 2026-05-26 Windows localhost Ollama generation smoke passed for `llama3.2:1b`; response was `Pong.`, total duration was about 21.8s, and model load duration was about 19.4s. Treat this as compatibility proof, not production-grade DFIR reasoning performance.
- [x] 2026-05-31 SIFT-to-Windows Ollama generation smoke passed from the SIFT VM against `http://192.168.88.1:11434/api/generate` using `llama3.2:1b`; response was `Pong.`.
- [x] 2026-05-31 Added `scripts/sift_e2e_ollama_run.sh` to launch a repeatable full-stack E2E run with Windows-hosted Ollama, bounded Blitz reasoning, SQLite-backed normalization, full SQL correlation, bounded report exports, and the existing `blitz_status.sh` progress monitor.
- [x] 2026-05-31 Progress monitoring exposes the bounded LLM reasoning layer explicitly instead of jumping from validation directly to reporting; disabled reasoning is marked as skipped and enabled reasoning is marked completed with provider/model/prompt metadata.
- [x] 2026-05-31 Progress monitoring split broad grouped rows into independent operator-visible layers: tool discovery, batch planning, evidence inventory, recovery planning, parsing, normalization, full accounting, SQLite event store, validation, unknowns, report generation, and audit finalization.
- [x] 2026-06-02 Truthful monitoring contract added: `audit/progress.json` remains analysis-layer progress, while supervised launcher completion is tracked through `analysis/runs/<RUN_ID>/run_status.json` and post-run artifact readiness is tracked through `analysis/postrun_checks/<session>_latest_postrun_manifest.json`.
- [x] 2026-06-02 `scripts/blitz_status.sh` now lists artifact readiness for reports, case objective, investigation priorities, evidence triage, bounded LLM reasoning, validation/safety outputs, evidentiary weighting, contradiction analysis, provenance, artifact manifest, audit attribution, and post-run checks instead of relying on 100% layer bars alone.
- [x] 2026-06-02 `scripts/blitz_monitor_until_done.sh` now waits for supervised `run_status.json` completion when present, so monitor completion is tied to post-run checks and operator lifecycle rather than session progress alone.
- [x] 2026-06-02 `scripts/blitz_status.sh` now formats active Blitz/SIFT processes as a compact table with PID, elapsed time, CPU, memory, process label, and parsed run limits instead of dumping unreadable full command lines.
- [x] 2026-06-02 `scripts/blitz_status.sh` now prints a review map for final reports, bounded LLM reasoning, correlation findings/scoring, evidentiary weighting, contradiction analysis, evidence traceability, audit progress, artifact hashes, normalized samples, parser results, and tool results.
- [x] 2026-06-02 `scripts/blitz_status.sh` now prints evidence-category proof: manifest evidence categories, SQLite normalized-event category counts, and bounded LLM reasoning category are displayed separately so PLASO remains visibly `DERIVED` and LLM reasoning remains `INFERRED`.
- [x] 2026-06-02 Added `scripts/blitz_fetch_latest_sift_proof_archive.ps1` to discover the latest completed SIFT session/run, create a proof archive, copy it to the Windows host, and verify SHA256 before cleanup or stress testing; full archive transfer now defaults to resumable `sftp reget`.
- [x] 2026-06-03 Added `scripts/blitz_fetch_latest_sift_thin_proof.ps1` for unstable network transfers and layer review; it preserves reports/audit/scoring/traceability/postrun status while excluding bulk timelines, SQLite event stores, normalized exports, full accounting, and tool-result payloads.
- [x] 2026-06-03 Fixed high-volume stress ladder pre-session failure handling: default `TOOL_TIMEOUT` now respects the Blitz typed-tool cap of `7200`, failed stage exit codes are preserved, and no-session failures print `run_status.json` plus the launcher log tail.
- [x] 2026-06-03 Converted the high-volume stress ladder into a current-ceiling proof path: default targets are `1M/2M/3M/4M/5M`, targets above the current `5M` normalized-event hard cap fail fast, and stage pass criteria require actual SQLite/accounting row counts to meet the target.
- [x] 2026-06-02 Normalization completion display now records actual completed normalized rows instead of carrying the configured cap into completed progress counters.
- [x] 2026-06-02 High-volume stress path prepared: normalized-event hard cap raised to 5,000,000, `PSORT_FILTER`/`PSORT_PROFILE` are configurable in the SIFT launcher, and `scripts/sift_high_volume_stress_ladder.sh` can run 1M/2M/3M/4M/5M supervised stages with target-row verification.
- [x] 2026-05-31 Added `LLM_TIMEOUT_SECONDS` so slow local Ollama model loading can be given a realistic timeout without changing provider code.
- [x] 2026-05-31 E2E runner now writes a per-run bundle under `/cases/<CASE>/analysis/runs/<RUN_ID>/` with launcher log, PID, preflight output, final session pointer, and final progress/session-state snapshots.
- [ ] 2026-05-31 Pending: run `scripts/sift_e2e_ollama_run.sh` on SIFT with `ENABLE_REASONING=1`, capture `audit/progress.json`, `session_state.json`, model metadata, token usage if reported, and final report artifacts.
- [ ] 2026-05-26 Pending: configure or re-verify OpenClaw with native Ollama base URL `http://192.168.88.1:11434` without `/v1`, then capture one OpenClaw-driven Blitz MCP typed-tool smoke.
- [x] 2026-05-26 OpenClaw installed/configured on SIFT with ClickClack local channel, no web search provider, skills deferred, and `command-logger` hook enabled.
- [x] 2026-05-26 OpenClaw model smoke passed through Windows Ollama using `ollama/llama3.2:1b`; prompt `Reply with exactly: pong` returned `Pong`.
- [ ] 2026-05-26 OpenClaw session file lock was observed for gateway PID 9875 and the lock file was removed manually while the gateway was alive. Verify gateway/session health before using OpenClaw logs as judge-facing evidence.
- [ ] 2026-05-26 Pending: after verifying OpenClaw session health, attempt Blitz MCP typed-tool smoke through OpenClaw and capture agent execution logs with timestamps and token/model usage.
- [x] 2026-05-26 Strategic model decision: `llama3.2:1b` is acceptable only for free/local compatibility proof and demo plumbing. It is not enough by itself for professional DFIR reasoning claims; submission credibility must come from deterministic Blitz outputs, complete dataset runs, audit logs, and conservative accuracy reporting.
- [x] 2026-05-26 Unknowns and Coverage Engine implemented additively: unsupported artifacts, parser degradation, missing expected data sources, validation issues, and partial/empty accounting artifacts are labeled as `UNKNOWN`, `NEEDS_REVIEW`, or `UNSUPPORTED` instead of being promoted to confirmed findings.
- [x] 2026-05-26 Provider-layer clarification recorded: OpenClaw is the judge-facing agent framework, Ollama is the free/local model backend, Featherless is a private OpenAI-compatible cloud inference backend used only for local smoke/timing comparisons, and Blitz MCP is the security boundary.
- [x] 2026-05-26 Decision: Ollama alone is sufficient for the free/local public path if it can run the required smoke tests, but Featherless remains useful as an optional stronger-model comparison path on constrained hardware. Neither provider should receive raw evidence or raw tool output.
- [ ] 2026-05-26 Pending after `llama3.2:1b` compatibility smoke: test one newer small local model only if host resources permit, preferably `qwen3.5:0.8b` or `qwen3:1.7b`, then compare against any private provider using the same bounded summaries and record model/provider limitations.
- [x] 2026-05-26 Submission-integrity decision: Featherless subscription access through 2026-06-13 may be used for private stronger-model testing and documentation reasoning over bounded summaries only, but every saved run must record the actual provider, model, timestamp, prompt hash, token usage, and whether raw evidence/tool output was sent.
- [x] 2026-05-26 Public GitHub remains provider-neutral and must not require Featherless, API keys, paid subscriptions, private harnesses, or private outputs. Do not claim a model/provider was used for judged evidence unless that exact provider/model run is logged and reproducible enough for the claim being made.
- [ ] 2026-05-26 Add a model evaluation matrix before submission: `local-free` OpenClaw/Ollama smoke path, `private-strong` Featherless bounded-summary reasoning path, exact model IDs, dates tested, datasets/scopes, token usage, limitations, and reproducibility notes.

## 16C. Phase 12B - Full Analyze Pipeline

- [x] Add reusable pipeline orchestration module instead of keeping analysis flow inside CLI glue.
- [x] `app.py analyze` now runs manifest load, session creation, evidence verification, typed tool execution, parsing, normalization, coverage, signal integrity, correlation, validation, bounded correction recording, and report export.
- [x] Keep Bounded LLM Reasoning disabled by default; enable only with `--enable-reasoning`, and send bounded normalized summaries only.
- [x] Route EVTX to `events`, PCAP to `pcap`, memory to allowlisted `windows.pslist`, PLASO to `psort`, and disk/timeline-capable raw artifacts to `timeline`.
- [x] Parse direct processed inputs for `CSV_TIMELINE`, `PREPROCESSED_EVTX`, `JSON_EXPORT`, `VOLATILITY_JSON`, `YARA_MATCHES`, and `STRINGS_OUTPUT` without invoking external tools.
- [x] Record tool failures as signal warnings and audit events instead of aborting the entire case.
- [x] Export report artifacts to the session `reports/` directory and intermediate JSON artifacts to `findings/`.
- [x] Run full local quality gates after Phase 12B implementation.
- [x] Sync Phase 12B to SIFT.
- [x] Run SIFT smoke with existing `/cases/BLITZ-SMOKE-001` before testing actual raw evidence.
- [x] SIFT Phase 12B quality gate passed: `test_app.py`, `compileall`, `mypy`, `ruff`, and `pip-audit`.
- [x] SIFT Phase 12B fake-EVTX smoke completed and wrote audit plus JSON/Markdown/HTML reports under session `sess-20260524T095512Z-73a7e1f1`.
- [x] Fake-EVTX smoke produced zero normalized events and warnings as expected because the smoke file is not valid EVTX forensic data.
- [x] Verify audit contains tool, parser, normalization, correlation, validation, report, and completion events.
- [x] Verify original evidence hash remains unchanged after Phase 12B smoke.
- [x] Verify smoke evidence remains read-only after Phase 12B run.
- [x] Phase 12B smoke audit events observed: manifest/evidence/analysis start, tool request validated/completed, tool result, parser completed, normalization, correlation, correction attempts/history, validation, reasoning skipped, reports written, analysis completed.
- [x] Phase 12B smoke integrity observed: `smoke.evtx` SHA256 remained `76cc4918df608a055d7efe0695346d54fdc2139c90d1965324cb1ac8b2544151`.
- [x] Phase 12B smoke report correctly showed zero normalized events for fake EVTX and parser/coverage warnings instead of false findings.
- [x] Add warning de-duplication before signal/validation reporting to avoid inflating repeated parser degradation issues.
- [x] Reporting interface decision recorded: MVP reporting interface is static `reports/report.html`, with `report.json` and `report.md` as supporting outputs. Do not add a separate GUI before core submission artifacts are complete.
- [x] Processed PLASO import path documented: declare `.plaso` files in `case.yaml` as `type: PLASO`; Blitz runs typed `psort` and then deterministic PLASO CSV parsing.
- [x] First user-provided processed PLASO diagnostic completed on SIFT for `base-rd-01-cdrive.E01`; initial run produced zero events because `psort.py -o l2tcsv` timed out after 300s on a 3.9 GB / 6,862,907-event store and left an empty CSV.
- [x] Phase 12B PLASO fix added: `psort` now defaults to `dynamic` output, quiet status, high-signal triage profile, bounded optional filters/slices, and configurable typed-tool timeout.
- [x] `app.py analyze` now exposes `--psort-profile triage|full`, `--psort-filter`, `--psort-slice`, `--psort-slice-size`, and `--tool-timeout` so large PLASO stores can be triaged first, focused by analyst criteria, and fully exported only when intentionally requested.
- [x] MCP `psort` schema now documents optional `profile`, `filter`, `slice`, `slice_size`, and `timeout_seconds` parameters for agent-driven self-correction without shell access.
- [x] Superseded: second user-provided PLASO attempt was manually interrupted during `psort`; the first proposed `SELECT ... WHERE (...) LIMIT 5000` triage syntax was later proven invalid for psort filters.
- [x] Superseded: manual SIFT diagnostic found `SELECT datetime,timestamp_desc,...` invalid; field selection belongs in `--fields` / `--additional_fields`, but the follow-up `SELECT timestamp ... LIMIT ...` idea was also later proven invalid.
- [x] Superseded: interim Blitz `psort` triage command used `SELECT timestamp WHERE (...) LIMIT 5000`; this was replaced with expression-only psort filters.
- [x] Follow-up SIFT diagnostic proved `SELECT timestamp LIMIT ...` is also invalid for this Plaso version. Official psort filters are expression filters, not SQL queries.
- [x] Corrected Blitz `psort` triage again to use expression-only filters such as `(data_type contains 'windows:evtx' or ...)` while keeping field selection in `--fields` and `--additional_fields`.
- [x] Follow-up SIFT diagnostic proved `psort.py --slice` and `--slicer` cannot be used together in this Plaso version.
- [x] Corrected Blitz `psort` slice command generation to emit `--slice` plus `--slice_size` without `--slicer`.
- [ ] Rerun the user-provided processed PLASO file on SIFT with `--psort-profile triage` before testing raw disk or memory images.
- [ ] Only after processed PLASO gates pass, test one small actual raw artifact type first.
- [x] 2026-05-26 Windows local regression check passed: `python -m pytest -q` passed with one skipped test, and `python -m compileall -q app.py blitz_dfir tests` passed.
- [x] 2026-05-26 Windows local layer check passed after full-accounting/unknowns/stress/spoliation additions: `python -m pytest -q` passed with one skipped test, and `python -m compileall -q app.py blitz_dfir tests` passed.
- [x] 2026-06-03 Added mixed-source correlation intake: manifest caps runs at six evidence inputs, direct processed routing now handles Volatility JSON, YARA matches, strings output, CSV timelines, JSON exports, and preprocessed EVTX, and reports/audit include `correlation_scope_recorded` plus `report.json.correlation_scope`.
- [ ] 2026-05-26 Windows local `ruff`, `mypy`, and `pip-audit` were not run because the Windows Python environment lacks those modules and the C: drive is too full to safely install dev dependencies during Ollama setup. Run these gates on SIFT `.venv` instead.
- [x] 2026-05-26 SIFT quality gates passed after Ollama bridge work: `pytest`, `compileall`, `ruff`, `mypy`, and `pip-audit` all passed; mypy emitted only `annotation-unchecked` notes in `tests/test_tool_adapters.py`.
- [ ] 2026-05-26 Processed PLASO rerun attempt for `BLITZ-RD01-PLASO` started with `--psort-profile triage --tool-timeout 900`, but the SIFT terminal reset before results were captured. Treat status as unknown until process table, session output, audit log, and system logs are checked.
- [ ] 2026-05-26 Before rerunning the 3.9 GB PLASO through full Blitz analyze, check for surviving `python app.py analyze` or `psort.py` processes, inspect `/cases/BLITZ-RD01-PLASO/output/sess-*`, and run a narrow `psort` slice/filter probe under `script`/`tee` so terminal resets do not destroy evidence.
- [ ] 2026-05-26 Follow-up showed `/mnt/hgfs` is broken with `Transport endpoint is not connected`, so the PLASO evidence path is unavailable through VMware shared folders. Repair/remount `vmhgfs-fuse` or copy the PLASO to a stable SIFT-local path before rerunning Blitz.
- [x] 2026-05-26 `/mnt/hgfs` was remounted successfully and `case.plaso` became readable again, but VMware shared-folder stability remains a risk for long processing.
- [x] 2026-05-26 Copied the 4.15 GB processed PLASO from `/mnt/hgfs/Forensics/cases/raw/rd-01-cdrive/case.plaso` to stable SIFT-local storage at `/cases/BLITZ-RD01-PLASO/processed/case.plaso`.
- [x] 2026-05-26 Copied PLASO hash verified: source `/mnt/hgfs/Forensics/cases/raw/rd-01-cdrive/case.plaso` and local `/cases/BLITZ-RD01-PLASO/processed/case.plaso` both hash to `cd9a0ce596ecdda9100176ccc950ec9f539787c47ef3d421d32d7e9ebe0c1e55`.
- [x] 2026-05-26 Rebuilt `/cases/BLITZ-RD01-PLASO/case.yaml` against local SIFT storage and ran the narrow logged `windows:evtx` PLASO probe.
- [ ] 2026-05-26 Narrow `windows:evtx` PLASO probe produced a safe failure: `psort` timed out after 300 seconds with exit code 124, wrote a zero-byte CSV, produced zero normalized events, generated 15 signal warnings, validation failed, and reports/audit were written under `sess-20260526T014233Z-d3014da3`. This is a parser/tool-performance failure, not evidence of no attacker activity.
- [x] 2026-05-26 `pinfo.py` confirmed the local PLASO store is valid and large: 6,862,907 total events, 685,866 event sources, 1,335,280 `winevtx` events, 1,768,862 `winreg_default` events, 753,727 `usnjrnl` events, 547 PowerShell transcript events, and parser/recovery warnings worth documenting as dataset limitations.
- [x] 2026-05-26 30-minute controlled retry completed the first useful PLASO extraction path with `--psort-filter "data_type contains 'windows:evtx'" --tool-timeout 1800`: session `sess-20260526T023915Z-21534fdf`, 457 MB `rd01-plaso.csv`, 5000 normalized events, reports written, and validation still failed with 15 signal warnings. Treat this as bounded engineering validation, not full dataset accuracy.
- [x] 2026-05-26 Early monitoring of the 30-minute retry initially showed `python app.py analyze` under `script` with latest session `sess-20260526T023915Z-21534fdf` and a zero-byte `rd01-plaso.csv`; follow-up process-tree inspection confirmed `psort.py` PID 10398 was active, had the local PLASO open for read, had the CSV open for write, and the VM showed ongoing read I/O with manageable swap.
- [ ] 2026-05-26 Pending: inspect parser cap/validation warnings for the 5000-event PLASO run, document why validation failed, and decide whether to raise bounded parser limits, use timestamp slicing, or split by data source for complete credible results.
- [x] 2026-05-26 Broad requirement implemented locally: user wants no dataset evidence left out for professional DFIR credibility. Blitz now adds a separate Full Evidence Accounting / Event Store layer that preserves and hashes complete exported CSV artifacts, streams every CSV row into indexed SQLite, records aggregate counts, and keeps the human report bounded. Do not simply raise `MAX_EVENTS` into millions or dump every row into JSON/HTML.
- [x] 2026-05-26 Stress-test reporting layer implemented locally: every analysis now writes `findings/stress_report.json` with tool counts, timeout status, normalized event count, full-accounting row totals, validation/signal status, and session artifact inventory.
- [ ] 2026-05-26 SIFT high-volume stress execution still pending: rerun the copied PLASO through the updated pipeline, verify `full_accounting.json`, `event_store.sqlite`, `unknowns.json`, `stress_report.json`, source hash preservation, and reproducibility against the same manifest.
- [ ] 2026-05-26 SIFT attempted the stress command after local layer implementation, but the CLI output did not print `Full accounting`, `Event store`, `Unknowns`, or `Stress report`, and the session findings directory did not contain the new files. Treat this as a code-sync/version mismatch on SIFT before treating it as a layer failure.
- [x] 2026-05-26 SIFT source sync confirmed and quality gates passed after layer transfer: focused new-layer tests, full pytest, compileall, ruff, mypy, and pip-audit all passed. Mypy emitted only existing `annotation-unchecked` notes in `tests/test_tool_adapters.py`.
- [x] 2026-05-26 First SIFT high-volume layer run succeeded against `BLITZ-RD01-PLASO` with `psort` EVTX filter and `--tool-timeout 1800`: `psort` exit code 0, duration 1,649,659 ms, 5,000 normalized events, 40 findings, 12 signal warnings, validation failed with 6 issues, and new artifacts were written: `full_accounting.json`, `event_store.sqlite`, `unknowns.json`, and `stress_report.json`.
- [x] 2026-05-26 First SIFT high-volume layer run accounting verified: exported CSV had 1,329,653 lines including header, SQLite `event_rows` had 1,329,652 rows, `full_accounting.json` reported 1,329,652 `windows:evtx:record` rows from parser `winevtx`, malformed count 0, partial false, and timed-out tools empty. The CSV was about 1.41 GB and the SQLite event store about 4.22 GB.
- [ ] 2026-05-26 Pending before raw E01/DD testing: verify source PLASO hash preservation after the run and inspect whether coverage validation should treat PLASO-derived EVTX rows as satisfying scoped EVTX coverage.
- [ ] 2026-05-26 Architecture requirement recorded: move from one scoped tool run toward batch-based artifact routing. The pipeline should enumerate declared/derived evidence, classify artifact families, queue specialized tool batches for EVTX, PLASO, registry, browser artifacts, memory, PCAP, prefetch, LNK, tasks, and strings/YARA where applicable, then run bounded batches step by step to avoid overloading the VM.
- [ ] 2026-05-26 Batch execution should be controlled by resource policy: max concurrent tools, per-tool timeout, per-batch row/event cap for normalized reports, full-accounting preservation for complete outputs, resumable checkpoints, and per-batch validation before moving to the next artifact family.
- [x] 2026-05-26 Source PLASO hash remained unchanged after high-volume run: `/cases/BLITZ-RD01-PLASO/processed/case.plaso` SHA256 stayed `cd9a0ce596ecdda9100176ccc950ec9f539787c47ef3d421d32d7e9ebe0c1e55`.
- [x] 2026-05-26 Batch-plan layer implemented locally: `app.py analyze` now writes `findings/batch_plan.json`, audits `batch_plan_created`, `batch_started`, and `batch_completed`, and executes planned tasks sequentially with `max_parallel_tools=1`.
- [x] 2026-05-26 Batch planner routes declared evidence into ordered artifact-family batches: direct processed inputs, EVTX, PLASO, registry, memory, PCAP, disk timeline, filesystem, and unsupported/manual-review evidence.
- [x] 2026-05-26 Scoped coverage refined locally: PLASO-derived rows with `windows:evtx` / `winevtx` now satisfy EVTX coverage for scoped runs instead of falsely reporting EVTX as missing.
- [x] 2026-05-26 Windows local batch-plan check passed: `python -m pytest -q` passed with one skipped test, and `python -m compileall -q app.py blitz_dfir tests` passed.
- [ ] 2026-05-26 Pending SIFT sync: copy `blitz_dfir/batching`, updated `app.py`, updated `blitz_dfir/pipeline/analyze.py`, updated `tests/test_app.py`, new `tests/test_batch_plan.py`, and updated checklist to SIFT, then rerun focused and full quality gates.
- [x] 2026-05-26 Documentation decision recorded: deploying Blitz means deploying orchestration, typed MCP, batch planning, accounting, validation, unknowns, and reports. It does not mean deploying a replacement forensic distro or bundling SIFT tools.
- [x] 2026-05-26 Judge-facing role split documented: SIFT provides forensic tools, Protocol SIFT/OpenClaw/Claude Code provides the agent workflow, Blitz provides typed safety controls, stepwise batch execution, full accounting, conservative validation, and audit-backed reporting.
- [x] 2026-05-26 Documented that Protocol SIFT resolves the SIFT-native AI workflow and action-logging path, but Blitz adds controls Protocol SIFT alone does not guarantee: no generic shell exposure, evidence-ID access, resource-aware batch execution, full accounting, unknowns, and bounded LLM reasoning.
- [ ] 2026-05-26 Add MCP batch-control endpoints after SIFT sync: `create_batch_plan`, `get_batch_status`, `run_next_batch`, and `summarize_unknowns`.
- [ ] 2026-05-26 Add SIFT tool discovery before full raw testing: detect `psort.py`, `log2timeline.py`, `vol`/`volatility3`, `tshark`, `chainsaw`, `yara`, and `strings`; mark unavailable batches/tools as `UNSUPPORTED` instead of crashing late.
- [ ] 2026-05-26 Add evidence inventory artifact before full raw testing: declared evidence, type, size, hash, recommended batch, estimated resource risk, and expected specialized tool family.
- [x] 2026-05-26 Evidence inventory and tool discovery layer implemented locally: every analysis now builds `tool_discovery.json` from configured executables and `evidence_inventory.json` from manifest evidence plus the batch plan, including evidence hashes, trust tier, recommended batch/tool, tool availability, resource risk, and required controls.
- [x] 2026-05-26 Tool discovery is non-destructive and preflight-only: it resolves executables with PATH lookup, records disabled/missing/hash-mismatch/unreadable states, and does not run forensic tools during discovery.
- [x] 2026-05-26 Inventory/discovery local verification passed: focused inventory/batch/app/parser/normalization tests passed, `compileall` passed, and full `pytest -q` passed with the existing skipped test. Local Windows lacks `ruff` and `mypy`, so run those on SIFT after sync.
- [ ] 2026-05-26 Pending SIFT sync for inventory/discovery: copy `blitz_dfir/inventory`, updated `blitz_dfir/pipeline/analyze.py`, updated `app.py`, `tests/test_inventory.py`, and this checklist, then run SIFT focused/full gates before registry/browser/memory/PCAP batches.
- [x] 2026-05-26 Suspicion explanation layer implemented locally: `CorrelatedFinding` and report findings now include `triage_score` and `suspicion_reasons`, derived deterministically from event category, suspicious command tokens, user-writable paths, persistence locations, network context, unusual ports, warnings, and multi-event/multi-source grouping.
- [x] 2026-05-26 Suspicion layer intentionally does not discard low-score events yet. It adds explainability and prioritization while preserving full accounting/event-store completeness. Filtering thresholds remain a later policy decision after SIFT data review.
- [x] 2026-05-26 Report rendering updated so Markdown and HTML show `Why suspicious` as evidence-backed analyst prioritization. MITRE/ATT&CK mapping is intentionally deferred and not included in this update to avoid unsupported taxonomy questions during submission review.
- [x] 2026-05-27 Submission decision recorded: do not include MITRE/ATT&CK labels in the current SIFT push. Keep the current update focused on evidence inventory, tool discovery, full accounting, tamper-evident artifacts, triage scoring, and suspicion reasons.
- [x] 2026-05-26 Suspicion layer local verification passed: targeted correlation/report/reasoning/correction/app tests passed, `compileall` passed, and full `pytest -q` passed with the existing skipped test. Local Windows lacks `ruff` and `mypy`, so run those on SIFT after sync.
- [ ] 2026-05-26 Pending SIFT sync for suspicion layer: copy updated `blitz_dfir/correlation`, `blitz_dfir/reporting`, updated `blitz_dfir/pipeline/analyze.py`, updated tests, and checklist, then run SIFT focused/full gates.
- [ ] 2026-05-26 Cleanup requirement: before overnight or full normalized stress testing, preserve small baseline summaries and delete old `/cases/<case>/output/sess-*` directories that are no longer needed. Never delete `/cases/<case>/processed/case.plaso`, `/cases/<case>/case.yaml`, manifests, or raw evidence.
- [x] 2026-05-27 Long deterministic stability testing setup created: `scripts/sift_long_stability_run.sh`, `scripts/sift_summarize_session.py`, `scripts/sift_cleanup_case_outputs.sh`, and `docs/STABILITY_TESTING.md`.
- [x] 2026-05-27 Stability setup scope recorded: test Blitz CLI end-to-end without Protocol SIFT/OpenClaw/Claude Code, including typed tool dispatch, timeout handling, parser/normalization, full accounting, event-store row preservation, unknowns, validation, reports, session state, artifact manifest hashes, evidence hash preservation, tool discovery, evidence inventory, and suspicion reasons.
- [x] 2026-05-27 Stability setup excludes MITRE/ATT&CK mapping and cloud/agent reasoning to keep this cycle focused on deterministic engineering reliability.
- [x] 2026-05-27 Stability harness hardening added after first SIFT attempt left a stale `RUNNING` session with no active process: phases now capture command exit codes, attempt a session summary even after failure, write `phase_status.jsonl`, status output prints the latest phase log, and `HASH_EACH_PHASE=0` can skip repeated large evidence hashes after a trusted source hash is recorded.
- [x] 2026-05-27 Low-memory stability profile added for constrained host/VM conditions: `STABILITY_PROFILE=lowmem` skips the intentional timeout probe and 100k normalized report phase, runs `evtx_baseline_5k`, `evtx_normalized_25k`, `evtx_normalized_50k`, and `evtx_repeat_5k`, and should be paired with `HASH_EACH_PHASE=0 DELETE_PASSED_SESSIONS=1`.
- [x] 2026-05-27 Stability threshold decision recorded: 25k normalized and repeat 5k are accepted as already passed; 50k is the next middle stress gate; 100k is no longer part of the default/low-memory ladder because it is the observed failure boundary and should be treated as a separate breakpoint experiment.
- [x] 2026-05-27 SIFT 50k normalized EVTX stress run completed cleanly before stdout/stderr streaming patch was applied: session `sess-20260527T043444Z-514a5e26`, `psort` exit code 0, `timed_out=False`, duration 1,800,880 ms, 50,000 normalized events, 3,400 findings, 3 signal warnings, validation failed with 1 expected truncation issue, and all reports/accounting/inventory/unknowns/stress artifacts were written. Treat 50k as the current proven normalized/report ceiling on the constrained VM until post-patch retest confirms otherwise.
- [x] 2026-05-27 First failed stability attempt classified as an interrupted external-tool run, not a completed Blitz result: session `sess-20260526T184855Z-c013cf53` stopped after `tool_request_validated` with a zero-byte CSV, no `tool_results.json`, no `tool_request_completed`, and stale `session_state.status=RUNNING`. Kernel logs did not show an explicit OOM kill, but constrained memory remains the operating assumption.
- [x] 2026-05-27 Tool stdout/stderr memory hardening implemented locally: `sandbox.runner.run_subprocess` no longer uses `subprocess.run(..., capture_output=True)` because that can accumulate noisy tool stdout/stderr in Python memory until tool exit. It now streams stdout/stderr to temporary files under the session working directory, reads back only the bounded captured output, hashes the bounded copy, and deletes the temporary files.
- [x] 2026-05-27 Memory-hardening verification passed locally: sandbox runner, tool adapter, and spoliation tests passed; full `pytest -q` passed with the existing skipped test; `compileall` passed. Local Windows lacks `ruff` and `mypy`, so run those on SIFT after sync.
- [ ] 2026-05-27 Pending SIFT sync for stdout/stderr streaming runner: copy `blitz_dfir/sandbox/runner.py`, `tests/test_sandbox_runner.py`, and updated checklist, then rerun SIFT focused/full gates before the next 50k or full raw stress test.
- [ ] 2026-05-27 Pending SIFT sync for stability setup: copy `scripts/`, `docs/STABILITY_TESTING.md`, and updated checklist to SIFT; run cleanup dry-run, then launch the long stability ladder under `nohup`.
- [ ] 2026-05-27 Long stability acceptance gates: clean phases must complete with `session_state.status=COMPLETED`, `analysis_completed` audit event, artifact manifest, unchanged evidence hash, empty `timed_out_tools`, CSV line count equal to SQLite rows plus header, inventory/discovery artifacts present, and reports showing `Why suspicious` with no MITRE/ATT&CK references.
- [ ] 2026-05-26 Test ladder recorded: do not jump straight from bounded PLASO EVTX success into full raw all-artifact execution. Next order is SIFT sync/gates, repeat EVTX-filter with batch plan, artifact-family batch tests, normalized-cap stress ladder, full-accounting full-mode PLASO test, then Protocol SIFT/OpenClaw driven batch execution.
- [ ] 2026-05-26 Threshold strategy recorded: full evidence completeness is proven by full-accounting/event-store row preservation, not by dumping all rows into normalized JSON/HTML. Increase normalized/report caps only as a controlled stress test with clear stop rules for disk, RAM, runtime, and report size.
- [ ] 2026-05-26 Before raising normalized thresholds, add configurable normalized/report cap support so tests can run `5k -> 25k -> 50k/100k` without editing source constants or pretending every row belongs in the human report.
- [ ] 2026-05-26 SIFT repeat EVTX-filter batch run reportedly reached `Normalization completed: events=5000 warnings=2`, then the terminal closed unexpectedly before visible completion. Investigate whether the process survived, whether full-accounting SQLite import was in progress, whether disk/RAM pressure caused the terminal/session failure, and whether the latest session has complete `batch_plan`, `full_accounting`, `event_store`, `unknowns`, `stress_report`, reports, and final audit events.
- [x] 2026-05-26 Failure investigation result: no `app.py analyze` or `psort.py` process survived; latest session had completed `psort` output (`rd01-plaso.csv` about 1.41 GB) and audit through `normalization_completed`, but no final reports. `event_store.sqlite` existed with table `event_rows` and 0 rows plus a rollback journal, consistent with process termination during full-accounting import before final commit.
- [x] 2026-05-26 Accounting durability fix implemented locally: `event_store` now commits CSV import chunks during full-accounting import and creates indexes after row import, so a terminal/session interruption should not roll back every inserted row.
- [ ] 2026-05-26 Pending SIFT sync for accounting durability fix: copy updated `blitz_dfir/accounting/event_store.py` to SIFT, rerun focused accounting tests, then recover or rerun the EVTX-filter batch under `tmux`/`nohup` instead of a normal foreground terminal.
- [x] 2026-05-26 Session integrity controls implemented locally: `audit/session_state.json` records checkpointed run status/phase with a state hash, and successful runs write `findings/artifact_manifest.json` with SHA256 and size for session output artifacts.
- [x] 2026-05-26 Tamper-evidence limitation documented internally: hashes and audit chains detect later modification if a trusted copy of the manifest/audit is preserved, but they are not tamper-proof against an actor with write access who can rewrite all local files. For judge-grade evidence, copy final audit/artifact manifest/report hashes off the VM after each completed run.
- [ ] 2026-05-26 Pending SIFT sync for session integrity controls: copy `blitz_dfir/audit/session_integrity.py`, updated `blitz_dfir/pipeline/analyze.py`, updated `app.py`, and `tests/test_session_integrity.py` to SIFT, then rerun gates.
- [ ] 2026-05-26 Updated five-step SIFT validation runbook issued: sync latest integrity/accounting/batch updates, run gates, rerun EVTX-filter batch under `tmux`, verify run completeness/tamper-evidence artifacts, run artifact-family batches, then proceed only to controlled threshold/full-mode testing.
- [ ] 2026-05-26 SIFT latest gate run passed focused tests/full tests/compileall/ruff/mypy after sync, but `pip-audit` was inconclusive because the HTTPS request to the vulnerability service/PyPI was reset by peer during TLS. This is a network-dependent gate failure, not a reported vulnerability. Rerun `pip-audit` before marking the latest SIFT gate complete.
- [x] 2026-05-26 Nohup EVTX-filter rerun completed as a controlled partial run: session `sess-20260526T102747Z-6cb94b00`, `session_state.status=COMPLETED`, `phase=analysis_completed`, source PLASO before hash `cd9a0ce596ecdda9100176ccc950ec9f539787c47ef3d421d32d7e9ebe0c1e55`, CSV had 801,204 lines, SQLite had 801,203 rows, and `artifact_manifest.json` recorded 21 session artifacts with SHA256s.
- [x] 2026-05-26 Nohup EVTX-filter rerun correctly reported timeout/partial evidence: `psort` exit code 124, timed_out true, `stress_report.status=needs_review`, `timed_out_tools=['psort']`, validation failed with 3 parser degradation/signal-loss issues, and unknowns recorded critical/high needs-review states instead of false completion.
- [ ] 2026-05-26 Before repeating EVTX-filter at a higher timeout, compare this partial 801,203-row run to the previous successful 1,329,652-row EVTX run and check host load/disk I/O, because the same filter previously completed within 1800 seconds.
- [x] 2026-05-26 Higher-timeout EVTX-filter rerun completed cleanly through the tool layer: session `sess-20260526T122628Z-8e7e8775`, `psort` exit code 0, `timed_out=False`, duration 2,046,887 ms, `session_state.status=COMPLETED`, `phase=analysis_completed`, 5,000 normalized events, 40 findings, 2 signal warnings, validation failed with 1 expected issue, and all integrity/accounting/unknowns/stress/report artifacts were written.
- [ ] 2026-05-26 Verify the higher-timeout EVTX-filter rerun row accounting before using it as the clean baseline: confirm CSV line count, SQLite `event_rows` count, `full_accounting_total_rows`, `timed_out_tools=[]`, source PLASO after-hash, and artifact manifest hash coverage.
- [x] 2026-05-26 Configurable normalized/report cap implemented locally for controlled stress runs: `app.py analyze --max-normalized-events N` sets `BLITZ_MAX_EVENTS`, parser/normalization/batch-plan layers read the active cap dynamically, default remains 5,000, and hard limit is 2,000,000 to prevent accidental unbounded report generation on constrained SIFT VMs.
- [x] 2026-05-26 Local cap-control verification passed: focused parser/normalization/app tests passed, `compileall` passed, and full `pytest -q` passed with the existing skipped test. Local Windows lacks `ruff` and `mypy`, so run those on SIFT after sync.
- [ ] 2026-05-26 Overnight normalized stress run is approved only as a controlled stress test, not a final forensic accuracy claim. Preserve full accounting/event-store as the evidence completeness source, run under `nohup`, capture before/after evidence hash, and monitor disk/RAM. Stop if free disk drops below 15 GB or swap pressure becomes heavy.
- [x] 2026-05-26 Report-refactor decision: do not replace or remove the existing JSON/Markdown/HTML report outputs before the core layers are complete. Keep current reports as compatibility artifacts, but defer report-size optimization and alternate lightweight-first report formats until after full-accounting/event-store, unknowns/coverage, and stress-test layers are proven.
- [x] 2026-05-26 Layer-first local implementation complete through stress-report readiness: deterministic ingestion/tool execution remains intact, full evidence accounting/event store added, unknowns/coverage added, validation/self-correction preserved, spoliation/bypass tests added, and stress reporting added before any final report redesign.
- [ ] 2026-05-26 Do not redesign final report packaging until the updated layers pass the SIFT high-volume PLASO stress run.

## 17. Documentation And Submission Readiness

- [x] Write `README.md` with Protocol SIFT-compatible positioning.
- [x] Write `docs/ARCHITECTURE.md`.
- [x] Write `docs/DEMO_SCRIPT.md`.
- [ ] Write `docs/ACCURACY_REPORT.md`.
- [ ] Write `docs/DATASETS.md`.
- [ ] Write `docs/JUDGE_QA.md`.
- [ ] Write or generate `docs/SUBMISSION_CHECKLIST.md` for the eight Devpost components.
- [x] Write `docs/PROTOCOL_SIFT_INTEGRATION.md`.
- [x] Write `docs/SPOLIATION_TESTING.md`.
- [x] Write `docs/AGENT_EXECUTION_LOGS.md` or document where generated logs are stored.
- [x] Include Protocol SIFT install reference and state the exact tested install method.
- [x] Include Protocol SIFT case-directory workflow.
- [x] Include how Blitz interacts with Protocol SIFT skills and settings without weakening them.
- [ ] Include how to uninstall or disable Blitz without damaging Protocol SIFT.
- [ ] Include OpenClaw setup as the primary judge-facing agent path.
- [ ] Include provider-neutral OpenAI-compatible setup without naming or requiring a private provider.
- [x] Include Claude Code compatibility notes as a secondary Protocol SIFT-oriented path.
- [x] Include cloud-provider disclosure and what data is never sent to any cloud model.
- [x] Include Simple Mental Model in README and architecture docs.
- [ ] Document raw evidence pipeline.
- [ ] Document processed evidence pipeline.
- [ ] Document why `.plaso` is DERIVED and not ground truth.
- [x] Document MCP/Protocol SIFT relationship clearly.
- [x] Document hard prohibitions.
- [ ] Document trust tiers.
- [ ] Document RAW/DERIVED/INFERRED separation.
- [ ] Document confidence model.
- [ ] Document coverage model.
- [ ] Document self-correction model and limits.
- [ ] Document what is deliberately out of scope.
- [ ] Document demo dataset setup.
- [ ] Document expected terminal output.
- [x] Document exact supported architecture approach: Custom MCP Server with Protocol SIFT-compatible typed tool boundary.
- [x] Document Agent Orchestrator layer separately from Blitz deterministic layers.
- [x] Document validation-before-optional-reasoning order.
- [x] Document that private provider testing is local-only and not the judge-facing agent framework.
- [ ] Document why Blitz rejects generic shell access and why this matters for judging.
- [ ] Document prompt-based controls separately from architectural controls.
- [x] Document evidence maturity artifacts and repeatability matrix scaffold.
- [x] Document real case walkthrough scaffold.

## 18. Demo Readiness Checklist

- [ ] Demo runs with `python app.py analyze --manifest case.yaml --mode timeline`.
- [ ] Terminal shows manifest loaded.
- [ ] Terminal shows evidence verified with SHA256 OK.
- [ ] Terminal shows read-only scope established.
- [ ] Terminal shows tool integrity verified.
- [ ] Terminal shows sandbox execution started.
- [ ] Terminal shows events parsed and normalized.
- [ ] Terminal shows signal warning when truncation or degradation occurs.
- [ ] Terminal shows coverage percentages.
- [ ] Terminal shows correlation completed.
- [ ] Terminal shows contradiction if applicable.
- [ ] Terminal shows self-correction triggered when applicable.
- [ ] Terminal shows scoped rerun details.
- [ ] Terminal shows confidence improvement or honest low-confidence result.
- [ ] Terminal shows report output path.
- [ ] Terminal shows audit chain output path.
- [ ] Terminal shows global case trust.
- [ ] Demo uses pre-tested datasets.
- [ ] Demo has no missing dependency surprises.
- [ ] Demo handles timeouts gracefully.
- [ ] Demo output is deterministic across reruns.
- [ ] Demo can be completed inside a 5 minute video.
- [ ] Demo narration calls out Protocol SIFT integration explicitly.
- [ ] Demo narration calls out where architectural guardrails are enforced.
- [ ] Demo narration shows one finding traced back to a specific tool execution.
- [ ] Demo narration shows `findings/evidence_maturity.json` or `reports/evidence_maturity.md` as the proof index.
- [ ] Demo narration shows one hallucination, contradiction, or unsupported claim being caught or downgraded.

## 19. Test And Quality Gates

- [x] Unit tests for manifest validation.
- [x] Unit tests for evidence path safety.
- [x] Unit tests for SHA256 verification.
- [x] Unit tests for read-only enforcement.
- [x] Unit tests for allowlist dispatcher.
- [x] Unit tests for sandbox runner.
- [x] Unit tests for tool adapters using mocked subprocess.
- [x] Unit tests for parser validation.
- [x] Unit tests for sanitization.
- [x] Unit tests for normalization determinism.
- [x] Unit tests for confidence scoring.
- [x] Unit tests for correlation logic.
- [x] Unit tests for contradiction detection.
- [x] Unit tests for bounded retry enforcement.
- [x] Unit tests for report schema.
- [x] Unit tests for audit hash chain.
- [ ] Integration test for raw EVTX flow.
- [ ] Integration test for processed `.plaso` flow.
- [ ] Integration test for malformed evidence.
- [ ] Integration test for parser degradation.
- [ ] Integration test for missing artifact.
- [ ] Integration test for contradiction plus scoped rerun.
- [ ] Integration test for report generation.
- [ ] Integration test for Protocol SIFT or selected agent calling Blitz MCP typed tools.
- [x] Integration test proving generic shell command execution is not exposed through the MCP surface.
- [x] Spoliation test proving original evidence is not modified even if model instructions request modification.
- [x] Bypass test for prompt-only guardrail failure mode.
- [x] Unit/integration tests for full-accounting event-store row preservation beyond `MAX_EVENTS`.
- [x] Unit/integration tests for explicit unknowns reporting from coverage, validation, signal, and partial accounting artifacts.
- [x] Unit/integration tests for stress-report status and artifact inventory.
- [x] Unit tests for evidence maturity finding traceability artifact.
- [ ] Benchmark test against known-good data with ground truth, false positives, missed artifacts, and hallucinated claims.
- [x] Run `pytest`.
- [x] Run `ruff`.
- [x] Run `mypy`.
- [x] Run `pip-audit`.
- [x] Confirm dependency versions are pinned.

## 20. Real-World Validation Dataset Needs

- [ ] Real or representative E01/DD image.
- [ ] Real or representative raw memory image.
- [ ] Real or representative EVTX files.
- [ ] Real or representative registry hives.
- [ ] Real or representative `.plaso` timeline.
- [ ] Malformed EVTX/parser degradation sample.
- [ ] Partial corruption sample.
- [ ] Missing artifact case.
- [ ] High-volume event/truncation case.
- [ ] Tool timeout simulation.
- [ ] Prompt-injection-in-evidence sample.
- [ ] Contradictory evidence sample.
- [ ] Known-good ground truth dataset for accuracy scoring.
- [ ] Protocol SIFT starter resources and sample case data, if available and license-compatible.

## 21. Explicitly Deferred Or Rejected Scope

Do not add these unless the user explicitly reopens the architecture decision:

- [ ] Kubernetes.
- [ ] Blockchain.
- [ ] eBPF observability.
- [ ] SIEM integrations.
- [ ] Autonomous remediation.
- [ ] Dynamic AI scripting.
- [ ] LangChain mega-stack.
- [ ] Multi-agent swarms.
- [ ] Graph databases.
- [ ] Vector memory.
- [ ] Deep learning or reinforcement learning.
- [ ] Distributed orchestration.
- [ ] Runtime telemetry infrastructure.
- [ ] Enterprise-scale zero-trust mesh.
- [ ] Kernel anti-tamper.
- [ ] Full deep PCAP reconstruction beyond bounded triage unless explicitly approved.
- [ ] MCP-connected live endpoint or SIEM triage unless explicitly selected as the track.
- [ ] Multi-agent framework implementation unless explicitly selected; current safest path is custom MCP server.

## 22. Known Decisions And Gaps To Resolve

- [ ] SSOT filename is `v2.1`, but document text labels itself "Version 2.0 / SSOT v2.0 (Consolidated)". Treat the file `Blitz_DFIR_SSOT_v2.1.docx` as authoritative unless user says otherwise.
- [ ] `Blitz_DFIR_SSOT_v2.docx` and `Blitz_DFIR_SSOT_v2.1.docx` are identical by SHA256. There are no v2.0-only missing implementation items at review time.
- [x] PCAP is now approved for bounded MVP triage with `tshark` first and optional Zeek if available on SIFT.
- [x] README table names Anthropic Claude API, while the current architecture uses a provider-agnostic adapter.
- [x] Judge-facing integration target is OpenClaw or Claude Code; any private OpenAI-compatible provider is only the LLM provider, not the agent framework.
- [ ] Protocol SIFT official repo is Claude Code-oriented. Because OpenClaw is chosen, document equivalence and any gap from the official Protocol SIFT setup.
- [ ] Runtime user `blitzsvc` is SIFT/Linux-specific. Local Windows development should scaffold this as a platform check and enforce it on Linux/SIFT.
- [ ] "No internet during analysis" may require OS/container/firewall control outside Python. Document and enforce where practical.
- [ ] Raw artifact byte offsets may not be available from every parser in MVP. Use best available `raw_reference` and document gaps.
- [ ] Tool integrity requires trusted tool hash baselines. Decide whether baselines live in `config/tools.yaml` or a signed external manifest.
- [ ] Existing `.plaso` files must include origin metadata or be treated as external low-trust DERIVED inputs by default.
- [ ] Actual `.env` should not be created as a committed file even though the SSOT tree lists `.env`.
- [ ] Devpost requires public repository and open-source license; confirm no private evidence or secrets enter the repo.
- [ ] Devpost requires source/assets/instructions sufficient for judges to run the project; decide which sample data can be referenced, downloaded, or bundled.

## 23. Living Checklist Rules

- [ ] Every implementation phase updates this checklist or a phase-specific checklist before moving on.
- [ ] Broad tasks must be broken into checkable subtasks before coding.
- [ ] If a requested change conflicts with this architecture, stop and explain the conflict before replacing the design.
- [ ] If any working feature would be removed, stop and ask for confirmation first.
- [ ] If a new feature expands scope, record what capability it adds and what problem it solves.
- [ ] If a feature is deferred or rejected, record why.
- [ ] Every phase ends with tests and audit/logging verification.
- [ ] No phase is considered complete until acceptance checks pass.

## 24. Scale Stabilization And Resume Hardening Log

- [x] Added resumable analysis entry point so an interrupted session can reuse existing session artifacts instead of rerunning SIFT tools from zero.
- [x] Added bounded downstream analysis controls: `--max-analysis-events`, `--report-event-limit`, `--report-finding-limit`, `--normalized-export-limit`, and `--parser-record-export-limit`.
- [x] Added checkpoint writes for batch plan, tool discovery, evidence inventory, tool results, parser summaries, full accounting, unknowns, stress report, session state, and artifact manifest.
- [x] Preserved full-accounting behavior separately from report scope: exported rows stay in SQLite/accounting, while analyst-facing reports can be bounded for low-memory systems.
- [x] Documented the stability principle for judges: full evidence accounting is exhaustive where completed, while correlation/report presentation is explicitly scoped and audit-visible.
- [x] Fixed mypy type narrowing in the optional typed-tool dispatch path without changing runtime behavior.
- [x] Changed large JSON artifact exports to safe-by-default bounded samples: `normalized_events.json` defaults to 10,000 records and `parser_results.json` defaults to 1,000 records per parser result.
- [x] Preserved backward-compatible `normalized_events.json` list shape when all normalized events fit within the export limit; bounded wrapper is used only when records are omitted.
- [x] Added pre-report checkpoint writes for validation, coverage, signal integrity, correction history, and unknowns so a report-phase interruption still leaves useful forensic receipts.
- [x] Added report-build session-state checkpoints to make crash location visible in `audit/session_state.json`.
- [x] Removed redundant final rewrites of already-checkpointed parser/tool/inventory/accounting artifacts to reduce report-phase memory and I/O pressure.
- [x] Added final export checkpoints for normalized export, stress report, report export, and artifact manifest generation.
- [x] Added batch-completed and normalization-started session checkpoints so scale interruptions identify the real active phase.
- [x] Optimized normalization by avoiding a duplicate parser-record list copy and avoiding a redundant per-parser sort before the final global normalized-event sort.
- [x] Added SQLite-backed normalization mode for large capped runs: when `--max-normalized-events` is greater than `--max-analysis-events`, Blitz streams normalized rows into `findings/event_store.sqlite` instead of retaining every normalized event in Python memory.
- [x] Added explicit override for normalization storage strategy with `BLITZ_SQLITE_NORMALIZATION=1` or `BLITZ_SQLITE_NORMALIZATION=0`, while keeping the automatic low-memory behavior as the default for large scoped runs.
- [x] Added parser-result sampling for SQLite-backed runs so `parser_results.json` records parser summaries and bounded sample records instead of serializing hundreds of thousands of parser objects.
- [x] Added `normalized_events` SQLite table with chunked commits, compact JSON fields, and indexes on event ID, timestamp, evidence ID, and category for auditability and future SQL-backed analytics.
- [x] Updated bounded normalized export accounting so `normalized_events.json` reports the total normalized count even when only the retained analysis/sample window is exported.
- [x] Added post-normalization object inventory as a first-class audited layer: `findings/object_inventory.json` records observed users, process images, process IDs, files, registry keys, hashes, network observables, evidence with no normalized events, unsupported/unavailable evidence, and bounded omission counts.
- [x] Added recovery planner as a first-class audited pre-execution layer: `findings/recovery_plan.json` records primary and fallback extraction paths per evidence item, sequential execution requirements, auto-runnable typed routes, and blocked/unchecked routes such as Velociraptor until a typed adapter, parser, and allowlist entry exist.
- [x] Added shell-readable operator progress: `audit/progress.json` tracks layer status, weighted overall percent, elapsed time, coarse ETA, and SQLite normalization row counts; `scripts/blitz_status.sh` displays this with active processes, latest session state, output sizes, memory, and disk.
- [x] Consolidated operator status to one canonical snapshot script: `scripts/blitz_status.sh` displays process heartbeat/writer PID visibility and explicitly marks stale `RUNNING` sessions as `ABANDONED_OR_PARTIAL` when no live process is updating them.
- [x] Added prompt-returning long-run monitor: `scripts/blitz_monitor_until_done.sh` refreshes `blitz_status.sh`, exits automatically after completion, and prints `Blitz DFIR Process completed` instead of keeping the operator in an endless `watch` loop.
- [x] Hardened E2E launcher completion messaging: `scripts/sift_e2e_ollama_run.sh` records `Blitz DFIR Process completed` in the run bundle log on success and now recommends the prompt-returning monitor command.
- [x] Hardened pre-session monitoring: if a new run is hashing or doing startup work before `output/sess-*` exists, `scripts/blitz_status.sh` now shows the latest run bundle and prints `Blitz run initiated. This may take a while; hashing in progress.` instead of displaying stale historical session results.
- [x] Added guarded resume support to the E2E launcher through `RESUME_SESSION=/cases/.../output/sess-*`; resume is refused unless completed typed tool results exist, then downstream layers rerun from parsing/normalization through final audit.
- [x] Added beginner-safe LLM reasoning inspection helper: `scripts/blitz_llm_reasoning_summary.sh` prints provider/model, prompt hash, token usage, hypothesis/decision counts, narrative preview, and safety interpretation without exposing raw evidence.
- [x] Hardened generated-output cleanup for fresh full-pipeline tests: `scripts/sift_clean_generated_for_rerun.sh` now refuses to delete generated sessions/logs while Blitz, psort, log2timeline, psteal, or case.plaso-related processes are active unless `FORCE=1` is explicitly set.
- [x] Added agent-stack preflight for Protocol SIFT/Ollama activation: `scripts/blitz_agent_stack_preflight.sh` checks the deterministic baseline, verifies Ollama/OpenAI-compatible reachability when configured, creates a tiny MCP smoke case, proves Blitz typed MCP `tools/list` and `strings` work, and proves non-allowlisted shell-style requests are rejected.
- [ ] After SIFT deployment, resume the failed 1M/100k session or rerun 1M/100k to verify `sqlite_normalization_completed`, bounded RAM use, final reports, artifact manifest, and audit-chain completion.
- [x] Added `--full-sql-correlation` as the next scale architecture step: SQLite scans the full `normalized_events` table and stores selected candidate findings in `sql_correlation_candidates`, while Python only loads supporting events for validation/reporting.
- [x] Preserved the existing Python correlation path for small runs and compatibility; SQL correlation is additive and selected explicitly by CLI flag.
- [x] Fixed recovery planner static typing so every recovery candidate status remains constrained to the approved literal status set.
- [x] Documented post-E2E LLM evaluation steps: preserve the successful session, run the Ollama E2E checker, inspect the reasoning section, state the limits of `llama3.2:1b`, and proceed to OpenClaw agent orchestration evaluation.
- [x] Added SQL correlation audit visibility: `sql_correlation_completed` records backend, rows scanned, candidate count, finding count, support-event count, and candidate-store location.
- [x] Established the judge-facing distinction for full-scale runs: analysis can scan every normalized row through SQL while report/event display remains intentionally bounded.
- [x] Added tests proving SQLite correlation scans the full normalized store and loads only bounded support events.
- [x] Hardened SQLite-backed resume normalization with staging-table replacement: new runs rebuild `normalized_events_next` and swap it into `normalized_events` only after completion, preventing interrupted resume attempts from replacing a completed normalized table with a partial one.
- [x] 2026-05-31 Reviewed last pasted SIFT E2E status: run completed with exit code 0, 1,329,652 normalized events, 500 findings, validation passed, full SQL correlation completed, and audit/report artifacts written. Treat this as successful pre-evidence-maturity E2E, not final new-layer E2E.
- [x] 2026-05-31 Fixed monitoring session selection bug: `blitz_status.sh` no longer wipes a discovered running session just because the latest run bundle has not yet written `session_path.txt`.
- [x] 2026-05-31 Added immediate run-bundle session pointer support: `run_analysis` writes `${BLITZ_RUN_ROOT:-$RUN_ROOT}/session_path.txt` as soon as the Blitz session is created, and the SIFT launcher exports `BLITZ_RUN_ROOT`.
- [x] 2026-05-31 Added realtime progress visibility for the new evidence maturity layer: `evidence_maturity` now appears between report generation and audit finalization.
- [x] 2026-05-31 Added live heartbeats for long object inventory, full accounting, SQL correlation, and evidence maturity phases so status output updates while the phase is still running.
- [x] 2026-05-31 Added session-state phase updates for manifest integrity, tool discovery, batch planning, evidence inventory, recovery planning, normalization progress, and evidence maturity.
- [x] 2026-05-31 Updated `blitz_e2e_ollama_check.sh` to require evidence maturity output and audit event for the next E2E.
- [x] 2026-05-31 Cleaned generated local workspace result directories under `output/` while preserving `.gitkeep` scaffold files.
- [x] 2026-05-31 Extended SIFT cleanup script so `analysis/runs/*` run bundles are deleted along with `output/sess-*` sessions during `APPLY=1` cleanup.
- [x] 2026-05-31 Added host-to-SIFT deployment script `scripts/blitz_sync_to_sift_vm.ps1` using tar plus `scp`/`ssh`, excluding generated outputs/caches while preserving remote `.venv`, `.git`, and `output` when `-CleanRemote` is used.
- [x] 2026-05-31 Removed duplicate filesystem lines in status/launcher/cleanup output by deduplicating identical `df` source/mount rows.
- [x] 2026-05-31 Removed duplicate monitor completion line by letting `blitz_monitor_until_done.sh` suppress the status script's `[operator result]` block and print the final result once.
- [x] 2026-05-31 Reduced terminal blinking: `blitz_monitor_until_done.sh` no longer clears the terminal by default; use `CLEAR_SCREEN=1` only for dashboard-style redraws.
- [x] 2026-05-31 Reduced false interruption risk: monitor now treats recent progress updates as live for a `STALE_GRACE_SECONDS` window before declaring `abandoned_or_partial`.
- [x] 2026-05-31 Added audit checkpoint attribution metadata: future audit entries now record `initiated_by`, `component`, `trust_boundary`, and `behavior`.
- [x] 2026-05-31 Updated `[recent audit checkpoints]` status output to display the initiator/component and surface security-relevant, degraded, bounded-scope, integrity-warning, validation, unknowns, and recovery behavior labels.
- [x] 2026-05-31 Added backward-compatible checkpoint inference so older audit logs still show likely initiator/component/boundary context even when the new metadata fields are missing.
- [x] 2026-05-31 Added Protocol SIFT/Ollama E2E launcher context through `BLITZ_AGENT_FRAMEWORK`, so `analysis_started` identifies the SIFT launcher and configured LLM when the SIFT run script starts Blitz.
- [x] 2026-05-31 Hardened host-to-SIFT sync exclusions so `.env`, local/private folders, evidence files, case folders, generated outputs, and caches are not copied to the VM.
- [x] 2026-05-31 Added VM post-run checker `scripts/blitz_vm_postrun_checks.sh` to run status, E2E validation, LLM reasoning summary, session summary, and audit-attribution checks against a completed SIFT session.
- [x] 2026-05-31 Reviewed pasted E2E output for `/cases/BLITZ-RD01-PLASO/output/sess-20260531T071128Z-556f606b`: completed all progress layers, normalized 1,329,652 events, scanned all rows through SQL correlation, produced 500 findings, passed validation, wrote evidence maturity, wrote artifact manifest, and completed audit finalization.
- [x] 2026-06-01 Reviewed pasted final SIFT proof run for `/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82`: status `COMPLETED`, elapsed 46m50s, `psort` exit code 0, 1,329,652 normalized events, 7,268 object-inventory objects, 1,329,652 full-accounting rows, SQL correlation scanned 1,329,652 rows, 17,880 candidates, 500 findings, validation passed with 0 issues, unknowns=2 with 0 critical/high, bounded Ollama reasoning completed over bounded summaries, evidence maturity traced 500/500 findings, evidence hashes preserved, artifact manifest written, and audit finalization completed.
- [x] 2026-06-01 Latest pasted run confirms audit-attribution metadata is now visible in checkpoints: initiator/component/trust-boundary context is shown for normalization, object inventory, full accounting, SQL correlation, validation/unknowns, reasoning, evidence maturity, reporting, and orchestration events.
- [x] 2026-06-01 Recorded the latest run in `docs/RUN_PROOF_SUMMARY_20260531T203012Z.md`, `docs/DATASETS.md`, `docs/REPEATABILITY_MATRIX.md`, `docs/ACCURACY_REPORT.md`, and `docs/JUDGE_LAYER_PROOF_CHECKLIST.md`.
- [x] 2026-06-01 Exact command and launcher environment captured from `/cases/BLITZ-RD01-PLASO/analysis/runs/20260531T202550Z/launcher.log`: `.venv/bin/python app.py analyze --manifest /cases/BLITZ-RD01-PLASO/case.yaml --mode timeline --tool-config /home/sansforensics/src/Blitz_DFIR/config/tools.yaml --enable-reasoning --psort-profile triage --psort-filter "data_type contains 'windows:evtx'" --tool-timeout 7200 --max-normalized-events 2000000 --max-analysis-events 100000 --report-event-limit 5000 --report-finding-limit 500 --normalized-export-limit 10000 --parser-record-export-limit 1000 --full-sql-correlation`.
- [x] 2026-06-01 Final proof archive copied from SIFT to Windows host: `Blitz_DFIR_Proof/sess-20260531T203012Z-bff65d82_proof_full.tar`, size 9,859,072,000 bytes, SHA256 `4c2772e55f8cc728a92769f517021b3d6cb92c1a7619b54ddd3b1c8ffc8cd28e`, matching the SIFT `.sha256` file.
- [x] 2026-06-01 Dataset source/license/permission documented: user confirmed `BLITZ-RD01-PLASO` is SANS Find Evil hackathon-provided case material and can be publicly named; raw evidence should not be redistributed unless SANS terms permit.
- [x] 2026-06-01 Formal ground truth is not currently known, so analyst expectations were documented: find suspicious, hidden, or unknown activity while minimizing hallucinated/unsupported claims.
- [x] 2026-06-01 Inspected latest run artifacts before judge presentation: captured `progress.final.json`, session `audit/progress.json`, `findings/parser_results.json`, and audit entries show `parser_results=1`, `parser_result_count=1`, `parser_processed_count=1329652`, parser `plaso`, `processed_count=1329652`, and `parser_completed`; treat pasted `Parser result extraction (0/1)` as a terminal status-display issue, not a parser-layer failure.
- [x] 2026-06-01 Closed explicit PLASO after-hash gap using `findings/evidence_maturity.json`: expected and observed SHA256 both equal `cd9a0ce596ecdda9100176ccc950ec9f539787c47ef3d421d32d7e9ebe0c1e55`, with `preserved=true`.
- [x] 2026-06-01 Created preliminary finding review `docs/FINDING_REVIEW_20260531T203012Z.md`.
- [x] 2026-06-01 Accuracy-review risks documented before judge-facing accuracy claims: 500 finding rows but 252 unique finding IDs, all findings single-source confidence `0.55` with `SINGLE_SOURCE_PENALTY`, most labels generic (`SQL-correlated suspicious event: evt`), optional `llama3.2:1b` reasoning produced unsupported SQL-injection/database narrative and should be treated only as INFERRED containment proof.
- [x] 2026-06-01 Added code fixes for three review risks: SQL correlation finding dedupe, report-level finding dedupe, evidence-derived SQL finding labels, and non-JSON LLM narrative suppression.
- [x] 2026-06-01 Reran selected judge-facing case after these fixes: `BLITZ-RD01-PLASO-R2`, session `/cases/BLITZ-RD01-PLASO/output/sess-20260601T010722Z-40b51cee`, completed with 1,329,652 normalized events, 252 findings, duplicate IDs 0, generic `evt` labels 0, validation passed, and evidence maturity traceability 252/252.
- [x] 2026-06-01 R2 post-fix quality capture copied to host and verified: `Blitz_DFIR_Proof/postfix_session_quality.txt`, SHA256 `753FB447AE7C89BCD827A814A36CBDCCCE612538FCD55F2732455BB540AFD005`.
- [x] 2026-06-01 Added `scripts/blitz_fetch_postfix_proof_archive.ps1` to create the R2 proof archive on SIFT, copy the tar plus `.sha256` sidecar to the host, and verify the host hash before any cleanup or 17G memory intake.
- [x] 2026-06-01 Hardened the SIFT Ollama launcher against operator-facing hangs: `scripts/sift_e2e_ollama_run.sh` now defaults to supervised completion, waits for the launched analysis PID, prints periodic status, enforces `RUN_MAX_WAIT_SECONDS` unless set to `0`, runs VM postrun checks on success, and returns the shell prompt with the analysis exit code. Detached mode remains available through `WAIT_FOR_COMPLETION=0`.
- [x] 2026-06-01 Reduced false active-process detection by removing `blitz_e2e`/`blitz_resume` helper-name matches from status, monitor, cleanup, and stop process patterns; the scripts now match actual analysis/tool processes such as `app.py analyze`, `psort.py`, `log2timeline.py`, `psteal.py`, and `case.plaso`.
- [x] 2026-06-01 Archive and host-verify the current post-trust R3 proof package before deleting SIFT outputs or copying the 17G memory dataset: `Blitz_DFIR_Proof/sess-20260601T113254Z-327c7a6a_postfix_proof_full.tar`, size `9,856,256,000` bytes, SHA256 `1A8BB27CADB13DF89D4E29E8F5FECBBCF2E3CBD524D738720E551BA6B85744D8`, matching the SIFT `.sha256` sidecar.
- [x] 2026-06-02 Added `scripts/sift_clean_remote_proof_archives.sh` so large remote proof archives can be removed with dry-run/apply semantics after host hash verification, while preserving `.sha256` and `.txt` captures by default.
- [ ] 2026-06-02 SIFT `/cases/BLITZ-RD01-PLASO` generated results and remote proof tar archives still need cleanup from inside the SIFT VM because `/cases` is not mounted in this Windows workspace. Keep `case.yaml`, `processed/case.plaso`, run receipts, failed-run receipts, and the Windows host proof archive. Use `APPLY=1 CASE=BLITZ-RD01-PLASO bash scripts/sift_clean_generated_for_rerun.sh` and `APPLY=1 CASE=BLITZ-RD01-PLASO bash scripts/sift_clean_remote_proof_archives.sh` after verifying no active analysis/tool process is running.
- [x] 2026-06-01 Full SQL correlation proof on the latest selected PLASO export is complete: `sql_correlation_completed` scanned all 1,329,652 normalized rows while reports remained bounded.
- [ ] Optional future scale test: run a true 2M-normalized scenario if a selected dataset/export exceeds 1.329M rows and enough VM disk/RAM remains available.
- [ ] Run SIFT verification after deployment: `compileall`, `pytest`, `ruff`, `mypy`, and the bounded 500k stability run.
- [ ] Add stage-level runtime summary output for judge reporting: tool export, parsing, normalization, accounting, correlation, validation, reporting, and artifact hashing.
- [x] Add streaming or SQL-backed correlation before attempting another full 1.3M+ normalized-event report on limited VM memory.
- [ ] Future scale backend option: keep SQL correlation APIs narrow enough to migrate `sqlite_backend.py` to DuckDB if candidate generation or long-horizon aggregation outgrows SQLite.

## 25. Evidence Maturity And Judge Trust Upgrade Proposal

Status: approved and partially implemented as an additive evidence-maturity layer.

Source: 2026-05-31 pasted upgrade note about moving Blitz from engineering maturity to evidence maturity.

Decision principle: Blitz already has substantial architecture. The next highest-value work should prove reliability, repeatability, traceability, and evidence safety instead of adding random parsers, dashboards, UI polish, cloud deployment, authentication, chat changes, or broad new integrations.

- [x] Confirm whether this upgrade package should become the next active implementation track.
- [x] Keep this package aligned with the existing Blitz architecture: typed MCP boundary, evidence manifest, read-only evidence posture, deterministic parsing/normalization, bounded correction, audit logs, reporting, and Protocol SIFT/OpenClaw judge path.
- [x] Do not remove existing working features as part of this package.
- [x] Additive report schema and output-path changes made: per-finding explainability, `findings/evidence_maturity.json`, and `reports/evidence_maturity.md`.
- [x] Treat partial smoke tests and interrupted runs as engineering validation only, not final accuracy evidence.

### 25A. Highest-ROI Upgrade Candidates

- [x] Upgrade candidate 1: full investigation traceability chain from finding to evidence reference, normalized record, parser result, tool output, tool execution, and audit entry.
- [x] Upgrade candidate 2: coverage analysis that shows what Blitz analyzed and what it could not analyze, including unsupported, corrupted, encrypted, missing, timed-out, degraded, or skipped evidence zones.
- [x] Upgrade candidate 3: evidence spoliation protection demo that attempts evidence mutation, denies or prevents it, logs the attempt, and proves original evidence hashes remain unchanged.
- [ ] Upgrade candidate 4: real case walkthrough using one coherent investigation story: initial access, persistence, beaconing or network activity, credential activity if present, timeline, findings, and report.
- [x] Upgrade candidate 4 scaffold: `docs/REAL_CASE_WALKTHROUGH.md` added; actual real-case content remains pending until a selected dataset run completes.
- [x] Upgrade candidate 5: explainability layer for every finding: why it was flagged, which artifacts support it, which tools produced it, confidence, confidence modifiers, and limitations.

### 25B. Evidence Package For Submission Credibility

- [ ] Produce a real-case validation run against documented data, not synthetic-only smoke evidence.
- [ ] Produce an accuracy report with dataset, ground truth or analyst expectations, true positives, false positives, false negatives, unsupported/hallucinated claims, and limitations.
- [ ] Produce dataset documentation with source/license, artifact types, hashes where practical, exact commands, environment, and reproducibility notes.
- [x] Produce repeatability matrix scaffold showing completion status, row counts, normalized counts, warnings, timeouts, and report paths.
- [x] Document agent execution log requirements with timestamps, tool-call sequence, model/provider metadata where available, token usage where available, and self-correction iteration traces.
- [x] Produce demo video flow that emphasizes proof: real data, typed tool execution, self-correction, traceability, coverage/unknowns, evidence hash before/after, and final report.

### 25C. Recommended Priority Order

- [ ] Tier 1: real-case validation, accuracy report, dataset documentation, full traceability chain, and demo video.
- [ ] Tier 2: spoliation demo, repeatability matrix, agent execution logs, and coverage analysis hardening.
- [ ] Tier 3: additional parsers, integrations, dashboards, UI improvements, multi-user features, cloud deployment, authentication systems, and chat enhancements.

### 25D. Acceptance Criteria Before Calling This Complete

- [x] A judge can pick any finding and trace it back to specific evidence, normalized events, parser output, tool execution, and audit log entry where session-produced tool output exists.
- [x] Reports clearly distinguish confirmed evidence-backed findings from inferred reasoning and unknown zones.
- [ ] Accuracy claims are backed by dataset documentation and repeatable commands.
- [x] Evidence hash before/after checks are visible in the demo or attached proof artifacts.
- [ ] Self-correction is demonstrated on real or representative data with before/after improvement or honest unresolved limitation.
- [x] Known limitations are documented plainly instead of hidden.
- [x] 2026-05-31 Evidence maturity local verification passed: full `pytest`, `compileall`, `ruff`, `mypy`, and `pip-audit` passed.
- [x] 2026-05-31 Spoliation demo runtime passed locally: mutation request rejected and source evidence SHA256 remained unchanged before analysis, after analysis, and after rejected mutation attempt.
- [ ] Final submission still requires running the evidence maturity package on selected real or representative case data and filling dataset, accuracy, repeatability, real walkthrough, and agent-log artifacts.

## 26. Adversarial Layer Evaluation Track

Status: deferred until the current final test finishes, then recommended as the next proof-hardening workstream.

Purpose: prove every Blitz layer with either adversarial failure-injection scenarios or a defensible alternative proof where adversarial testing is not the right method.

Source: 2026-05-31 discussion about creating known-ground-truth failure scenarios for correlation, confidence, reasoning, self-correction, and all supporting layers.

Decision principle: Synthetic adversarial scenarios are acceptable and valuable for layer validation, but they must not be represented as real-world DFIR accuracy evidence. Final accuracy still requires real/reference data, hashes, repeatability, expected results, false positives, missed artifacts, unsupported claims, and documented limitations.

- [x] Record the all-layer adversarial proof plan in `docs/ADVERSARIAL_EVALUATION_PLAN.md`.
- [x] Link the adversarial proof track from `docs/JUDGE_LAYER_PROOF_CHECKLIST.md`.
- [x] Require every architecture layer to have a proof path, not only correlation, confidence, reasoning, and self-correction.
- [x] Define alternative proof types for layers where adversarial evidence is a weak fit: deterministic invariant tests, boundary rejection tests, traceability proof, repeatability proof, operator logs, artifact hashes, and real/reference dataset proof.
- [x] Add four proof levels to the plan: functional/manual, adversarial/failure-injection, representative DFIR dataset, and full investigation scenario.
- [x] Add fixture and antivirus safety rules: avoid real malware, prefer inert text/structured outputs, isolate any harmless AV-detected test artifact, and do not require AV-detected fixtures for the normal judge path.
- [ ] After the current final test, create `evals/scenarios/` with scenario YAML files grouped by layer family.
- [ ] Add fixtures under `evals/fixtures/` with clear labels that they are synthetic/adversarial and not real case evidence.
- [ ] Add `scripts/run_adversarial_evals.py` to execute scenario definitions and produce machine-readable results.
- [ ] Add adversarial tests for correlation: missing memory, EVTX time shift, network activity after process exit, contradictory lineage, parser-truncated process names, out-of-order events, duplicate events, and benign lookalikes.
- [ ] Add adversarial tests for confidence: single-source penalty, multi-source agreement boost, parser warning penalty, timeout penalty, hash-mismatch penalty, coverage-gap penalty, contradiction penalty, and unknown-zone penalty.
- [ ] Add adversarial tests for reasoning: prompt injection in evidence, unsupported hypothesis, overconfident language, invalid/fenced JSON, request to mutate evidence, invented tool request, and attempted raw-evidence exfiltration.
- [ ] Add adversarial tests for self-correction: approved triggers only, scoped action selection, retry cap, unapproved tool-chain rejection, failed correction remaining low-confidence, and correction-history audit/report visibility.
- [ ] Add adversarial or alternative proof for evidence integrity, typed MCP, controlled execution, tool adapters, batch planning, tool discovery, evidence inventory, recovery planner, parser validation, sanitization, signal integrity, coverage, normalization, SQLite normalization, full accounting, object inventory, reporting, evidence maturity, audit hardening, session integrity, stress reporting, and private-provider exclusion.
- [ ] Ensure each scenario states base ground truth, mutation, expected finding behavior, expected warnings/unknowns/contradictions, expected confidence modifiers/range, required artifacts, and pass/fail assertions.
- [ ] Ensure every scenario result is repeatable and produces a proof artifact that can be shown to judges.
- [ ] Add a judge-facing adversarial evaluation summary that separates layer-validation proof from real/reference dataset accuracy proof.
- [ ] Do not claim all layers are dependable as a blanket statement; claim specific tested behavior per layer and show the artifact.

## 27. Two-Week Submission Test Completion Track

Status: active after successful PLASO proof run.

Purpose: use the remaining submission window for proof packaging, selected dataset validation, minimal adversarial layer tests, and demo readiness instead of broad feature expansion.

Source: 2026-06-01 discussion after completed SIFT proof run and proposed pure-memory dataset.

- [x] Create `docs/TWO_WEEK_TEST_COMPLETION_PLAN.md` with priority order, memory intake requirements, and two-week schedule.
- [x] Record `BLITZ-MEMORY-001` as a candidate dataset in `docs/DATASETS.md`.
- [x] Update `docs/SUBMISSION_CHECKLIST.md` to reflect that a large SIFT proof run completed, while exact command/artifact archive/hash values/accuracy scoring remain pending.
- [x] Preserve PLASO proof run artifacts from SIFT: `audit/`, `findings/`, `reports/`, `timelines/`, and `psort-*.log.gz`.
- [x] Capture exact command or launcher environment from `/cases/BLITZ-RD01-PLASO/analysis/runs/20260531T202550Z`.
- [x] Capture explicit source evidence hash before/after values.
- [x] Inspect parser progress mismatch: `Parser result extraction (0/1)` versus `parser_results=1`.
- [ ] Run and preserve final SIFT quality gates: `pytest`, `compileall`, `ruff`, `mypy`, and `pip-audit`.
- [ ] Document dataset source/license/permission and ground truth or analyst expectations.
- [x] Complete preliminary mechanical review of PLASO findings for duplicates, confidence, labels, traceability, warning/unknown context, and reasoning quality.
- [ ] Review representative PLASO findings against ground truth or analyst expectations for true positives, false positives, unknowns, misses, unsupported claims, and limitations.
- [ ] Fill `docs/ACCURACY_REPORT.md` with reviewed results.
- [ ] Fill `docs/REAL_CASE_WALKTHROUGH.md` with evidence-backed investigation story.
- [ ] Intake memory file details: path, SHA256, size, OS/acquisition notes if known, source/permission, and expected findings or analyst expectations.
- [ ] Run memory dataset through typed Volatility route if intake checks pass.
- [ ] Decide whether memory result is demo-supporting evidence, engineering validation, or deferred due to tool/profile limitations.
- [ ] Build minimal adversarial layer suite for MCP rejection, prompt injection, confidence penalties, correlation contradiction, self-correction, and evidence maturity negative trace.
- [ ] Select final demo path and record exact artifacts to show.
- [ ] Avoid nonessential features, dashboards, broad parser expansion, cloud features, auth systems, and unplanned refactors during the remaining window.

## 28. Evidence-First Case Objective, Investigation Planning, And Evidence Triage

Status: implemented locally; SIFT proof run pending.

Purpose: keep Blitz aligned to DFIR evidence rather than SOC alert handling. The case objective guides prioritization, but manifest-verified evidence remains the authority.

- [x] Remove the active alert-intake/trigger overlay from the code path because it no longer matches the evidence-first architecture.
- [x] Remove optional `--alert`, `ALERT_PATH`, alert helper script, alert package, and alert-specific tests.
- [x] Add optional `--case-objective` CLI input and `CASE_OBJECTIVE` SIFT launcher support.
- [x] Add `findings/case_objective.json` and `reports/case_objective.md` with objective, success criteria, constraints, and evidence IDs in scope.
- [x] Add `findings/investigation_plan.json` and `reports/investigation_plan.md` with evidence-first phases and prioritized artifact families.
- [x] Feed investigation-plan artifact-family priority into batch planning without bypassing manifest hashes, tool allowlists, parser validation, correlation, confidence, or evidence maturity.
- [x] Add `findings/evidence_triage.json` and `reports/evidence_triage.md` with per-evidence priority, tool status, resource risk, and recovery limitations.
- [x] Add case objective, investigation plan, and evidence triage sections to JSON, Markdown, and HTML reports.
- [x] Add progress/monitor layers: `case_objective`, `investigation_planning`, and `evidence_triage`.
- [x] Update postrun/E2E checks for case objective, investigation planning, evidence triage, report sections, and audit events.
- [x] Update monitor readiness so report, LLM, safety, trust artifacts, audit attribution, postrun checks, case objective, investigation priorities, and evidence triage are independently visible.
- [x] Keep high-volume stress capability after the refactor: normalized cap supports 5M, psort filter can be disabled for full PLASO export, and the stress ladder records 1M/2M/3M/4M/5M target verification.
- [x] Add clean SIFT deployment helper: `scripts/blitz_clean_deploy_to_sift.ps1`.
- [ ] Sync clean code to SIFT and run compile/pytest there.
- [ ] Run one evidence-first `BLITZ-RD01-PLASO` proof pass and preserve `case_objective`, `investigation_plan`, `evidence_triage`, progress, postrun checks, and archive hash.
- [ ] Rerun EVTX-focused evidence before the high-volume stress ladder and before the 17G memory dataset.
- [ ] Run the 1M/2M/3M/4M/5M stress ladder only after the evidence-first proof pass is verified and SIFT disk space is clean.
- [ ] Run or defer the 17G memory dataset based on available disk, Volatility profile support, and bounded memory-tool output.

## 29. Memory Triage, Investigation Guidance, Reporting Sync, And SIFT Refresh

Status: implemented locally; fresh SIFT deployment and memory proof run pending.

Purpose: keep the upgraded Blitz flow aligned from typed Volatility execution through investigation guidance, truth-validation reporting, progress monitoring, and SIFT redeployment without deleting raw memory evidence.

- [x] Pin Volatility symbols in the package configuration to `/cases/volatility_symbols`.
- [x] Keep the SIFT memory runner preflight strict: fail before analysis if `case.yaml`, `config/tools.yaml`, the Python environment, disk space, or writable Volatility symbols are missing.
- [x] Expand default memory triage beyond `windows.pslist` and `windows.pstree` to include `windows.cmdline`, `windows.psscan`, `windows.netscan`, and `windows.malfind`.
- [x] Normalize Volatility memory rows into process, process tree, command line, network flow, scan, and injection-candidate categories instead of generic Blitz-run metadata.
- [x] Treat memory triage as coverage-bounded analysis: missing or failed plugins become unknowns/coverage gaps, not proof that the memory image is clean.
- [x] Add investigation guidance artifacts and report sections: `findings/investigation_guidance.json`, JSON report section, Markdown report section, and HTML report section.
- [x] Add truth-validation report synchronization with default `status: not_run` when no truth dataset is supplied.
- [x] Add investigation guidance to `audit/progress.json` as its own operator-visible layer after correlation and before evidentiary weighting.
- [x] Sync `scripts/blitz_status.sh` progress reconstruction, readiness checks, review map, and artifact list with investigation guidance and truth validation.
- [x] Update postrun/E2E checks to require the investigation guidance artifact, report section, audit event, and progress layer.
- [x] Document SIFT Volatility symbols and memory triage limitations in `README.md`.
- [x] Fix stdout-primary tool output preservation after SIFT verification showed `windows.pstree` JSON was truncated at the 1 MiB sandbox capture boundary.
- [x] Keep bounded stdout/stderr API captures for safety while preserving full stdout to the primary output file for stdout-producing forensic tools.
- [x] Make tool stdout/stderr sidecar filenames unique per primary output so multi-plugin Volatility runs do not overwrite earlier plugin sidecars.
- [x] Treat memory-run postrun checks as explicitly not configured when the deterministic memory runner completes, instead of reporting `postrun=UNKNOWN` or implying skipped evidence processing.
- [x] Add full-accounting support for JSON primary tool outputs so Volatility plugin rows are accounted in `event_rows`, not only normalized into `normalized_events`.
- [x] Downgrade stress-report zero full-accounting rows to `needs_review` when normalized rows exist, while still failing true zero-output runs.
- [x] Add temporal gap analysis artifacts: `findings/temporal_gap_analysis.json`, `reports/temporal_gap_analysis.md`, and synced report JSON/Markdown/HTML sections.
- [x] Add attack-stage timeline artifacts: `findings/attack_stage_timeline.json`, `reports/attack_stage_timeline.md`, and synced report JSON/Markdown/HTML sections.
- [x] Add post-LLM report verification gate: `findings/llm_report_verification.json`, `reports/llm_report_verification.md`, report section, and explicit `not_run` receipt for no-LLM runs.
- [x] Add `temporal_analysis` and `llm_report_verification` to the progress/status contract and review map.
- [x] Separate clean-start and continuation commands for SIFT memory testing: default runners use `RUN_MODE=clean`; resume wrappers require explicit `RESUME_SESSION`.
- [x] Add dedicated Rocba C-drive E01 clean test runner: `scripts/sift_rocba_e01_clean_run.sh`, defaulting to in-place analysis of `/home/sansforensics/Desktop/cases/Rocba-E01/rocba-cdrive.e01`, with optional copy mode and E01 disk-space guards.
- [x] Add external evidence manifest mode (`evidence_root: external`) so judges/users can reference raw evidence from any absolute path without copying it into `/cases`.
- [x] Add dedicated Rocba memory plus E01 clean runners: `scripts/sift_rocba_memory_e01_clean_run.sh`, `scripts/sift_rocba_memory_e01_no_llm_clean_run.sh`, and `scripts/sift_rocba_memory_e01_ollama_clean_run.sh`, using external absolute evidence paths, SHA256 verification against real SIFT paths, and argument-array execution to avoid fragile pasted line continuations.
- [x] Add collated-output layer that writes judge-facing rollups: `findings/overall_findings.md`, `reports/overall_reports.md`, and `audit/collated_audit.md`.
- [x] Add generic judge/user external-evidence runners: `scripts/sift_run_external_evidence.sh`, `scripts/sift_run_external_evidence_no_llm.sh`, and `scripts/sift_run_external_evidence_ollama.sh`, where users provide one or two evidence paths and evidence types without copying raw data.
- [x] Harden E01 log2timeline execution for automation by adding a dedicated logfile plus `--partitions all`, `--vss_stores none`, and `--unattended` for first-pass E01/DD sources, with `BLITZ_LOG2TIMELINE_VSS_STORES` available for explicit advanced VSS retries.
- [x] Add `scripts/sift_e01_timeline_diagnostics.sh` to inspect E01 timeline failures, tool versions, stderr, gzip Plaso logs, manifest E01 paths, and segment visibility.
- [x] Add deterministic agent trace and journal layer: `findings/agent_trace.json` and `reports/agent_journal.md`, with objective, observations, hypotheses, plan changes, fallback decisions, validation, unknowns, and finding-to-tool trace without raw evidence or raw tool output.
- [x] Add audit events for adaptive investigation decisions: `hypothesis_formed`, `plan_change`, and `investigation_guidance_completed`.
- [x] Add read-only MCP review tools: `get_status`, `get_findings`, `get_unknowns`, `get_agent_trace`, and `get_artifact_manifest`.
- [ ] Deploy refreshed code to SIFT without deleting `/cases/BLITZ-ROCBA-MEMORY/raw`.
- [ ] Run deterministic memory analysis first: `CASE=BLITZ-ROCBA-MEMORY bash scripts/sift_memory_no_llm_run.sh`.
- [ ] Inspect `findings/overall_findings.md`, `reports/overall_reports.md`, `audit/collated_audit.md`, `reports/report.json`, `reports/report.html`, `findings/investigation_guidance.json`, `findings/temporal_gap_analysis.json`, `findings/attack_stage_timeline.json`, `findings/llm_report_verification.json`, `findings/unknowns.json`, `findings/validation.json`, and `findings/artifact_manifest.json`.
- [ ] Run bounded Ollama memory analysis only after the no-LLM run is mechanically healthy.

Current upgraded progress layer contract:

```text
[ ] Manifest and evidence integrity
[ ] Protocol SIFT workflow context
[ ] Case objective definition
[ ] Tool discovery
[ ] Investigation planning
[ ] Batch planning
[ ] Evidence inventory
[ ] Recovery planning
[ ] Evidence triage
[ ] Typed SIFT tool execution
[ ] Parser result extraction
[ ] SQLite-backed normalization
[ ] Object inventory
[ ] Full accounting
[ ] SQLite event store
[ ] Correlation and suspicion scoring
[ ] Investigation guidance
[ ] Temporal gap and attack-stage timeline
[ ] Evidentiary weighting
[ ] Evidence contradiction analysis
[ ] Validation
[ ] Unknowns and coverage
[ ] Bounded LLM reasoning over validated summaries
[ ] LLM report verification
[ ] Report generation
[ ] Evidence maturity traceability
[ ] Agent trace and investigative journal
[ ] Overall findings, reports, and collated audit
[ ] Audit finalization and artifact hashes
```
