# Blitz DFIR - One Source of Truth

Version: SSOT v2.1 + Find Evil submission alignment
Status: Current authoritative architecture
Updated: 2026-05-24
Target: SANS SIFT / Find Evil Hackathon
Architecture Mode: Evidence-safe autonomous DFIR reasoning system

This file supersedes earlier draft notes, architecture conversations, and older SSOT wording. If any older document, chat note, or draft conflicts with this file, this file wins.

Important source reconciliation:

- `Blitz_DFIR_SSOT_v2.docx` and `Blitz_DFIR_SSOT_v2.1.docx` are identical by SHA256 and extracted text.
- `Blitz_DFIR_SSOT_v2.1.docx` remains the control document for the system architecture.
- `Blitz_DFIR_IMPLEMENTATION_CHECKLIST.md` is the execution checklist and phase tracker.
- Devpost / Find Evil requirements are submission gates and must be satisfied before delivery.

## 1. Mission

Blitz DFIR exists to improve Protocol SIFT for the Find Evil hackathon by making autonomous DFIR analysis safer, more deterministic, more auditable, and less prone to hallucination.

The system must teach an AI-enabled responder to behave like a senior analyst:

- sequence the investigation intelligently
- recognize when evidence does not add up
- self-correct through bounded validation
- preserve original evidence
- produce traceable findings
- report uncertainty honestly

Blitz DFIR is not a generic chatbot, not an autonomous cyber AGI platform, not an EDR, not a SIEM, and not an auto-remediation engine.

Core positioning:

> Blitz DFIR is a Protocol SIFT-compatible controlled forensic reasoning layer that uses typed MCP boundaries, deterministic parsing, evidence-safe correlation, bounded self-correction, and auditable reporting to help responders find evil at machine speed without sacrificing forensic discipline.

## 2. Hackathon Submission Target

The Find Evil challenge requires software that improves how Protocol SIFT processes case data on the SANS SIFT Workstation.

Required submission outcomes:

- improve autonomous incident response execution
- reduce hallucinated findings compared with weak agent-to-shell workflows
- support real case data, not toy-only examples
- demonstrate at least one self-correction sequence
- preserve evidence integrity
- provide structured execution logs
- make findings traceable to tool execution
- document accuracy, false positives, missed artifacts, and hallucinated claims

Required Devpost artifacts:

- public GitHub repository
- MIT or Apache 2.0 license
- demo video, 5 minutes max target, showing live terminal execution
- architecture diagram
- written project description
- dataset documentation
- accuracy report
- try-it-out instructions
- agent execution logs

Judging criteria that Blitz must optimize for:

- autonomous execution quality
- IR accuracy
- breadth and depth of analysis
- constraint implementation
- audit trail quality
- usability and documentation

Autonomous execution quality is especially important because it is the hackathon tiebreaker.

## 3. Selected Architecture

Primary architecture pattern:

- Custom MCP Server
- Protocol SIFT-compatible agent integration
- OpenClaw as the primary judge-facing agent path
- Provider-agnostic LLM inference through an OpenAI-compatible adapter
- Typed, allowlisted DFIR functions
- Deterministic pipeline behind the MCP boundary

This is the strongest fit for Blitz because it creates architectural guardrails instead of relying only on prompts.

The LLM provider is not the agent framework. This matters for hackathon alignment: the judge-facing autonomous workflow must still run through OpenClaw, Protocol SIFT, Claude Code, or the documented compatible agent path. Any private model provider supplies inference behind that workflow only.

Provider strategy:

- implement a provider-agnostic LLM adapter
- keep the public hackathon build provider-neutral
- allow private local testing with an authorized OpenAI-compatible provider
- keep provider configuration outside source control
- support provider replacement without changing evidence, parsing, normalization, correlation, or audit logic

Cloud-provider safety rule:

- never send raw evidence, raw stdout, raw CSV/JSON dumps, memory strings, or sensitive local paths to any cloud model
- send only bounded normalized summaries, structured findings, contradictions, confidence scores, and coverage summaries
- record model/provider metadata and token usage where available
- disclose in documentation that a cloud inference provider is used for reasoning
- for sensitive real-world cases, support replacing any cloud provider with a local or private provider
- do not make the public repo depend on a private provider subscription or hardcoded API key
- capture the final demo, logs, and accuracy report with an account that remains available through submission

Blitz should not expose a generic shell command tool to the agent. Instead, expose typed functions such as:

- run timeline extraction
- run psort extraction
- run memory triage
- run EVTX analysis
- run YARA scan
- run strings scan
- retrieve normalized findings
- retrieve confidence and coverage summary

The agent may reason about next steps and request approved typed actions. The dispatcher, schema validators, allowlists, resource limits, and correction engine decide what actually executes.

This distinction is critical:

- Allowed: bounded autonomous reasoning and typed action requests.
- Forbidden: LLM-controlled arbitrary execution.

## 4. Protocol SIFT Integration

Blitz must integrate with Protocol SIFT. It must not replace SIFT or claim to be SIFT.

Correct relationship:

Agent framework
-> Protocol SIFT or Blitz MCP server
-> controlled typed tool boundary
-> SIFT tools
-> bounded parsers
-> normalization
-> correlation
-> validation
-> reporting and audit

Current intended judge-facing path:

- SANS SIFT Workstation as the execution environment
- Protocol SIFT installed or available
- OpenClaw as the primary agentic interface
- Claude Code, OpenClaw, or an authorized provider-neutral agent path for LLM-driven reasoning
- Claude Code compatibility documented as a secondary path because Protocol SIFT is Claude Code-oriented
- Blitz MCP server as the controlled typed boundary

Protocol SIFT-specific requirements:

- document the exact tested Protocol SIFT install method
- document the case-directory workflow
- document how OpenClaw connects to Blitz
- document Claude Code compatibility limits and fallback path
- document whether Blitz is a case-local MCP server, companion server, or Protocol SIFT workflow extension
- do not overwrite Protocol SIFT global files without backup instructions
- do not broaden Protocol SIFT write permissions into evidence directories
- preserve Protocol SIFT guardrails while enforcing Blitz's own allowlist and evidence protections
- provide a smoke test proving the selected agent can call Blitz typed tools

Known Protocol SIFT layout to document during implementation:

- `~/.claude/CLAUDE.md`
- `~/.claude/settings.json`
- `~/.claude/settings.local.json`
- `~/.claude/skills/`
- case templates
- analysis scripts

## 5. Non-Negotiable Rules

These are hard architectural rules.

- Typed MCP execution is required.
- Evidence manifest is required.
- Allowlist-only tools are required.
- Read-only evidence enforcement is required.
- Deterministic normalization is required.
- Structured findings with evidence references are required.
- Deterministic confidence scoring is required.
- Validation-driven self-correction is required.
- Audit logs are required.
- Parser validation and signal integrity are required.
- Sanitization boundary is required.
- RAW / DERIVED / INFERRED separation is required.
- Coverage scoring is required.
- Sandbox execution for tools and parsers is required.

Forbidden:

- arbitrary shell execution
- `shell=True`
- dynamic AI script generation
- dynamic AI command generation
- evidence mutation
- auto-remediation
- unbounded retries
- self-modifying logic
- raw tool stdout sent directly to the LLM
- LLM controlling execution flow
- absolute truth claims such as "confirmed beyond doubt"
- silent evidence truncation

Constants:

- `MAX_RETRIES = 2`
- `MAX_CORRECTIONS = 2`
- `TOOL_TIMEOUT = 300`
- `MAX_EVENTS = 5000`
- `MAX_FIELD_LENGTH = 2048`
- evidence access mode is read-only
- audit log format is `.ndjson`
- HTML output must use escaping, preferably Jinja2 `autoescape=True`

## 6. Evidence Trust Model

Blitz treats evidence as evidence candidates, never as absolute truth.

Trust tiers:

- Tier 1: RAW evidence processed internally by Blitz. Highest trust.
- Tier 2: DERIVED evidence generated internally by Blitz. Medium-high trust.
- Tier 3: external processed evidence such as uploaded `.plaso`, CSV, or JSON. Low trust.
- Tier 4: INFERRED LLM reasoning. Very low trust and never evidence.

Evidence categories must remain separate:

- RAW: original evidence such as E01, EVTX, memory, registry hives, PCAP, filesystem artifacts.
- DERIVED: parser or tool output such as `.plaso`, CSV extracts, psort output, normalized artifacts.
- INFERRED: analyst reasoning, hypotheses, narrative, and conclusions.

A `.plaso` file is DERIVED evidence, not ground truth. If Blitz generated it internally, trust is higher than if it was externally uploaded. External processed data must be treated as untrusted until validated, sanitized, normalized, and cross-checked.

## 7. Input Pipelines

Blitz has two input pipelines.

Raw evidence pipeline:

1. Evidence input
2. Evidence integrity layer
3. Evidence validation
4. Controlled MCP boundary
5. Sandboxed SIFT tool execution
6. Bounded parsing layer
7. Sanitization boundary
8. Signal integrity and coverage layer
9. Deterministic normalization
10. Correlation engine
11. Analyst reasoning layer
12. Validation and self-correction engine
13. Reporting and audit layer

Processed evidence pipeline:

1. Processed evidence input
2. Integrity verification
3. Evidence classification
4. Sanitization boundary
5. Structured validation
6. Controlled extraction
7. Signal integrity and coverage layer
8. Normalization through audit, identical to the raw pipeline from normalization forward

Supported raw inputs:

- E01
- DD
- raw memory
- EVTX
- PCAP
- registry hives
- filesystem artifacts

Supported processed inputs:

- `.plaso`
- CSV timelines
- JSON exports
- preprocessed EVTX
- third-party parser exports

PCAP note:

PCAP support is approved for MVP. It must still follow the same controlled-execution model: typed adapter, allowlisted tool, sandboxed subprocess, bounded output, parser validation, normalization, signal warnings, and confidence penalties. Preferred scope is practical PCAP triage with `tshark` first and optional Zeek support if it is available on the tested SIFT image. PCAP depth must not weaken evidence integrity or delay the core pipeline.

## 8. Repository Structure

Target repository structure:

```text
blitz_dfir/
|-- app.py
|-- pyproject.toml
|-- requirements.txt
|-- README.md
|-- LICENSE
|-- .env.example
|-- config/
|   |-- settings.yaml
|   |-- tools.yaml
|   `-- scoring.yaml
|-- core/
|   |-- session.py
|   |-- evidence.py
|   |-- manifest.py
|   |-- integrity.py
|   |-- validation.py
|   `-- normalization.py
|-- mcp/
|   |-- server.py
|   |-- dispatcher.py
|   |-- allowlist.py
|   `-- tool_registry.py
|-- sandbox/
|   |-- runner.py
|   |-- limits.py
|   `-- user_isolation.py
|-- tools/
|   |-- log2timeline_tool.py
|   |-- psort_tool.py
|   |-- volatility_tool.py
|   |-- chainsaw_tool.py
|   |-- pcap_tool.py
|   |-- yara_tool.py
|   `-- strings_tool.py
|-- parsers/
|   |-- evtx_parser.py
|   |-- plaso_parser.py
|   |-- volatility_parser.py
|   |-- pcap_parser.py
|   |-- yara_parser.py
|   `-- parser_validation.py
|-- sanitization/
|   |-- sanitizer.py
|   |-- schema_enforcer.py
|   `-- provenance.py
|-- signal/
|   |-- integrity.py
|   |-- warnings.py
|   `-- coverage.py
|-- correlation/
|   |-- timeline.py
|   |-- lineage.py
|   |-- persistence.py
|   |-- attack_chain.py
|   `-- confidence.py
|-- reasoning/
|   |-- analyst.py
|   |-- narrative.py
|   |-- hypotheses.py
|   `-- contradiction.py
|-- correction/
|   |-- validator.py
|   |-- rerun_engine.py
|   |-- triggers.py
|   `-- bounded_retry.py
|-- reporting/
|   |-- findings.py
|   |-- report_builder.py
|   |-- html_export.py
|   |-- markdown_export.py
|   `-- templates/
|-- audit/
|   |-- audit_log.py
|   |-- execution_trace.py
|   `-- integrity_log.py
|-- docs/
|   |-- ARCHITECTURE.md
|   |-- DEMO_SCRIPT.md
|   |-- ACCURACY_REPORT.md
|   |-- DATASETS.md
|   |-- JUDGE_QA.md
|   |-- PROTOCOL_SIFT_INTEGRATION.md
|   |-- SPOLIATION_TESTING.md
|   `-- SUBMISSION_CHECKLIST.md
|-- tests/
|   |-- test_validation.py
|   |-- test_correlation.py
|   |-- test_integrity.py
|   |-- test_self_correction.py
|   `-- test_reporting.py
`-- output/
    |-- reports/
    |-- audit/
    |-- findings/
    `-- timelines/
```

Do not commit a real `.env`. Use `.env.example` and `.gitignore`.

## 9. Implementation Order

Do not start with the AI layer.

Phase 1: Foundation

- manifest
- integrity hashing
- evidence read-only enforcement
- audit log skeleton
- normalization schemas

Phase 2: Sandbox and MCP

- sandboxed subprocess wrapper
- tool allowlist
- MCP dispatcher
- typed tool registry
- Protocol SIFT-compatible server launch path

Phase 3: Tool adapters

- log2timeline
- psort
- volatility
- chainsaw
- pcap / tshark
- yara
- strings

Phase 4: Parsers and sanitization

- Plaso parser
- EVTX parser
- Volatility parser
- PCAP parser
- YARA parser
- strings parsing if used in findings
- sanitization boundary
- schema enforcement

Phase 5: Signal integrity

- coverage scoring
- truncation tracking
- timeout tracking
- parser warning tracking
- warning object generation

Phase 6: Normalization

- canonical artifact model
- deterministic timestamp/path/user/hash normalization
- stable event IDs

Phase 7: Correlation

- timeline reconstruction
- lineage mapping
- persistence detection
- attack-chain reconstruction
- multi-source agreement scoring

Phase 8: Reasoning

- hypothesis generation
- contradiction explanation
- narrative generation
- analyst-training transparency

Phase 9: Validation and correction

- confidence scoring
- evidence support validation
- bounded rerun
- scoped recovery
- correction history

Phase 10: Reporting

- HTML
- Markdown
- JSON findings
- evidence credibility section
- coverage
- unknown zones
- self-correction logs

Phase 11: Audit hardening

- execution trace
- `.ndjson`
- tamper-evident hash chain
- token usage where available
- agent decisions where available

## 10. Confidence And Correction

Confidence is deterministic. Never use "AI thinks maybe suspicious" as a confidence basis.

Confidence inputs:

- artifact support
- temporal consistency
- parser quality
- cross-source validation
- multi-tool agreement
- contradiction penalty
- signal degradation penalty

Valid correction triggers:

- missing evidence
- broken lineage
- low confidence
- parser degradation
- signal loss
- timeline gaps
- contradictions
- contradiction count above threshold

Allowed scoped recovery actions:

- narrow time range extraction
- specific Volatility plugin only
- filtered strings extraction
- scoped psort filtering
- chunked extraction
- alternate parser fallback
- fallback correlation from available sources

Forbidden correction behavior:

- recursive autonomy
- infinite loops
- tool discovery
- script generation
- full uncontrolled reruns

## 11. Reporting Requirements

Required outputs:

- HTML
- Markdown
- JSON findings
- audit logs

Every finding must include:

- finding text
- evidence source
- source tool
- parser
- parser version
- timestamp
- confidence
- confidence modifiers
- correlation path
- evidence type
- recovery notes

Every report must include:

- findings
- evidence references
- timeline
- confidence
- contradictions
- self-correction logs
- audit trail
- evidence credibility assessment
- coverage scoring
- unknown zones / analysis gaps
- global case trust score

Approved language:

- "Evidence strongly supports"
- "High-confidence reconstruction suggests"
- "Coverage X percent; analysis gaps documented"
- "Tool output is an evidence candidate"

Forbidden language:

- "Confirmed beyond doubt"
- "Definitively malicious"
- "I analyzed everything"
- "Tool output proves"
- "Certain"
- "Guaranteed"

## 12. Audit Requirements

Audit logs must be deterministic, structured, and traceable.

Execution trace records:

- session ID
- correlation ID
- tool name
- tool version
- tool hash
- timestamp in ISO 8601 UTC
- sanitized arguments
- duration
- output hash
- exit code
- warnings

Session audit records:

- rerun triggers
- validation failures
- parser warnings
- correction actions
- correction outcomes
- integrity checks
- confidence adjustments
- coverage scores
- agent decisions where available
- token usage where available

Audit integrity:

- store logs as `.ndjson`
- hash every entry
- chain each hash to the previous entry
- make tampering visible
- do not claim tampering is impossible

## 13. Test And Validation Gates

Required test areas:

- manifest validation
- evidence path safety
- SHA256 verification
- read-only enforcement
- allowlist dispatcher
- sandbox runner
- tool adapters
- parser validation
- sanitization
- normalization determinism
- confidence scoring
- correlation logic
- contradiction detection
- bounded retry enforcement
- report schema
- audit hash chain
- Protocol SIFT / agent integration
- generic shell command exposure bypass
- spoliation test
- prompt-only guardrail bypass
- benchmark against known-good data

Required validation datasets:

- E01 or DD image
- memory image
- EVTX
- registry hives
- `.plaso` timeline
- malformed evidence
- partial corruption case
- missing artifact case
- high-volume truncation case
- timeout simulation
- prompt-injection-in-evidence case
- contradictory evidence case
- known-good ground truth case

## 14. Deferred Or Rejected Scope

Do not add unless explicitly approved:

- Kubernetes
- blockchain
- eBPF observability
- SIEM integrations
- autonomous remediation
- dynamic AI scripting
- LangChain mega-stack
- multi-agent swarms
- graph databases
- vector memory
- deep learning
- reinforcement learning
- distributed orchestration
- runtime telemetry infrastructure
- enterprise-scale zero-trust mesh
- kernel anti-tamper
- full deep PCAP reconstruction beyond bounded triage
- live endpoint or SIEM triage

## 15. Decisions Before Implementation

Closed decisions:

- Judge-facing agent path: OpenClaw primary.
- LLM provider: provider-neutral through an OpenAI-compatible provider adapter where applicable.
- Provider strategy: provider-agnostic adapter, so private/local/cloud providers can be swapped without changing DFIR logic.
- PCAP support: implement now for MVP with bounded `tshark`-first triage and optional Zeek if available.
- Claude Code: document compatibility as a secondary path because Protocol SIFT is Claude Code-oriented.

Remaining decisions:

- Final demo provider/model selection.
- Tool hash baseline storage: `config/tools.yaml` or signed external manifest.
- Sample datasets: which can be bundled, linked, or documented for judges.

Recommended defaults:

- Choose a strong code/reasoning model with adequate context and stable latency.
- Tool hash baselines in `config/tools.yaml` for the hackathon version.

## 16. Final Success Condition

Blitz DFIR succeeds when a judge can:

1. Install or run it on SANS SIFT.
2. Connect it through Protocol SIFT or the documented agent path.
3. Run a real case analysis.
4. See evidence verified read-only.
5. See tools executed through typed, bounded functions.
6. See raw tool output parsed, sanitized, normalized, and correlated before reasoning.
7. See a contradiction, gap, or low-confidence issue trigger bounded self-correction.
8. Trace every finding back to specific tool execution and evidence references.
9. Review coverage, unknown zones, confidence modifiers, and audit logs.
10. Reproduce the result without trusting prompt promises alone.

This is the standard. Anything less risks looking like another LLM shell wrapper.
