# Agent Execution Logs

Blitz records deterministic execution logs in every session. Agent-facing logs must still be captured from the selected judge-facing agent path, such as OpenClaw or Claude Code.

## Blitz Session Logs

Every `app.py analyze` run writes:

```text
output/<session>/audit/<session>.ndjson
output/<session>/audit/session_state.json
output/<session>/audit/progress.json
output/<session>/findings/evidence_maturity.json
output/<session>/reports/evidence_maturity.md
```

The audit log contains timestamped lifecycle events such as manifest load, evidence verification, batch planning, typed tool execution, parser completion, correlation, validation, report export, evidence maturity export, artifact manifest generation, and analysis completion.

The evidence maturity report is the judge-facing index. For each finding it links:

- finding ID
- normalized event ID
- evidence ID
- parser result
- typed tool output path/hash where available
- audit entry sequence and entry hash

## Agent Logs Still Required

For the final submission, capture the OpenClaw or Claude Code session log separately and preserve:

- agent framework name and version
- model/provider name where available
- timestamps
- tool-call sequence
- Blitz MCP request/response summaries
- token usage where available
- self-correction iteration traces
- final session output path
- trust-proof scenario ID if the agent triggered or observed an adversarial validation scenario
- selected finding ID used for evidence-to-conclusion verification

Do not paste raw evidence or raw tool stdout into public logs. Use bounded summaries, hashes, event IDs, finding IDs, and artifact paths.

## Minimum Acceptance

- A reviewer can match an agent tool request to a Blitz typed tool execution.
- A reviewer can match a reported finding to `findings/evidence_maturity.json`.
- A reviewer can identify the self-correction sequence required by the organizer demo rules.
- A reviewer can identify whether the showcased trust proof is real-case evidence, synthetic/adversarial layer-validation evidence, or both.
- Token usage is present when the selected agent/model exposes it.
- Missing token usage is documented as a limitation, not silently omitted.

## Trust Proof Log Checklist

- [ ] Agent log links to the selected Blitz session ID.
- [ ] Agent log includes the selected adversarial evidence validation scenario ID.
- [ ] Agent log includes the selected evidence-to-conclusion verification finding ID.
- [ ] Agent log includes timestamps for the tool request that produced the selected finding.
- [ ] Agent log includes timestamps for the self-correction or bounded recovery sequence.
- [ ] Agent log records any rejected unsafe request as a Blitz boundary decision, not as an agent failure hidden from judges.
