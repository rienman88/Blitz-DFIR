# Spoliation Testing

Blitz must prove original evidence is not modified even when evidence content or an agent request attempts to override forensic rules.

## Demo Command

```bash
python scripts/blitz_spoliation_demo.py --work-dir /tmp/blitz-spoliation-demo
```

The demo creates a synthetic CSV timeline containing hostile prompt-injection text, runs the normal Blitz analysis pipeline, then attempts a non-allowlisted `write_evidence` tool request through the dispatcher.

Expected result:

- The hostile text is treated as evidence data.
- The source evidence SHA256 before analysis equals the SHA256 after analysis.
- The mutation request is rejected by the typed MCP allowlist.
- The source evidence SHA256 after the rejected mutation attempt still matches the original hash.
- The audit log records the rejection.
- The demo writes `findings/spoliation_demo_result.json` in the generated session.

## Evidence To Show A Judge

- `findings/spoliation_demo_result.json`
- `audit/<session>.ndjson`
- `findings/evidence_maturity.json`
- `reports/report.html`

## Limitations

This is spoliation resistance inside Blitz's execution boundary. It proves Blitz does not mutate registered evidence through its typed dispatcher and normal analysis flow.

It does not claim the VM is tamper-proof. A user with unrestricted filesystem access can rewrite local files. For judge-grade preservation, copy the final audit log, artifact manifest, report hashes, and evidence hashes off the VM or into a read-only location after a completed run.
