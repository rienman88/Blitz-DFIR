# Evidence Maturity Upgrades

This package moves Blitz from feature claims toward proof artifacts.

## Added Capabilities

- Per-finding explainability in JSON, Markdown, and HTML reports.
- `findings/evidence_maturity.json` as the judge-facing traceability index.
- `reports/evidence_maturity.md` as the readable traceability summary.
- Before/after evidence hash checks in the evidence maturity report.
- Coverage and unknown-zone maturity summary.
- Spoliation-resistance demo script at `scripts/blitz_spoliation_demo.py`.
- Repeatability matrix scaffold at `docs/REPEATABILITY_MATRIX.md`.

## Traceability Chain

For every finding where supporting data is available, Blitz now records:

```text
finding
-> normalized event
-> evidence ID and raw reference
-> parser result
-> typed tool output/hash where available
-> audit entry sequence and entry hash
```

Direct processed evidence may not have a tool execution in the same session. In that case, traceability still records the evidence ID, hash preservation, normalized event, parser result, and audit entries.

## What This Does Not Solve By Itself

- It does not create real ground truth.
- It does not replace real dataset testing.
- It does not make local artifacts tamper-proof against a user who can rewrite every file.
- It does not prove OpenClaw or Claude Code agent execution until those logs are captured.

## Recommended Next Evidence Work

1. Run one demo-safe real or representative dataset end to end.
2. Fill `docs/DATASETS.md` with source, license, hashes, commands, and observed results.
3. Fill `docs/ACCURACY_REPORT.md` with true positives, false positives, missed artifacts, unsupported claims, and limitations.
4. Fill `docs/REPEATABILITY_MATRIX.md` with at least one rerun.
5. Capture OpenClaw or Claude Code logs and connect them to `findings/evidence_maturity.json`.
