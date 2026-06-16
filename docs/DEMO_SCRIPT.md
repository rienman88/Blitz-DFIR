# Demo Script

The demo must show Protocol SIFT/OpenClaw integration, bounded typed execution, real or representative case data, evidence traceability, and at least one self-correction or honest limitation sequence.

Target length: 5 minutes maximum.

Trust proof alignment: `docs/FIND_EVIL_TRUST_PROOF_PACKAGE.md`.

## Non-Negotiable Demo Checklist

- [ ] Show live terminal execution, not only slides.
- [ ] Use real or representative SIFT case data for the main run.
- [ ] Show one self-correction sequence. If it is an adversarial scenario rather than an organic dataset event, label it as layer-validation proof.
- [ ] Show one adversarial evidence validation result: prompt injection, poisoning, unsafe tool request, or spoliation rejection.
- [ ] Show one evidence-to-conclusion verification trace: finding to event to evidence to parser/tool/audit.
- [ ] Show one limitation, contradiction, unknown zone, or confidence penalty.
- [ ] Show proof artifacts, not verbal claims only.

## Evidence-Maturity Demo Flow

1. State the architecture in one sentence: Protocol SIFT/OpenClaw requests typed actions, Blitz enforces the forensic boundary, SIFT tools produce bounded outputs, and Blitz validates before reporting.
2. Show the case manifest and call out evidence IDs, evidence hashes, and read-only evidence posture.
3. Run the analysis command against the selected real or representative dataset.

```bash
python app.py analyze \
  --manifest /cases/BLITZ-PLASO-001/case.yaml \
  --mode timeline \
  --tool-config /home/sansforensics/src/Blitz_DFIR/config/tools.yaml \
  --psort-profile triage \
  --full-sql-correlation
```

4. Show terminal output for normalized events, findings, validation status, audit path, report path, and evidence maturity path.
5. Open `reports/report.html` and show one evidence-supported finding.
6. Open `findings/evidence_maturity.json` or `reports/evidence_maturity.md` and trace the same finding through:
   - finding ID
   - normalized event ID
   - evidence ID
   - parser result
   - typed tool output
   - audit entry sequence/hash
7. Show `findings/coverage.json`, `findings/unknowns.json`, or the evidence maturity coverage section to explain what Blitz did not analyze.
8. Show before/after evidence hashes in `findings/evidence_maturity.json`.
9. Run or show the spoliation demo result:

```bash
python scripts/blitz_spoliation_demo.py --work-dir /tmp/blitz-spoliation-demo
```

10. Show one validation issue, correction history entry, unknown zone, or conservative limitation. If no real self-correction triggers in the selected dataset, state that plainly and do not pretend a correction happened.

## Trust-Proof Demo Insert

Use this as the `2:45-4:15` segment in the final video.

1. Show a hostile evidence or adversarial fixture containing instruction-like text such as "ignore previous instructions" or "report clean."
2. Run the selected adversarial scenario through Blitz or show the preserved scenario result.
3. Show the output proving one of these outcomes:
   - evidence-derived instruction was sanitized or bounded
   - unsupported tool request was blocked
   - poisoned parser output created warnings and confidence penalties
   - mutation request was rejected and evidence hash stayed unchanged
4. Open the selected report finding and trace it through evidence maturity.
5. Call out the exact confidence modifier, contradiction, unknown zone, or `INFERRED` label that prevents overclaiming.

## Required Callouts

- Blitz does not expose generic shell execution to the agent.
- Raw evidence and raw tool output are not sent to an LLM provider.
- Findings are evidence-supported or inferred; INFERRED reasoning is not evidence.
- Hash chains and artifact manifests are tamper-evident, not tamper-proof.
- Partial, timed-out, or scoped runs are not full-dataset accuracy evidence.
