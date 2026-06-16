# Adversarial Test Results: 2026-06-01

Purpose: record the local engineering proof added before the next SIFT full run. These tests validate layer behavior; they are not real-dataset accuracy scoring.

## Added Executable Proof

- `tests/adversarial/test_llm_red_team_inputs.py`
  - Prompt-injection text embedded in EVTX-like JSON, memory strings, PLASO CSV, and Volatility JSON is sanitized before bounded LLM reasoning.
  - Malformed parser output generates parser/signal warnings and non-zero confidence penalty.
- `tests/adversarial/test_evidence_weighting_and_contradictions.py`
  - Multi-source support receives an explicit evidence weight.
  - Cross-source hash disagreement and timestamp skew create contradiction objects.
  - Related finding confidence is reduced and `CONTRADICTION_PENALTY` is added.
- `tests/test_evidence_maturity.py`
  - Evidence maturity now also renders `reports/finding_provenance.md` with Mermaid finding-to-evidence flowcharts.

## New Generated Artifacts For Future Runs

- `findings/evidentiary_weighting.json`
- `reports/evidentiary_weighting.md`
- `findings/contradiction_analysis.json`
- `reports/contradiction_analysis.md`
- `reports/finding_provenance.md`

## Local Verification

Command:

```powershell
$env:PYTHONPATH=(Resolve-Path test_tmp\pydeps).Path
python -m pytest -q tests/adversarial tests/test_evidence_maturity.py tests/test_correlation.py tests/test_session_integrity.py tests/test_reasoning.py tests/test_signal_integrity.py tests/test_parsers.py
```

Result before the parser-display and SQLite-checkpoint follow-up fixes:

```text
44 passed
```

Result after the parser-display and SQLite-checkpoint follow-up fixes:

```text
48 passed
```

Compile check:

```powershell
python -m compileall -q app.py blitz_dfir scripts tests
```

Result: passed.

## Submission Boundary

Use these results as adversarial layer-validation evidence. The next SIFT full run is still required to produce judge-facing artifacts from a real case session using the new layers.
