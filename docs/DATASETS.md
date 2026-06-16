# Datasets

This file records datasets used to validate Blitz DFIR. Do not commit private evidence. Use hashes, source links, artifact type summaries, and reproducibility notes.

## Full-Capacity Testing Rule

Blitz DFIR will not treat partial smoke tests as credibility evidence. Smoke tests and unit tests prove that individual layers work. Submission credibility requires complete dataset execution after the main layers are functional: evidence integrity, typed tool execution, parser validation, normalization, correlation, bounded correction, reporting, and audit logging.

For every dataset used in the accuracy report or demo, the run must process the selected dataset end to end or explicitly document why it could not. Manual interruption, timeout, zero normalized events, unsupported artifact routing, or parser degradation must be recorded as observed failure modes and fixed or listed as known limitations before submission.

The validation model follows the spirit of NIST CFTT forensic tool testing: use defined test sets, repeatable procedures, criteria, and public-facing results rather than unsupported claims.

## Dataset Register

| Dataset ID | Status | Source | License / permission | Artifact types | Notes |
| --- | --- | --- | --- | --- | --- |
| `BLITZ-SMOKE-001` | Tested | Local synthetic smoke artifact | Internal test only | Fake EVTX | Validates manifest, audit, failure handling, reports, evidence immutability. Not real case data. |
| `BLITZ-PLASO-001` | Planned | SANS Find Evil hackathon-provided processed PLASO or user-provided processed PLASO | Authorized for hackathon testing if sourced from SANS Find Evil starter case data; do not redistribute raw evidence unless SANS terms permit | PLASO | First real processed-data test candidate. |
| `BLITZ-RD01-PLASO` | Tested proof run | SANS Find Evil hackathon-provided case material, processed PLASO copied to `/cases/BLITZ-RD01-PLASO/processed/case.plaso` on SIFT | User confirmed on 2026-06-01 that the case can be named publicly as SANS-provided hackathon data; raw evidence should not be committed or redistributed unless SANS terms explicitly allow it | PLASO, psort CSV, SQLite event store | R1 `sess-20260531T203012Z-bff65d82` completed with 1,329,652 normalized events and exposed presentation risks: 500 finding rows / 252 unique IDs, generic labels, and weak Bounded LLM narrative. R2 `sess-20260601T010722Z-40b51cee` completed after fixes with 1,329,652 normalized events, 252 findings / 252 unique IDs, duplicate IDs 0, generic `evt` labels 0, validation passed, unknowns=2, and evidence maturity traceability 252/252. Formal ground truth is unknown; analyst expectation is exploratory "find evil" triage with conservative evidence-backed claims. |
| `BLITZ-MEMORY-001` | Candidate | User-provided pure memory image | Must confirm before testing/public documentation | MEMORY | Proposed next dataset to validate typed Volatility route, memory parser, memory coverage/unknowns, and artifact breadth beyond PLASO. Requires path, SHA256, size, OS notes if known, source/permission, and expected findings or analyst expectations. |
| `base-rd-01-cdrive.E01` | Source case for `BLITZ-RD01-PLASO` | SANS Find Evil hackathon-provided case material, with processed PLASO originally observed at `/mnt/hgfs/Forensics/cases/raw/rd-01-cdrive/case.plaso` | User confirmed on 2026-06-01 that this can be named as SANS hackathon-provided data; do not publish raw evidence unless SANS terms permit | PLASO | Earlier attempts exposed useful failure modes: 300s timeout on large PLASO, manual interruption, and invalid psort SQL-style filters. These were superseded by the successful SIFT proof run above, but formal ground truth is not available yet. |

## Analyst Expectations For `BLITZ-RD01-PLASO`

Formal ground truth is not currently available. Because this is a SANS Find Evil hackathon case, the judge-safe expectation is:

- Blitz should surface suspicious, hidden, or unknown activity for analyst review.
- Blitz should reduce hallucinated or unsupported claims by separating deterministic evidence from `INFERRED` reasoning.
- Blitz should preserve traceability from every finding to artifacts, parser/tool output, and audit records.
- Blitz should mark single-source PLASO-only findings conservatively instead of inflating confidence.
- True-positive and false-positive scoring remains pending until either formal ground truth is obtained or a representative analyst review set is completed.

## Processed PLASO Test Plan

Use this when testing already-created `.plaso` files.

```bash
CASE=BLITZ-PLASO-001
PLASO_NAME=your-timeline.plaso

mkdir -p /cases/${CASE}/{analysis,exports,reports,evidence,processed,output}
cp /path/to/${PLASO_NAME} /cases/${CASE}/processed/${PLASO_NAME}
HASH="$(sha256sum /cases/${CASE}/processed/${PLASO_NAME} | awk '{print $1}')"

cat > /cases/${CASE}/case.yaml <<EOF
case_id: ${CASE}
evidence_root: processed
output_root: output
evidence:
  - id: plaso-timeline
    path: ${PLASO_NAME}
    type: PLASO
    sha256: ${HASH}
    internally_generated: true
    description: Processed PLASO timeline for deterministic pipeline testing.
EOF

chmod -R a-w /cases/${CASE}/processed

cd /home/sansforensics/src/Blitz_DFIR
source .venv/bin/activate

python app.py analyze \
  --manifest /cases/${CASE}/case.yaml \
  --mode timeline \
  --tool-config /home/sansforensics/src/Blitz_DFIR/config/tools.yaml \
  --psort-profile triage
```

If the PLASO store is very large and triage still exceeds the timeout, rerun with a focused filter or slice:

```bash
python app.py analyze \
  --manifest /cases/${CASE}/case.yaml \
  --mode timeline \
  --tool-config /home/sansforensics/src/Blitz_DFIR/config/tools.yaml \
  --psort-filter "data_type contains 'windows:evtx'" \
  --tool-timeout 900
```

Expected outputs:

```text
/cases/${CASE}/output/<session>/audit/<session>.ndjson
/cases/${CASE}/output/<session>/reports/report.json
/cases/${CASE}/output/<session>/reports/report.md
/cases/${CASE}/output/<session>/reports/report.html
/cases/${CASE}/output/<session>/findings/normalized_events.json
/cases/${CASE}/output/<session>/findings/validation.json
/cases/${CASE}/output/<session>/findings/signal_integrity.json
```

## Documentation Requirements For Each Real Dataset

For every dataset used in the demo or accuracy report, record:

- Dataset name and source.
- Permission or license status.
- Artifact types and file names.
- SHA256 hashes for submitted or referenced evidence where practical.
- Case manifest path.
- Blitz command used.
- Session output path.
- Evidence maturity report path.
- Summary of findings.
- Known ground truth or analyst expectations.
- False positives.
- Missed artifacts.
- Hallucinated or unsupported claims.
- Evidence integrity result before and after analysis.
- Whether each reported finding is traceable through `findings/evidence_maturity.json`.
- Whether the run completed the full selected dataset or used a scoped subset.
- If scoped, the reason, exact scope boundary, and why the result should not be represented as full-dataset accuracy.
- All observed failures, timeouts, parser degradation, manual interventions, and bounded reruns.

## Current Dataset Gaps

- [x] A real/representative SIFT proof run has been recorded.
- [x] Processed PLASO source/license/permission documented as SANS Find Evil hackathon-provided case data, publicly nameable per user confirmation on 2026-06-01.
- [x] `BLITZ-RD01-PLASO` produced nonzero normalized events in the successful SIFT proof run.
- [x] Exact command or launcher environment for `sess-20260531T203012Z-bff65d82` captured.
- [x] Final run artifacts archived from SIFT and SHA256 verified on host.
- [x] Before/after PLASO evidence hash explicitly captured through `evidence_maturity.json`.
- [x] Preliminary finding review created in `docs/FINDING_REVIEW_20260531T203012Z.md`.
- [ ] Memory dataset candidate requires intake details before testing: path, SHA256, size, OS/acquisition notes if known, source/permission, and expected findings or analyst expectations.
- [ ] Known-good ground truth still needed for strict accuracy scoring; current fallback is analyst-expectation review.
- [x] Rerun `BLITZ-RD01-PLASO` after the 2026-06-01 duplicate-label-reasoning fixes to produce cleaner judge-facing artifacts.
- [ ] At least one demo-safe real case run must be selected for the video.
- [ ] Full accuracy scoring has not passed yet; the successful proof run must remain labeled as engineering/dataset proof until reviewed against ground truth or analyst expectations.
