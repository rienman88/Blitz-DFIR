# Repeatability Matrix

Use this file to record reruns and multi-dataset validation. Do not turn one successful smoke test into an accuracy claim.

## Required Fields

For every repeatability entry, record:

- dataset ID
- command
- environment
- tool versions
- session path
- evidence hash before and after
- normalized event count
- finding count
- validation status
- coverage score
- unknown count
- warning count
- timeout or parser degradation
- `findings/evidence_maturity.json` path
- whether the result is full-dataset accuracy evidence or engineering validation only

## Matrix

| Run ID | Dataset ID | Scope | Command | Session | Normalized events | Findings | Validation | Coverage | Unknowns | Evidence hash preserved | Status |
| --- | --- | --- | --- | --- | ---: | ---: | --- | ---: | ---: | --- | --- |
| `BLITZ-SMOKE-001-R1` | `BLITZ-SMOKE-001` | synthetic smoke | `python app.py analyze --manifest <path> --mode timeline` | local test output | varies | varies | engineering check | varies | varies | yes | Not submission accuracy evidence |
| `BLITZ-RD01-PLASO-R1` | `BLITZ-RD01-PLASO` | SANS Find Evil hackathon-provided processed PLASO proof run; `psort` filtered to `data_type contains 'windows:evtx'` | `.venv/bin/python app.py analyze --manifest /cases/BLITZ-RD01-PLASO/case.yaml --mode timeline --tool-config ... --enable-reasoning --psort-profile triage --psort-filter "data_type contains 'windows:evtx'" --tool-timeout 7200 --max-normalized-events 2000000 --max-analysis-events 100000 --report-event-limit 5000 --report-finding-limit 500 --normalized-export-limit 10000 --parser-record-export-limit 1000 --full-sql-correlation` | `/cases/BLITZ-RD01-PLASO/output/sess-20260531T203012Z-bff65d82` | 1329652 | 500 rows / 252 unique IDs | passed | artifact written | 2 | yes; expected and observed SHA256 matched | Strong engineering proof run; not final accuracy evidence until formal ground truth or analyst-review scoring is captured. Rerun needed after 2026-06-01 duplicate-label-reasoning fixes before judge-facing accuracy use. |
| `BLITZ-RD01-PLASO-R2` | `BLITZ-RD01-PLASO` | post-fix SANS Find Evil processed PLASO proof run; same EVTX-focused `psort` scope as R1 | `.venv/bin/python app.py analyze --manifest /cases/BLITZ-RD01-PLASO/case.yaml --mode timeline --tool-config ... --enable-reasoning --psort-profile triage --psort-filter "data_type contains 'windows:evtx'" --tool-timeout 7200 --max-normalized-events 2000000 --max-analysis-events 100000 --report-event-limit 5000 --report-finding-limit 500 --normalized-export-limit 10000 --parser-record-export-limit 1000 --full-sql-correlation` | `/cases/BLITZ-RD01-PLASO/output/sess-20260601T010722Z-40b51cee` | 1329652 | 252 rows / 252 unique IDs | passed | artifact written | 2 | yes; evidence maturity checkpoint reported preserved hashes | Clean post-fix proof candidate: duplicate IDs `0`, generic `evt` labels `0`, SQL/database hallucination absent from reasoning narrative, evidence maturity traceable findings `252/252`. Still PLASO-only, so confidence remains conservative single-source `0.55`. |
| `BLITZ-RD01-PLASO-R3` | `BLITZ-RD01-PLASO` | post-trust-layer SANS Find Evil processed PLASO proof run; same EVTX-focused `psort` scope as R2, with evidentiary weighting, contradiction analysis, provenance visualization, supervised launcher, E2E check, and post-run checks | `CASE=BLITZ-RD01-PLASO bash scripts/sift_e2e_ollama_run.sh` after syncing 2026-06-01 trust-layer code | `/cases/BLITZ-RD01-PLASO/output/sess-20260601T113254Z-327c7a6a` | 1329652 | 252 rows / 252 unique IDs | passed | artifact written | 2 | yes; evidence maturity checkpoint reported preserved hashes | Current preferred trust-layer proof candidate: `evidentiary_weighting.json`, `contradiction_analysis.json`, and `finding_provenance.md` exist; `e2e_ollama_check=passed`; `postrun_checks=passed`; host proof archive verified with SHA256 `1A8BB27CADB13DF89D4E29E8F5FECBBCF2E3CBD524D738720E551BA6B85744D8`. Parser display still showed stale `(0/1)` and SQLite WAL sidecars were present; both code fixes were implemented after this run. |

## Current Gaps

- [x] Add at least one real or representative dataset proof run.
- [x] Add at least one rerun of the selected demo dataset.
- [ ] Add OpenClaw or Claude Code agent-driven run metadata.
- [ ] Add exact SIFT environment and tool versions.
- [x] Add exact command or launcher environment for `BLITZ-RD01-PLASO-R1`.
- [x] Archive or copy the `BLITZ-RD01-PLASO-R1` proof artifacts from SIFT; host SHA256 matched SIFT hash file.
- [x] Record dataset source/permission for `BLITZ-RD01-PLASO-R1` as SANS Find Evil hackathon-provided data.
- [x] Rerun selected case after 2026-06-01 fixes: `BLITZ-RD01-PLASO-R2`.
- [x] Rerun selected case after 2026-06-01 trust-layer additions: `BLITZ-RD01-PLASO-R3`.
- [x] Archive and host-verify `BLITZ-RD01-PLASO-R3` before SIFT cleanup or memory-dataset intake.
- [ ] Add explicit limitations for any scoped, timed-out, or interrupted run.
