# GitHub Package Manifest

Prepared: 2026-06-14

Owner:

```text
Rienart Ryan Ilagan
```

## Included

This GitHub-ready package includes the source and reviewer-facing material
needed to build, test, run, and understand Blitz DFIR:

- `app.py`
- `blitz_dfir/`
- `config/`
- `scripts/`
- `tests/`
- `.github/workflows/ci.yml`
- `.env.example`
- `.gitignore`
- `README.md`
- `LICENSE`
- `NOTICE`
- `THIRD_PARTY_LICENSES.md`
- `pyproject.toml`
- `requirements.txt`
- `requirements-dev.txt`
- `Blitz_DFIR_IMPLEMENTATION_CHECKLIST.md`
- `One Source of Truth.md`
- curated `docs/`

## Curated Docs Included

- `docs/ACCURACY_REPORT.md`
- `docs/ADVERSARIAL_EVALUATION_PLAN.md`
- `docs/ADVERSARIAL_TEST_RESULTS_20260601.md`
- `docs/AGENT_EXECUTION_LOGS.md`
- `docs/ARCHITECTURE.md`
- `docs/CODE_UPDATE_TO_SIFT_20260601.md`
- `docs/DATASETS.md`
- `docs/DEMO_SCRIPT.md`
- `docs/EVIDENCE_MATURITY_UPGRADES.md`
- `docs/FIND_EVIL_TRUST_PROOF_PACKAGE.md`
- `docs/FINDING_REVIEW_20260531T203012Z.md`
- `docs/JUDGE_LAYER_PROOF_CHECKLIST.md`
- `docs/JUDGE_QA.md`
- `docs/PROTOCOL_SIFT_INTEGRATION.md`
- `docs/REAL_CASE_WALKTHROUGH.md`
- `docs/REPEATABILITY_MATRIX.md`
- `docs/RUN_PROOF_SUMMARY_20260531T203012Z.md`
- `docs/SIFT_MIXED_EVIDENCE_RUNBOOK.md`
- `docs/SPOLIATION_TESTING.md`
- `docs/STABILITY_TESTING.md`
- `docs/SUBMISSION_CHECKLIST.md`
- `docs/TWO_WEEK_TEST_COMPLETION_PLAN.md`

## Excluded

These were intentionally excluded because they are generated, local-only,
too large for source control, or not needed for public GitHub review:

- `.deps/`, `.venv/`, Python caches, pytest/mypy/ruff caches
- `output/`, `local/`, `test_tmp/`, `.sync/`
- `Blitz_DFIR_Proof/`
- `proof_exports/`, `extracted_review/`, `cases/`, `evidence/`
- raw evidence and processed evidence files: `*.E01`, `*.raw`, `*.dd`,
  `*.pcap`, `*.pcapng`, `*.plaso`
- generated proof archives and tar files
- root-level run result dumps:
  - `no_llm_rocba_memory_e01_results.md`
  - `rocba_memory_e01_nollm_results.md`
  - `rocbaduale01memory.md`
- local Word drafts:
  - `Blitz_DFIR_README_v1.docx`
  - `Blitz_DFIR_SSOT_v2.docx`
  - `Blitz_DFIR_SSOT_v2.1.docx`
- rough local proof notes:
  - `docs/evidences.txt`
  - `docs/memory normalization error.md`
  - `docs/memory_no_llm.md`

## Pre-Push Review Checklist

- [ ] Confirm no real evidence files are present.
- [ ] Confirm no proof archives or generated session outputs are present.
- [ ] Confirm `.env` is absent and only `.env.example` is present.
- [ ] Confirm `LICENSE`, `NOTICE`, and `THIRD_PARTY_LICENSES.md` are present.
- [ ] Confirm CI workflow is present under `.github/workflows/ci.yml`.
- [ ] Run `python -m pytest -q` before pushing if time allows.
- [ ] Review `README.md` for any SIFT lab-specific IPs or paths you want to
      generalize before making the repository public.
