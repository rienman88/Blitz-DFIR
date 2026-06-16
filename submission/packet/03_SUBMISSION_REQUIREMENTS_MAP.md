# Submission Requirements Map

This maps the eight required hackathon components to the exact Blitz DFIR files.

## 1. Code Repository

Status: ready after final README polish and GitHub push.

Use:

- Repository root: `../../`
- License: `../../LICENSE`
- Notice: `../../NOTICE`
- Third-party notices: `../../THIRD_PARTY_LICENSES.md`
- GitHub package zip already staged previously: `../blitz_dfir_github_ready_20260614.zip`

Submit the public GitHub repository, not the proof package alone.

## 2. Demo Video

Status: pending recording.

Use:

- `08_DEMO_VIDEO_CHECKLIST.md`

The video should show live terminal execution, status checking, and the self-correction sequence where `log2timeline.py` fails and Blitz falls back to disk triage.

## 3. Architecture Diagram

Status: ready as Markdown/Mermaid.

Use:

- `04_ARCHITECTURE_DIAGRAM_AND_TRUST_BOUNDARIES.md`

This identifies the architectural pattern and separates prompt guardrails from architectural guardrails.

## 4. Written Project Description

Status: ready.

Use:

- `../../../blitz_dfir_devpost_FINAL_POLISHED.md`

Do not submit `../../../blitz_dfir_devpost_IMPROVED.md` unless you intentionally want the more aggressive older draft.

## 5. Dataset Documentation

Status: ready.

Use:

- `05_DATASET_DOCUMENTATION.md`

This documents the Rocba memory and E01 evidence, hashes, sizes, source description, and what Blitz found.

## 6. Accuracy Report

Status: ready.

Use:

- `06_ACCURACY_REPORT.md`

This includes false positives, missed artifacts, hallucination controls, evidence integrity, spoliation controls, and validation caveats.

## 7. Try-It-Out Instructions

Status: ready as submission draft; README still needs final beginner polish later.

Use:

- `09_TRY_IT_OUT_INSTRUCTIONS.md`

This gives local SIFT run commands and LLM configuration notes.

## 8. Agent Execution Logs

Status: ready.

Use:

- `07_AGENT_EXECUTION_LOGS_INDEX.md`
- Original package: `../BLITZ-ROCBA-MEMORY-E01_agent_logs_20260615T082911Z.tar.gz`
- Extracted logs: `../BLITZ-ROCBA-MEMORY-E01_agent_logs_20260615T082911Z/`

Judges can trace the run through `agent_journal.md`, `agent_trace.json`, `tool_results.json`, `progress.json`, and the append-only audit `.ndjson`.

