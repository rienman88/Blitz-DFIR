# Try-It-Out Instructions

These are judge-facing instructions for running Blitz DFIR locally on SANS SIFT Workstation.

The README should later absorb and simplify this section, but this file is ready for the submission packet.

## Requirements

- SANS SIFT Workstation.
- Python virtual environment for Blitz.
- Volatility 3 available as `vol`.
- Plaso tools available as `log2timeline.py`, `psort.py`, and `pinfo.py`.
- Sleuth Kit tools available as `mmls` and `fls`.
- Optional local or remote OpenAI-compatible LLM endpoint.

## Evidence Placement

Users can keep raw evidence in their own folders. Blitz does not require copying raw evidence into the case folder.

Example:

- Memory: `/path/to/memory.raw`
- E01: `/path/to/disk.e01`

The case manifest points to those files and records hashes.

## LLM Configuration

For local Ollama:

```bash
export OLLAMA_BASE_URL=http://127.0.0.1:11434
export LLM_PROVIDER=ollama
export LLM_MODEL=llama3.2:1b
export LLM_API_KEY=ollama
```

For a remote Ollama host:

```bash
export OLLAMA_BASE_URL=http://YOUR_HOST_OR_IP:11434
export LLM_PROVIDER=ollama
export LLM_MODEL=llama3.2:1b
export LLM_API_KEY=ollama
```

For another OpenAI-compatible provider, use that provider's base URL, API key, and model name:

```bash
export LLM_PROVIDER=openai
export LLM_BASE_URL=https://YOUR_OPENAI_COMPATIBLE_ENDPOINT/v1
export LLM_API_KEY=YOUR_API_KEY
export LLM_MODEL=YOUR_MODEL
```

## Combined Memory+E01 Run

This is the exact style used for the final Rocba LLM run:

```bash
cd /home/sansforensics/src/Blitz_DFIR

BLITZ_SQLITE_ANALYSIS_EVENT_MEMORY_LIMIT=50000 \
BLITZ_SQLITE_NORMALIZATION_CHECKPOINT_INTERVAL=100000 \
OLLAMA_BASE_URL=http://192.168.88.1:11434 \
LLM_TIMEOUT_SECONDS=600 \
LLM_MAX_TOKENS=800 \
OLLAMA_KEEP_ALIVE=30m \
OLLAMA_KEEPALIVE_INTERVAL_SECONDS=600 \
CASE=BLITZ-ROCBA-MEMORY-E01 \
bash scripts/sift_rocba_memory_e01_ollama_clean_run.sh
```

For a user's own dataset, use the external evidence runner or create a manifest with their own evidence paths. The key rule is simple: register each evidence item in `case.yaml` with `id`, `path`, `type`, and `sha256`.

## Status Check

```bash
cd /home/sansforensics/src/Blitz_DFIR
CASE=YOUR_CASE_ID bash scripts/blitz_status.sh
```

## Process Check

```bash
ps -eo pid,ppid,stat,etime,%mem,%cpu,cmd | egrep 'app.py analyze|log2timeline.py|psort.py|tsk_e01_triage.py|fls|mmls|vol|ollama' | grep -v grep || true
```

## Expected Outputs

After a successful run, review:

- `reports/report.html`
- `reports/report.md`
- `reports/agent_journal.md`
- `findings/agent_trace.json`
- `findings/tool_results.json`
- `findings/parser_results.json`
- `audit/progress.json`
- `audit/session_state.json`
- `audit/*.ndjson`
- `findings/artifact_manifest.json`

## Failure Interpretation

If a tool fails, do not assume the case failed. Check `blitz_status.sh`, `tool_results.json`, validation, unknowns, and audit logs.

In the Rocba run, full Plaso E01 timeline extraction failed, but Blitz continued with bounded disk triage and completed the pipeline. That is expected self-correction behavior.

