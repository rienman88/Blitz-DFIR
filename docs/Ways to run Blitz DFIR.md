IMPORTANT NOTICE : If you ran into this problem while using the commands given below - "preflight_failed=workdir_not_found"
```
(.venv) sansforensics@siftworkstation: ~/src/Blitz-DFIR
$ cd /home/sansforensics/src/Blitz-DFIR
CASE=BLITZ-MY-MEMORY \
EVIDENCE1_PATH="/home/sansforensics/Desktop/cases/BLITZ-ROCBA-MEMORY/raw/Rocba-Memory.raw" \
EVIDENCE1_TYPE=MEMORY \
EVIDENCE1_ID=memory-01 \
bash scripts/sift_run_external_evidence_no_llm.sh
preflight_failed=workdir_not_found

```
the symlink wasn't created yet. Run this first, before the pipeline command:
```
ln -s /home/sansforensics/src/Blitz-DFIR /home/sansforensics/src/Blitz_DFIR
```

Verify it exists:
```
ls -la /home/sansforensics/src/
```
you should see something like this
```
Blitz-DFIR/
Blitz_DFIR -> /home/sansforensics/src/Blitz-DFIR
````

# WAYS TO RUN BLITZ DFIR

## Run One Dataset By Script

No LLM:

```bash
cd /home/sansforensics/src/Blitz-DFIR

CASE=BLITZ-MY-MEMORY \
EVIDENCE1_PATH="/absolute/path/to/memory.raw" \
EVIDENCE1_TYPE=MEMORY \
EVIDENCE1_ID=memory-01 \
bash scripts/sift_run_external_evidence_no_llm.sh
```

With Ollama:

```bash
cd /home/sansforensics/src/Blitz-DFIR

CASE=BLITZ-MY-MEMORY \
EVIDENCE1_PATH="/absolute/path/to/memory.raw" \
EVIDENCE1_TYPE=MEMORY \
EVIDENCE1_ID=memory-01 \
OLLAMA_BASE_URL=http://127.0.0.1:11434 \
LLM_MODEL=llama3.2:1b \
bash scripts/sift_run_external_evidence_ollama.sh
```

If a SHA256 file already exists:

```bash
CASE=BLITZ-MY-E01 \
EVIDENCE1_PATH="/absolute/path/to/disk.E01" \
EVIDENCE1_TYPE=E01 \
EVIDENCE1_ID=disk-01 \
EVIDENCE1_SHA_FILE="/absolute/path/to/disk.E01.sha256" \
bash scripts/sift_run_external_evidence_no_llm.sh
```

If no SHA is provided, Blitz computes SHA256 and writes it into `/cases/<CASE>/case.yaml`.

## Run Two Datasets By Script

No LLM:

```bash
cd /home/sansforensics/src/Blitz-DFIR

CASE=BLITZ-MY-MEMORY-E01 \
EVIDENCE1_PATH="/absolute/path/to/memory.raw" \
EVIDENCE1_TYPE=MEMORY \
EVIDENCE1_ID=memory-01 \
EVIDENCE2_PATH="/absolute/path/to/disk.E01" \
EVIDENCE2_TYPE=E01 \
EVIDENCE2_ID=disk-01 \
bash scripts/sift_run_external_evidence_no_llm.sh
```

With Ollama:

```bash
cd /home/sansforensics/src/Blitz-DFIR

CASE=BLITZ-MY-MEMORY-E01 \
EVIDENCE1_PATH="/absolute/path/to/memory.raw" \
EVIDENCE1_TYPE=MEMORY \
EVIDENCE1_ID=memory-01 \
EVIDENCE2_PATH="/absolute/path/to/disk.E01" \
EVIDENCE2_TYPE=E01 \
EVIDENCE2_ID=disk-01 \
OLLAMA_BASE_URL=http://127.0.0.1:11434 \
LLM_MODEL=llama3.2:1b \
bash scripts/sift_run_external_evidence_ollama.sh
```

Useful optional variables:

```bash
CASE_OBJECTIVE="Analyze the selected evidence for execution, persistence, credential activity, temporal gaps, cross-source correlation, and unknowns while avoiding unsupported conclusions."
EVIDENCE1_SHA="<sha256>"
EVIDENCE1_SHA_FILE="/absolute/path/to/file.sha256"
EVIDENCE2_SHA="<sha256>"
EVIDENCE2_SHA_FILE="/absolute/path/to/file.sha256"
MAX_NORMALIZED_EVENTS=5000000
MAX_ANALYSIS_EVENTS=2000000
BLITZ_SQLITE_ANALYSIS_EVENT_MEMORY_LIMIT=50000
BLITZ_SQLITE_NORMALIZATION_CHECKPOINT_INTERVAL=100000
```

## Run One Dataset Manually

Use this when you do not want the helper script. Replace the case name, evidence path, evidence type, and objective.

```bash
cd /home/sansforensics/src/Blitz-DFIR

CASE=BLITZ-MANUAL-ONE
CASE_ROOT="/cases/${CASE}"
EVIDENCE1_ID=evidence-01
EVIDENCE1_TYPE=MEMORY
EVIDENCE1_PATH="/absolute/path/to/evidence.raw"

mkdir -p "${CASE_ROOT}/output" "${CASE_ROOT}/analysis/runs"
EVIDENCE1_SHA="$(sha256sum "${EVIDENCE1_PATH}" | awk '{print $1}')"

cat > "${CASE_ROOT}/case.yaml" <<EOF
case_id: ${CASE}
evidence_root: external
output_root: ${CASE_ROOT}/output
evidence:
  - id: ${EVIDENCE1_ID}
    path: "${EVIDENCE1_PATH}"
    type: ${EVIDENCE1_TYPE}
    sha256: ${EVIDENCE1_SHA}
    description: "User-selected evidence referenced in place."
EOF

.venv/bin/python app.py analyze \
  --manifest "${CASE_ROOT}/case.yaml" \
  --mode timeline \
  --tool-config /home/sansforensics/src/Blitz-DFIR/config/tools.yaml \
  --case-objective "Analyze the selected evidence for evidence-backed execution artifacts, persistence, credential activity, user activity, temporal gaps, and unknowns while avoiding unsupported conclusions." \
  --psort-profile triage \
  --windows-artifact-profile windows-light \
  --tool-timeout 7200 \
  --max-normalized-events 5000000 \
  --max-analysis-events 2000000 \
  --report-event-limit 2000000 \
  --report-finding-limit 2000000 \
  --normalized-export-limit 10000 \
  --parser-record-export-limit 10000 \
  --full-sql-correlation

CASE="${CASE}" bash scripts/blitz_status.sh
```

To enable LLM in the manual command, add these exports before `app.py analyze` and add `--enable-reasoning` to the analyze command:

```bash
export LLM_PROVIDER=ollama
export LLM_BASE_URL=http://127.0.0.1:11434/v1
export LLM_API_KEY=ollama
export LLM_MODEL=llama3.2:1b
export LLM_TIMEOUT_SECONDS=600
export LLM_MAX_TOKENS=800
export LLM_RESPONSE_FORMAT_JSON=1
```

## Run Two Datasets Manually

This is the same pattern with two evidence records:

```bash
cd /home/sansforensics/src/Blitz-DFIR

CASE=BLITZ-MANUAL-TWO
CASE_ROOT="/cases/${CASE}"

EVIDENCE1_ID=memory-01
EVIDENCE1_TYPE=MEMORY
EVIDENCE1_PATH="/absolute/path/to/memory.raw"

EVIDENCE2_ID=disk-01
EVIDENCE2_TYPE=E01
EVIDENCE2_PATH="/absolute/path/to/disk.E01"

mkdir -p "${CASE_ROOT}/output" "${CASE_ROOT}/analysis/runs"
EVIDENCE1_SHA="$(sha256sum "${EVIDENCE1_PATH}" | awk '{print $1}')"
EVIDENCE2_SHA="$(sha256sum "${EVIDENCE2_PATH}" | awk '{print $1}')"

cat > "${CASE_ROOT}/case.yaml" <<EOF
case_id: ${CASE}
evidence_root: external
output_root: ${CASE_ROOT}/output
evidence:
  - id: ${EVIDENCE1_ID}
    path: "${EVIDENCE1_PATH}"
    type: ${EVIDENCE1_TYPE}
    sha256: ${EVIDENCE1_SHA}
    description: "User-selected evidence 1 referenced in place."
  - id: ${EVIDENCE2_ID}
    path: "${EVIDENCE2_PATH}"
    type: ${EVIDENCE2_TYPE}
    sha256: ${EVIDENCE2_SHA}
    description: "User-selected evidence 2 referenced in place."
EOF

export LLM_PROVIDER=ollama
export LLM_BASE_URL=http://127.0.0.1:11434/v1
export LLM_API_KEY=ollama
export LLM_MODEL=llama3.2:1b
export LLM_TIMEOUT_SECONDS=600
export LLM_MAX_TOKENS=800
export LLM_RESPONSE_FORMAT_JSON=1

BLITZ_SQLITE_ANALYSIS_EVENT_MEMORY_LIMIT=50000 \
BLITZ_SQLITE_NORMALIZATION_CHECKPOINT_INTERVAL=100000 \
.venv/bin/python app.py analyze \
  --manifest "${CASE_ROOT}/case.yaml" \
  --mode timeline \
  --tool-config /home/sansforensics/src/Blitz-DFIR/config/tools.yaml \
  --case-objective "Analyze the selected evidence together for evidence-backed suspicious processes, execution artifacts, persistence, credential activity, user activity, temporal gaps, cross-source correlation, and unknowns while avoiding unsupported conclusions." \
  --enable-reasoning \
  --psort-profile triage \
  --windows-artifact-profile windows-light \
  --tool-timeout 7200 \
  --max-normalized-events 5000000 \
  --max-analysis-events 2000000 \
  --report-event-limit 2000000 \
  --report-finding-limit 2000000 \
  --normalized-export-limit 10000 \
  --parser-record-export-limit 10000 \
  --full-sql-correlation

CASE="${CASE}" bash scripts/blitz_status.sh
```

