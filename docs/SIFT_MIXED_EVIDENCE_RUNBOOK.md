# SIFT Mixed Evidence Runbook

Use this when testing Rocba with more than one evidence type, such as memory plus E01, E01 plus PLASO, or memory plus EVTX.

Default policy: reference raw evidence in place. Do not create a second combined-case raw folder unless the analyst explicitly chooses copy mode for chain-of-custody or lab policy reasons.

## Generic User-Selected Evidence Runner

Use this when the analyst wants to choose one or two evidence files from any folder. This is the shell equivalent of a UI where the user browses for dataset paths.

One selected evidence file:

```bash
cd /home/sansforensics/src/Blitz_DFIR

CASE=CLIENT01-E01 \
EVIDENCE1_PATH="/path/to/client01.E01" \
EVIDENCE1_TYPE=E01 \
bash scripts/sift_run_external_evidence_no_llm.sh
```

Two selected evidence files:

```bash
cd /home/sansforensics/src/Blitz_DFIR

CASE=CLIENT01-MEMORY-E01 \
EVIDENCE1_PATH="/path/to/memory.raw" \
EVIDENCE1_TYPE=MEMORY \
EVIDENCE2_PATH="/path/to/client01.E01" \
EVIDENCE2_TYPE=E01 \
bash scripts/sift_run_external_evidence_no_llm.sh
```

With Ollama:

```bash
CASE=CLIENT01-MEMORY-E01 \
EVIDENCE1_PATH="/path/to/memory.raw" \
EVIDENCE1_TYPE=MEMORY \
EVIDENCE2_PATH="/path/to/client01.E01" \
EVIDENCE2_TYPE=E01 \
OLLAMA_BASE_URL=http://192.168.88.1:11434 \
LLM_TIMEOUT_SECONDS=600 \
LLM_MAX_TOKENS=800 \
LLM_RESPONSE_FORMAT_JSON=1 \
OLLAMA_KEEP_ALIVE=30m \
bash scripts/sift_run_external_evidence_ollama.sh
```

The runner writes `/cases/<CASE>/case.yaml` with `evidence_root: external`, verifies or computes SHA256, then runs the normal Blitz analysis pipeline.

For E01/DD first-pass extraction, Blitz uses `--partitions all --vss_stores none --unattended`. This avoids a common Plaso failure where broken Volume Shadow Copy metadata stops the whole E01 timeline. After the base disk timeline works, an advanced analyst can retry VSS explicitly:

```bash
BLITZ_LOG2TIMELINE_VSS_STORES=all CASE=CLIENT01-E01 \
EVIDENCE1_PATH="/path/to/client01.E01" \
EVIDENCE1_TYPE=E01 \
bash scripts/sift_run_external_evidence_no_llm.sh
```

## Clean Run Versus Resume

Clean run:

```bash
CASE=BLITZ-ROCBA-MEMORY bash scripts/sift_memory_no_llm_run.sh
```

Resume only after a disconnect or instability, and only when a prior session already has completed typed tool results:

```bash
RESUME_SESSION=/cases/BLITZ-ROCBA-MEMORY/output/sess-YYYYMMDDTHHMMSSZ-xxxxxxxx \
CASE=BLITZ-ROCBA-MEMORY bash scripts/sift_memory_no_llm_resume.sh
```

If the typed tool layer did not complete, start clean. Do not resume from a partial upstream extraction and call it complete.

## Copy Rocba E01 From The Shared Folder

First find the shared folder mount and E01 path:

```bash
find /media /mnt /home/sansforensics -maxdepth 6 -type f \( -iname '*.e01' -o -iname '*.E01' \) 2>/dev/null
```

Then copy all E01 segments to SIFT-local evidence storage. Replace `SRC_DIR` and the file pattern with the real path shown by `find`:

```bash
CASE_E01=BLITZ-ROCBA-E01
SRC_DIR="/media/sf_Forensics/Rocba"
DEST_DIR="/cases/${CASE_E01}/raw/Rocba-E01"

mkdir -p "$DEST_DIR"
rsync -ah --info=progress2 --partial "$SRC_DIR"/Rocba*.E* "$DEST_DIR"/
sha256sum "$DEST_DIR"/* | tee "$DEST_DIR/SHA256SUMS.txt"
df -h /cases
```

If the E01 is segmented, keep every segment together in the same directory. The manifest points to the first `.E01` file; forensic tooling discovers adjacent `.E02`, `.E03`, and later segments from that directory.

## Run Rocba C-Drive E01 Only

The dedicated E01-only clean runner expects this source by default:

```text
/home/sansforensics/Desktop/cases/Rocba-E01/rocba-cdrive.e01
```

Run in-place. This keeps the E01 in the uploaded folder and writes Blitz outputs under `/cases/BLITZ-ROCBA-E01`:

```bash
cd /home/sansforensics/src/Blitz_DFIR
CASE=BLITZ-ROCBA-E01 bash scripts/sift_rocba_e01_clean_run.sh
```

Use copy mode only if you intentionally want a second copy under `/cases`:

```bash
IMPORT_MODE=copy CASE=BLITZ-ROCBA-E01 bash scripts/sift_rocba_e01_clean_run.sh
```

Space estimate:

```text
E01-only in-place     = 30 GB reserve
E01-only copy mode    = E01 segment size + 30 GB reserve
Memory + E01 copy     = E01 segment size + 40 GB reserve
Memory + E01 in-place = 40 GB reserve
Comfortable target    = E01 segment size + 80 GB free
```

## Manifest: Memory Plus E01

For mixed evidence from different folders, use external evidence mode. This lets analysts upload raw data anywhere and reference those files directly. Blitz does not copy the memory image, E01, EVTX, PLASO, or other raw files into the case folder.

The manifest uses `evidence_root: external`, then each evidence item uses its real absolute path. Outputs still go under `/cases/<CASE>/output`.

Do not create `/cases/BLITZ-ROCBA-MEMORY-E01/raw` for this combined test. That wastes disk space and can duplicate tens of GB of evidence. Keep the original memory and E01 files where they already are, then point the manifest to those absolute paths.

Preferred clean-run command, without LLM:

```bash
cd /home/sansforensics/src/Blitz_DFIR
CASE=BLITZ-ROCBA-MEMORY-E01 bash scripts/sift_rocba_memory_e01_no_llm_clean_run.sh
```

Preferred clean-run command, with Ollama:

```bash
cd /home/sansforensics/src/Blitz_DFIR
CASE=BLITZ-ROCBA-MEMORY-E01 bash scripts/sift_rocba_memory_e01_ollama_clean_run.sh
```

These scripts reference the raw evidence in place, verify SHA256 hashes against the real SIFT paths, write `case.yaml`, run Blitz with argument arrays instead of fragile pasted line continuations, and then call `scripts/blitz_status.sh`.

Review these three rollup files first after completion:

```text
/cases/BLITZ-ROCBA-MEMORY-E01/output/<session>/findings/overall_findings.md
/cases/BLITZ-ROCBA-MEMORY-E01/output/<session>/reports/overall_reports.md
/cases/BLITZ-ROCBA-MEMORY-E01/output/<session>/audit/collated_audit.md
```

Current Rocba no-copy manifest, shown for transparency:

```yaml
case_id: BLITZ-ROCBA-MEMORY-E01
evidence_root: external
output_root: /cases/BLITZ-ROCBA-MEMORY-E01/output
evidence:
  - id: rocba-memory
    path: "/home/sansforensics/Desktop/cases/BLITZ-ROCBA-MEMORY/raw/Rocba-Memory.raw"
    type: MEMORY
    sha256: "<memory sha256>"
    description: "Rocba memory image referenced in place."
  - id: rocba-e01
    path: "/home/sansforensics/Desktop/cases/Rocba-E01/rocba-cdrive.e01"
    type: E01
    sha256: "<first E01 sha256>"
    description: "Rocba full disk image E01 referenced in place."
```

To use a judge's own raw files, replace the `path` values with the real absolute paths to their evidence files. Keep `output_root` outside the raw evidence folders.

Manual run without LLM, only if you are not using the helper script:

```bash
cd /home/sansforensics/src/Blitz_DFIR
.venv/bin/python app.py analyze \
  --manifest /cases/BLITZ-ROCBA-MEMORY-E01/case.yaml \
  --mode timeline \
  --tool-config /home/sansforensics/src/Blitz_DFIR/config/tools.yaml \
  --case-objective "Analyze Rocba memory and disk evidence for evidence-backed suspicious processes, execution artifacts, persistence, credential activity, network activity, temporal gaps, and unknowns while avoiding unsupported conclusions." \
  --tool-timeout 7200 \
  --max-normalized-events 5000000 \
  --max-analysis-events 2000000 \
  --report-event-limit 2000000 \
  --report-finding-limit 2000000 \
  --normalized-export-limit 10000 \
  --parser-record-export-limit 10000 \
  --full-sql-correlation
```

Manual bounded Ollama reasoning, only if you are not using the helper script:

```bash
LLM_PROVIDER=ollama \
LLM_BASE_URL=http://192.168.88.1:11434/v1 \
LLM_API_KEY=ollama \
LLM_MODEL=llama3.2:1b \
LLM_TIMEOUT_SECONDS=600 \
LLM_MAX_TOKENS=800 \
LLM_RESPONSE_FORMAT_JSON=1 \
.venv/bin/python app.py analyze \
  --manifest /cases/BLITZ-ROCBA-MEMORY-E01/case.yaml \
  --mode timeline \
  --tool-config /home/sansforensics/src/Blitz_DFIR/config/tools.yaml \
  --case-objective "Analyze Rocba memory and disk evidence for evidence-backed suspicious processes, execution artifacts, persistence, credential activity, network activity, temporal gaps, and unknowns while avoiding unsupported conclusions." \
  --enable-reasoning \
  --tool-timeout 7200 \
  --max-normalized-events 5000000 \
  --max-analysis-events 2000000 \
  --report-event-limit 2000000 \
  --report-finding-limit 2000000 \
  --normalized-export-limit 10000 \
  --parser-record-export-limit 10000 \
  --full-sql-correlation
```

## Manifest: E01 Plus PLASO

Prefer external mode if the E01 and PLASO already live in different folders:

```yaml
case_id: BLITZ-ROCBA-E01-PLASO
evidence_root: external
output_root: /cases/BLITZ-ROCBA-E01-PLASO/output
evidence:
  - id: rocba-e01
    path: "/absolute/path/to/Rocba-E01/<first-file>.E01"
    type: E01
    sha256: "<first E01 sha256>"
  - id: rocba-plaso
    path: "/absolute/path/to/Rocba-PLASO/<file>.plaso"
    type: PLASO
    sha256: "<plaso sha256>"
    internally_generated: true
```

Use the same `app.py analyze` command format and point `--manifest` to `/cases/BLITZ-ROCBA-E01-PLASO/case.yaml`.

## Manifest: Memory Plus EVTX

Prefer external mode if the memory image and EVTX files already live in different folders:

```yaml
case_id: BLITZ-ROCBA-MEMORY-EVTX
evidence_root: external
output_root: /cases/BLITZ-ROCBA-MEMORY-EVTX/output
evidence:
  - id: rocba-memory
    path: "/absolute/path/to/Rocba-Memory.raw"
    type: MEMORY
    sha256: "<memory sha256>"
  - id: security-evtx
    path: "/absolute/path/to/Security.evtx"
    type: EVTX
    sha256: "<evtx sha256>"
```

Use the same `app.py analyze` command format and point `--manifest` to `/cases/BLITZ-ROCBA-MEMORY-EVTX/case.yaml`.

## Important Limits

Blitz accepts up to six evidence records per manifest. E01 processing can be much slower than memory triage because `log2timeline.py` must process a disk image before Blitz can normalize and correlate the resulting timeline. If the E01 tool layer times out, preserve the run artifacts and treat the result as incomplete coverage, not as a clean verdict.
