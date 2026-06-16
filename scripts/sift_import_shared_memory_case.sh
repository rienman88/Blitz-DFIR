#!/usr/bin/env bash
set -euo pipefail

CASE="${CASE:-BLITZ-ROCBA-MEMORY}"
SRC="${SRC:-/mnt/hgfs/Forensics/cases/raw/Rocba/Rocba memory/Rocba-Memory}"
EVIDENCE_ID="${EVIDENCE_ID:-rocba-memory}"
CASE_ROOT="${CASE_ROOT:-/cases/${CASE}}"
RAW_DIR="${RAW_DIR:-${CASE_ROOT}/raw}"
OUTPUT_DIR="${OUTPUT_DIR:-${CASE_ROOT}/output}"
DESCRIPTION="${DESCRIPTION:-Rocba memory image copied from VMware shared folder to SIFT-local raw evidence storage.}"

if [[ ! -e "$SRC" ]]; then
  echo "source_not_found=$SRC" >&2
  echo "If VMware mounted the share under a different name, run: find /mnt/hgfs -maxdepth 5 -iname 'Rocba-Memory*' -print" >&2
  exit 1
fi

mkdir -p "$RAW_DIR" "$OUTPUT_DIR" "$CASE_ROOT/analysis/run_receipts" "$CASE_ROOT/analysis/failed_run_receipts"

base_name="$(basename "$SRC")"
if [[ -d "$SRC" ]]; then
  DEST="$RAW_DIR/$base_name"
  mkdir -p "$DEST"
  if command -v rsync >/dev/null 2>&1; then
    rsync -aH --info=progress2 --partial --append-verify --sparse "$SRC/" "$DEST/"
  else
    cp -a --reflink=auto --sparse=always "$SRC/." "$DEST/"
  fi
else
  DEST="$RAW_DIR/$base_name"
  if command -v rsync >/dev/null 2>&1; then
    rsync -aH --info=progress2 --partial --append-verify --sparse "$SRC" "$RAW_DIR/"
  else
    cp -a --reflink=auto --sparse=always "$SRC" "$RAW_DIR/"
  fi
fi

if [[ -f "$DEST" ]]; then
  MEMORY_FILE="$DEST"
else
  MEMORY_FILE="$(
    find "$DEST" -type f \( \
      -iname "*.raw" -o -iname "*.mem" -o -iname "*.vmem" -o -iname "*.dmp" -o -iname "*memory*" \
    \) -printf '%s\t%p\n' | sort -nr | head -n 1 | cut -f 2-
  )"
  if [[ -z "$MEMORY_FILE" ]]; then
    MEMORY_FILE="$(find "$DEST" -type f -printf '%s\t%p\n' | sort -nr | head -n 1 | cut -f 2-)"
  fi
fi

if [[ -z "${MEMORY_FILE:-}" || ! -f "$MEMORY_FILE" ]]; then
  echo "memory_file_not_found_under=$DEST" >&2
  exit 1
fi

HASH="$(sha256sum "$MEMORY_FILE" | awk '{print $1}')"
RELATIVE_PATH="$(realpath --relative-to="$RAW_DIR" "$MEMORY_FILE")"

chmod u+w "${MEMORY_FILE}.sha256" "$CASE_ROOT/case.yaml" 2>/dev/null || true
printf '%s  %s\n' "$HASH" "$MEMORY_FILE" | tee "${MEMORY_FILE}.sha256" >/dev/null

cat > "$CASE_ROOT/case.yaml" <<EOF
case_id: $CASE
evidence_root: $RAW_DIR
output_root: $OUTPUT_DIR
evidence:
  - id: $EVIDENCE_ID
    path: "$RELATIVE_PATH"
    type: MEMORY
    sha256: $HASH
    description: "$DESCRIPTION"
EOF

chmod a-w "$MEMORY_FILE" "${MEMORY_FILE}.sha256" "$CASE_ROOT/case.yaml"

echo "import_completed=1"
echo "case_root=$CASE_ROOT"
echo "raw_dir=$RAW_DIR"
echo "memory_file=$MEMORY_FILE"
echo "sha256=$HASH"
echo "manifest=$CASE_ROOT/case.yaml"
ls -lh "$MEMORY_FILE" "${MEMORY_FILE}.sha256" "$CASE_ROOT/case.yaml"
