#!/usr/bin/env bash
set -euo pipefail

CASE="${CASE:-BLITZ-RD01-PLASO}"
CASE_ROOT="/cases/${CASE}"
PROOF_DIR="${CASE_ROOT}/proof_exports"
APPLY="${APPLY:-0}"
DELETE_ALL="${DELETE_ALL:-0}"

df_unique() {
  {
    df -h "$@" 2>/dev/null || df -h / 2>/dev/null || true
  } | awk 'NR == 1 { print; next } !seen[$1 "|" $6]++'
}

if [[ "${CASE_ROOT}" != /cases/* ]]; then
  echo "refusing unsafe case root: ${CASE_ROOT}" >&2
  exit 2
fi

if [[ ! -d "${PROOF_DIR}" ]]; then
  echo "proof export directory not found: ${PROOF_DIR}" >&2
  exit 2
fi

echo "[case]"
echo "${CASE_ROOT}"

echo
echo "[proof exports]"
echo "${PROOF_DIR}"

echo
echo "[keep by default]"
printf '%s\n' \
  "*.sha256 sidecars" \
  "*.txt captures"

echo
echo "[disk before]"
df_unique "${CASE_ROOT}" /

if [[ "${DELETE_ALL}" == "1" ]]; then
  mapfile -t CANDIDATES < <(find "${PROOF_DIR}" -maxdepth 1 -type f -print 2>/dev/null | sort)
else
  mapfile -t CANDIDATES < <(
    find "${PROOF_DIR}" -maxdepth 1 -type f \
      \( -name '*.tar' -o -name '*.tar.gz' -o -name '*.zip' \) \
      -print 2>/dev/null | sort
  )
fi

echo
echo "[delete candidates]"
if [[ "${#CANDIDATES[@]}" -eq 0 ]]; then
  echo "none"
else
  ls -lh -- "${CANDIDATES[@]}"
fi

if [[ "${APPLY}" != "1" ]]; then
  echo
  echo "dry run only. Re-run with APPLY=1 after verifying the host copy and hash."
  echo "Set DELETE_ALL=1 only if you also want to delete small sidecars/captures."
  exit 0
fi

if [[ "${#CANDIDATES[@]}" -gt 0 ]]; then
  rm -f -- "${CANDIDATES[@]}"
fi

echo
echo "[disk after]"
df_unique "${CASE_ROOT}" /
