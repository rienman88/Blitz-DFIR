#!/usr/bin/env bash
set -euo pipefail

CASE="${CASE:-BLITZ-RD01-PLASO}"
ROOT="${ROOT:-/cases/${CASE}/output}"
RECEIPTS="${RECEIPTS:-/cases/${CASE}/analysis/run_receipts}"
KEEP="${KEEP:-}"
APPLY="${APPLY:-0}"

mkdir -p "$RECEIPTS"

echo "[disk before]"
df -h "/cases/${CASE}" /

echo
echo "[candidate sessions]"
du -sh "${ROOT}"/sess-* 2>/dev/null | sort -h || true

for session in "${ROOT}"/sess-*; do
  [ -d "$session" ] || continue
  session_id="$(basename "$session")"
  if [ -n "$KEEP" ] && [ "$session_id" = "$KEEP" ]; then
    echo "keeping explicit session: $session_id"
    continue
  fi

  mkdir -p "${RECEIPTS}/${session_id}"
  cp -a "${session}/audit/session_state.json" "${RECEIPTS}/${session_id}/" 2>/dev/null || true
  cp -a "${session}/findings/artifact_manifest.json" "${RECEIPTS}/${session_id}/" 2>/dev/null || true
  cp -a "${session}/findings/stress_report.json" "${RECEIPTS}/${session_id}/" 2>/dev/null || true
  cp -a "${session}/findings/full_accounting.json" "${RECEIPTS}/${session_id}/" 2>/dev/null || true
  cp -a "${session}/findings/validation.json" "${RECEIPTS}/${session_id}/" 2>/dev/null || true
  cp -a "${session}/findings/unknowns.json" "${RECEIPTS}/${session_id}/" 2>/dev/null || true

  case "$session" in
    "${ROOT}"/sess-*)
      if [ "$APPLY" = "1" ]; then
        echo "deleting session: $session"
        rm -rf -- "$session"
      else
        echo "dry-run would delete: $session"
      fi
      ;;
    *)
      echo "refusing unsafe path: $session"
      ;;
  esac
done

find "$RECEIPTS" -type f -exec sha256sum {} \; > "${RECEIPTS}/receipt_hashes.sha256"

echo
echo "[disk after]"
df -h "/cases/${CASE}" /

if [ "$APPLY" != "1" ]; then
  echo
  echo "dry run only. Re-run with APPLY=1 after reviewing candidates."
fi
