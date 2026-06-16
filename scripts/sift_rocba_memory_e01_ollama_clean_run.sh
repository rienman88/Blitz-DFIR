#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export ENABLE_REASONING=1
export RUN_SUFFIX="${RUN_SUFFIX:-rocba_memory_e01_ollama}"
exec bash "${SCRIPT_DIR}/sift_rocba_memory_e01_clean_run.sh" "$@"
