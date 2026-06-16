#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export ENABLE_REASONING=0
export RUN_MODE=clean
export RUN_SUFFIX="${RUN_SUFFIX:-rocba_memory_no_llm}"
exec bash "${SCRIPT_DIR}/sift_memory_run.sh" "$@"

