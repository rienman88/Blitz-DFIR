#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export ENABLE_REASONING=0
exec bash "${SCRIPT_DIR}/sift_run_external_evidence.sh" "$@"
