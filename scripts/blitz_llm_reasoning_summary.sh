#!/usr/bin/env bash
set -euo pipefail

CASE="${CASE:-BLITZ-RD01-PLASO}"
SESSION="${1:-${SESSION:-}}"

if [[ -z "${SESSION}" ]]; then
  RUN_ROOT="$(ls -td "/cases/${CASE}/analysis/runs"/* 2>/dev/null | head -n 1 || true)"
  if [[ -n "${RUN_ROOT}" && -f "${RUN_ROOT}/session_path.txt" ]]; then
    SESSION="$(cat "${RUN_ROOT}/session_path.txt")"
  fi
fi

if [[ -z "${SESSION}" ]]; then
  SESSION="$(ls -td "/cases/${CASE}/output"/sess-* 2>/dev/null | head -n 1 || true)"
fi

if [[ -z "${SESSION}" || ! -d "${SESSION}" ]]; then
  echo "no session found for CASE=${CASE}" >&2
  exit 2
fi

python - "${SESSION}" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

session = Path(sys.argv[1])
report_path = session / "reports" / "report.json"
progress_path = session / "audit" / "progress.json"
state_path = session / "audit" / "session_state.json"


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def find_layer(progress: dict, layer_id: str) -> dict:
    for layer in progress.get("layers", []):
        if isinstance(layer, dict) and layer.get("layer_id") == layer_id:
            return layer
    return {}


state = load_json(state_path)
progress = load_json(progress_path)
report = load_json(report_path)
reasoning = report.get("inferred_analyst_reasoning")
llm_layer = find_layer(progress, "bounded_llm_reasoning")

print(f"session={session}")
print(f"session_status={state.get('status')} phase={state.get('phase')}")
print(f"llm_layer_status={llm_layer.get('status')}")
if llm_layer.get("details"):
    print(f"llm_layer_details={json.dumps(llm_layer.get('details'), sort_keys=True)}")

if not isinstance(reasoning, dict) or not reasoning:
    print("reasoning_section=missing_or_empty")
    raise SystemExit(1)

provider = reasoning.get("provider_metadata")
token_usage = reasoning.get("token_usage")
hypotheses = reasoning.get("hypotheses") if isinstance(reasoning.get("hypotheses"), list) else []
decisions = reasoning.get("decisions") if isinstance(reasoning.get("decisions"), list) else []
limits = reasoning.get("analysis_limits") if isinstance(reasoning.get("analysis_limits"), list) else []

print("reasoning_section=present")
print(f"evidence_type={reasoning.get('evidence_type')}")
print(f"prompt_hash={reasoning.get('prompt_hash')}")
print(f"provider={provider.get('provider') if isinstance(provider, dict) else None}")
print(f"model={provider.get('model') if isinstance(provider, dict) else None}")
print(f"base_url={provider.get('base_url') if isinstance(provider, dict) else None}")
print(f"token_usage={json.dumps(token_usage, sort_keys=True) if isinstance(token_usage, dict) else None}")
print(f"hypothesis_count={len(hypotheses)}")
print(f"decision_count={len(decisions)}")
print(f"analysis_limit_count={len(limits)}")

print()
print("[narrative preview]")
narrative = str(reasoning.get("narrative") or "")
print(narrative[:1200] if narrative else "<empty>")

print()
print("[first hypotheses]")
for index, hypothesis in enumerate(hypotheses[:5], start=1):
    if not isinstance(hypothesis, dict):
        continue
    print(
        f"{index}. status={hypothesis.get('status')} "
        f"confidence={hypothesis.get('confidence')} "
        f"events={hypothesis.get('evidence_event_ids')}"
    )
    print(f"   hypothesis={hypothesis.get('hypothesis')}")
    print(f"   rationale={hypothesis.get('rationale')}")

print()
print("[first decisions]")
for index, decision in enumerate(decisions[:5], start=1):
    if not isinstance(decision, dict):
        continue
    print(f"{index}. id={decision.get('decision_id')} events={decision.get('evidence_event_ids')}")
    print(f"   why={decision.get('why')}")
    print(f"   expected={decision.get('expected')}")
    print(f"   actual={decision.get('actual')}")

print()
print("[safety interpretation]")
print("raw_evidence_sent=false")
print("raw_tool_output_sent=false")
print("deterministic_blitz_findings_are_authoritative=true")
print("llm_reasoning_is_inferred_explanation_only=true")
PY
