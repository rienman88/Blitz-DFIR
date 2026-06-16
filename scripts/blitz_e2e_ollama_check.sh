#!/usr/bin/env bash
set -euo pipefail

CASE="${CASE:-BLITZ-RD01-PLASO}"
SESSION="${1:-${SESSION:-}}"

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
import sqlite3
import sys
from pathlib import Path

session = Path(sys.argv[1])
state_path = session / "audit" / "session_state.json"
progress_path = session / "audit" / "progress.json"
report_path = session / "reports" / "report.json"
evidence_maturity_path = session / "findings" / "evidence_maturity.json"
case_objective_path = session / "findings" / "case_objective.json"
investigation_plan_path = session / "findings" / "investigation_plan.json"
evidence_triage_path = session / "findings" / "evidence_triage.json"
investigation_guidance_path = session / "findings" / "investigation_guidance.json"
evidentiary_weighting_path = session / "findings" / "evidentiary_weighting.json"
contradiction_analysis_path = session / "findings" / "contradiction_analysis.json"
finding_provenance_path = session / "reports" / "finding_provenance.md"
event_store_path = session / "findings" / "event_store.sqlite"

failures: list[str] = []


def load_json(path: Path) -> dict:
    if not path.exists():
        failures.append(f"missing {path.relative_to(session)}")
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        failures.append(f"invalid JSON {path.relative_to(session)}: {exc}")
        return {}
    return value if isinstance(value, dict) else {}


def audit_events() -> list[dict]:
    entries: list[dict] = []
    for audit_path in sorted((session / "audit").glob("*.ndjson")):
        for line in audit_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                entries.append(payload)
    return entries


state = load_json(state_path)
progress = load_json(progress_path)
report = load_json(report_path)
evidence_maturity = load_json(evidence_maturity_path)
case_objective = load_json(case_objective_path)
investigation_plan = load_json(investigation_plan_path)
evidence_triage = load_json(evidence_triage_path)
investigation_guidance = load_json(investigation_guidance_path)
evidentiary_weighting = load_json(evidentiary_weighting_path)
contradiction_analysis = load_json(contradiction_analysis_path)
entries = audit_events()
event_types = [str(item.get("event_type")) for item in entries]

if state.get("status") != "COMPLETED":
    failures.append(f"session_state status is {state.get('status')!r}, expected COMPLETED")
if state.get("phase") != "analysis_completed":
    failures.append(f"session_state phase is {state.get('phase')!r}, expected analysis_completed")
if progress.get("status") != "COMPLETED":
    failures.append(f"progress status is {progress.get('status')!r}, expected COMPLETED")

layers = {
    str(layer.get("layer_id")): layer
    for layer in progress.get("layers", [])
    if isinstance(layer, dict)
}
for required in (
    "manifest_integrity",
    "protocol_sift_workflow",
    "case_objective",
    "tool_discovery",
    "investigation_planning",
    "batch_planning",
    "evidence_inventory",
    "recovery_planning",
    "evidence_triage",
    "typed_tool_execution",
    "parsing",
    "normalization",
    "object_inventory",
    "full_accounting",
    "sqlite_event_store",
    "correlation",
    "investigation_guidance",
    "evidentiary_weighting",
    "contradiction_analysis",
    "validation",
    "unknowns",
    "bounded_llm_reasoning",
    "report_generation",
    "evidence_maturity",
    "audit_finalization",
):
    if required not in layers:
        failures.append(f"progress layer missing: {required}")

llm_layer = layers.get("bounded_llm_reasoning") or {}
if llm_layer.get("status") != "COMPLETED":
    failures.append(
        "bounded_llm_reasoning layer is "
        f"{llm_layer.get('status')!r}; expected COMPLETED for Ollama E2E"
    )

for required_event in (
    "manifest_loaded",
    "protocol_sift_workflow_recorded",
    "case_objective_defined",
    "investigation_plan_completed",
    "tool_discovery_completed",
    "evidence_inventory_completed",
    "recovery_plan_created",
    "evidence_triage_completed",
    "batch_completed",
    "sqlite_normalization_completed",
    "object_inventory_completed",
    "full_accounting_completed",
    "sql_correlation_completed",
    "correlation_completed",
    "investigation_guidance_generated",
    "evidentiary_weighting_completed",
    "contradiction_analysis_completed",
    "validation_completed",
    "unknowns_completed",
    "reasoning_completed",
    "evidence_maturity_written",
    "reports_written",
    "analysis_completed",
):
    if required_event not in event_types:
        failures.append(f"audit event missing: {required_event}")

reasoning = report.get("inferred_analyst_reasoning")
if not isinstance(reasoning, dict):
    failures.append("report inferred_analyst_reasoning is missing or not an object")
if case_objective.get("schema_version") != "case-objective.v1":
    failures.append("case_objective schema_version missing or unexpected")
if investigation_plan.get("schema_version") != "investigation-plan.v1":
    failures.append("investigation_plan schema_version missing or unexpected")
if evidence_triage.get("schema_version") != "evidence-triage.v1":
    failures.append("evidence_triage schema_version missing or unexpected")
if investigation_guidance.get("schema_version") != "investigation-guidance.v1":
    failures.append("investigation_guidance schema_version missing or unexpected")
if not isinstance(report.get("case_objective"), dict):
    failures.append("report case_objective section is missing or not an object")
if not isinstance(report.get("investigation_plan"), dict):
    failures.append("report investigation_plan section is missing or not an object")
if not isinstance(report.get("evidence_triage"), dict):
    failures.append("report evidence_triage section is missing or not an object")
if not isinstance(report.get("investigation_guidance"), dict):
    failures.append("report investigation_guidance section is missing or not an object")
provider = reasoning.get("provider_metadata")
if not isinstance(provider, dict):
    failures.append("report reasoning provider_metadata missing")
if not reasoning.get("prompt_hash"):
    failures.append("report reasoning prompt_hash missing")

if evidence_maturity.get("schema_version") != "evidence-maturity.v1":
    failures.append("evidence_maturity schema_version missing or unexpected")
if not evidence_maturity.get("summary", {}).get("evidence_hashes_preserved"):
    failures.append("evidence_maturity did not record preserved evidence hashes")
if evidentiary_weighting.get("schema_version") != "evidentiary-weighting.v1":
    failures.append("evidentiary_weighting schema_version missing or unexpected")
if contradiction_analysis.get("schema_version") != "evidence-contradiction-analysis.v1":
    failures.append("contradiction_analysis schema_version missing or unexpected")
if not finding_provenance_path.exists():
    failures.append("finding_provenance.md missing")
else:
    provenance_text = finding_provenance_path.read_text(encoding="utf-8", errors="replace")
    if "flowchart LR" not in provenance_text:
        failures.append("finding_provenance.md does not include Mermaid flowchart provenance")

normalized_count = None
accounting_count = None
if not event_store_path.exists():
    failures.append("event_store.sqlite missing")
else:
    with sqlite3.connect(event_store_path) as db:
        try:
            normalized_count = int(db.execute("select count(*) from normalized_events").fetchone()[0])
        except sqlite3.Error as exc:
            failures.append(f"normalized_events count failed: {exc}")
        try:
            accounting_count = int(db.execute("select count(*) from event_rows").fetchone()[0])
        except sqlite3.Error as exc:
            failures.append(f"event_rows count failed: {exc}")

print(f"session={session}")
print(f"status={state.get('status')} phase={state.get('phase')}")
print(f"progress_status={progress.get('status')} overall={progress.get('overall_percent')}")
print(f"llm_layer_status={llm_layer.get('status')} details={llm_layer.get('details')}")
print(f"normalized_events={normalized_count}")
print(f"accounting_rows={accounting_count}")
print(f"evidence_maturity={evidence_maturity_path}")
print(f"case_objective={case_objective_path}")
print(f"investigation_plan={investigation_plan_path}")
print(f"evidence_triage={evidence_triage_path}")
print(f"investigation_guidance={investigation_guidance_path}")
print(f"evidentiary_weighting={evidentiary_weighting_path}")
print(f"contradiction_analysis={contradiction_analysis_path}")
print(f"finding_provenance={finding_provenance_path}")

if failures:
    print()
    print("[FAILED CHECKS]")
    for failure in failures:
        print(f"- {failure}")
    raise SystemExit(1)

print()
print("e2e_ollama_check=passed")
PY
