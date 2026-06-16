from __future__ import annotations

import hashlib
import json

from blitz_dfir.audit.session_integrity import write_artifact_manifest, write_session_state
from blitz_dfir.audit.progress import write_progress_state
from blitz_dfir.core.manifest import load_manifest
from blitz_dfir.core.session import create_session


def test_session_state_records_status_phase_and_hash(tmp_path):
    session = _session(tmp_path)

    path = write_session_state(
        session=session,
        status="RUNNING",
        phase="normalization_completed",
        details={"event_count": 5000},
    )

    payload = json.loads(path.read_text(encoding="utf-8"))
    state_hash = payload.pop("state_hash")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    assert payload["status"] == "RUNNING"
    assert payload["phase"] == "normalization_completed"
    assert state_hash == hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def test_artifact_manifest_hashes_session_outputs_and_detects_tamper(tmp_path):
    session = _session(tmp_path)
    report = session.reports_dir / "report.json"
    report.write_text('{"ok": true}\n', encoding="utf-8")

    manifest_path = write_artifact_manifest(session=session, status="COMPLETED")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifacts = {item["path"]: item for item in manifest["artifacts"]}
    original_hash = artifacts["reports/report.json"]["sha256"]

    report.write_text('{"ok": false}\n', encoding="utf-8")

    assert hashlib.sha256(report.read_bytes()).hexdigest() != original_hash
    assert "findings/artifact_manifest.json" not in artifacts


def test_progress_state_tracks_layers_percent_and_eta(tmp_path):
    session = _session(tmp_path)

    path = write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="manifest_integrity",
        layer_status="COMPLETED",
        details={"evidence_count": 1},
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="normalization",
        layer_status="RUNNING",
        processed_items=25,
        total_items=100,
    )

    payload = json.loads(path.read_text(encoding="utf-8"))
    layers = {layer["layer_id"]: layer for layer in payload["layers"]}
    assert payload["status"] == "RUNNING"
    assert payload["current_layer"] == "normalization"
    assert payload["writer_pid"] > 0
    assert layers["manifest_integrity"]["status"] == "COMPLETED"
    assert layers["protocol_sift_workflow"]["name"] == "Protocol SIFT workflow context"
    assert layers["case_objective"]["name"] == "Case objective definition"
    assert layers["investigation_planning"]["name"] == "Investigation planning"
    assert layers["evidence_triage"]["name"] == "Evidence triage"
    assert layers["normalization"]["percent"] == 25.0
    assert layers["tool_discovery"]["name"] == "Tool discovery"
    assert layers["batch_planning"]["name"] == "Batch planning"
    assert layers["evidence_inventory"]["name"] == "Evidence inventory"
    assert layers["recovery_planning"]["name"] == "Recovery planning"
    assert layers["sqlite_event_store"]["name"] == "SQLite event store"
    assert layers["investigation_guidance"]["name"] == "Investigation guidance"
    assert layers["bounded_llm_reasoning"]["name"] == "Bounded LLM reasoning over validated summaries"
    assert payload["overall_percent"] > 0
    assert payload["progress_hash"]


def test_progress_completion_replaces_stale_running_counters(tmp_path):
    session = _session(tmp_path)

    path = write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="parsing",
        layer_status="RUNNING",
        processed_items=0,
        total_items=1,
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="parsing",
        layer_status="COMPLETED",
        details={"parser_result_count": 1},
    )

    payload = json.loads(path.read_text(encoding="utf-8"))
    layers = {layer["layer_id"]: layer for layer in payload["layers"]}
    assert layers["parsing"]["status"] == "COMPLETED"
    assert layers["parsing"]["processed_items"] == 1
    assert layers["parsing"]["total_items"] == 1


def test_progress_completion_can_override_running_cap_with_actual_count(tmp_path):
    session = _session(tmp_path)

    path = write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="normalization",
        layer_status="RUNNING",
        processed_items=0,
        total_items=2_000_000,
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="normalization",
        layer_status="COMPLETED",
        details={"event_count": 1_329_652},
        processed_items=1_329_652,
        total_items=1_329_652,
    )

    payload = json.loads(path.read_text(encoding="utf-8"))
    layers = {layer["layer_id"]: layer for layer in payload["layers"]}
    assert layers["normalization"]["status"] == "COMPLETED"
    assert layers["normalization"]["processed_items"] == 1_329_652
    assert layers["normalization"]["total_items"] == 1_329_652


def test_progress_state_marks_bounded_llm_skipped_as_non_blocking(tmp_path):
    session = _session(tmp_path)

    path = write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="bounded_llm_reasoning",
        layer_status="SKIPPED",
        details={"enabled": False, "reason": "not_enabled"},
    )

    payload = json.loads(path.read_text(encoding="utf-8"))
    layers = {layer["layer_id"]: layer for layer in payload["layers"]}
    assert layers["bounded_llm_reasoning"]["status"] == "SKIPPED"
    assert layers["bounded_llm_reasoning"]["percent"] == 100.0
    assert layers["report_generation"]["status"] == "PENDING"
    assert layers["audit_finalization"]["status"] == "PENDING"


def _session(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    evidence = evidence_root / "Security.evtx"
    evidence.write_bytes(b"evtx")
    manifest_path = tmp_path / "case.yaml"
    manifest_path.write_text(
        f"""
case_id: integrity-case
evidence_root: evidence
output_root: output
evidence:
  - id: security
    path: Security.evtx
    type: EVTX
    sha256: {hashlib.sha256(b"evtx").hexdigest()}
""".strip(),
        encoding="utf-8",
    )
    return create_session(load_manifest(manifest_path))
