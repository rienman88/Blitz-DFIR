from __future__ import annotations

import json
import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from blitz_dfir.core.integrity import hash_text
from blitz_dfir.core.session import CaseSession

ProgressStatus = Literal["RUNNING", "COMPLETED", "FAILED", "PARTIAL"]
LayerStatus = Literal["PENDING", "RUNNING", "COMPLETED", "FAILED", "SKIPPED"]

PROGRESS_LAYERS: tuple[tuple[str, str, int], ...] = (
    ("manifest_integrity", "Manifest and evidence integrity", 5),
    ("protocol_sift_workflow", "Protocol SIFT workflow context", 3),
    ("case_objective", "Case objective definition", 2),
    ("tool_discovery", "Tool discovery", 4),
    ("investigation_planning", "Investigation planning", 4),
    ("batch_planning", "Batch planning", 4),
    ("evidence_inventory", "Evidence inventory", 4),
    ("recovery_planning", "Recovery planning", 4),
    ("evidence_triage", "Evidence triage", 4),
    ("typed_tool_execution", "Typed SIFT tool execution", 20),
    ("parsing", "Parser result extraction", 8),
    ("normalization", "SQLite-backed normalization", 11),
    ("object_inventory", "Object inventory", 6),
    ("full_accounting", "Full accounting", 6),
    ("sqlite_event_store", "SQLite event store", 8),
    ("correlation", "Correlation and suspicion scoring", 12),
    ("investigation_guidance", "Investigation guidance", 2),
    ("temporal_analysis", "Temporal gap and attack-stage timeline", 2),
    ("evidentiary_weighting", "Evidentiary weighting", 2),
    ("contradiction_analysis", "Evidence contradiction analysis", 2),
    ("validation", "Validation", 3),
    ("unknowns", "Unknowns and coverage", 3),
    ("bounded_llm_reasoning", "Bounded LLM reasoning over validated summaries", 4),
    ("llm_report_verification", "LLM report verification", 2),
    ("report_generation", "Report generation", 2),
    ("evidence_maturity", "Evidence maturity traceability", 2),
    ("agent_trace", "Agent trace and investigative journal", 2),
    ("collated_outputs", "Overall findings, reports, and collated audit", 1),
    ("audit_finalization", "Audit finalization and artifact hashes", 1),
)


def write_progress_state(
    *,
    session: CaseSession,
    status: ProgressStatus,
    current_layer: str,
    layer_status: LayerStatus = "RUNNING",
    details: dict[str, Any] | None = None,
    processed_items: int | None = None,
    total_items: int | None = None,
) -> Path:
    path = session.audit_dir / "progress.json"
    now = _now_dt()
    payload = _load_or_initialize(path, session=session, started_at=now)
    layer_index = _layer_index(current_layer)
    layers = payload["layers"]

    for index, layer in enumerate(layers):
        if index < layer_index and layer["status"] == "PENDING":
            layer["status"] = "COMPLETED"
            layer["percent"] = 100.0
            layer["completed_at_utc"] = _format_dt(now)

    layer = layers[layer_index]
    if layer["status"] == "PENDING":
        layer["started_at_utc"] = _format_dt(now)
    layer["status"] = layer_status
    layer["updated_at_utc"] = _format_dt(now)
    if layer_status == "COMPLETED":
        layer["percent"] = 100.0
        layer["completed_at_utc"] = _format_dt(now)
    elif layer_status == "RUNNING":
        layer["percent"] = _layer_percent(processed_items=processed_items, total_items=total_items)
    elif layer_status == "SKIPPED":
        layer["percent"] = 100.0
        layer["completed_at_utc"] = _format_dt(now)
    elif layer_status == "FAILED":
        layer["completed_at_utc"] = _format_dt(now)
    if details is not None:
        layer["details"] = details
    if layer_status == "COMPLETED" and processed_items is None and total_items is None:
        existing_total = layer.get("total_items")
        if isinstance(existing_total, int) and existing_total > 0:
            processed_items = existing_total
            total_items = existing_total
    if processed_items is not None:
        layer["processed_items"] = processed_items
    if total_items is not None:
        layer["total_items"] = total_items

    overall_percent = _overall_percent(layers)
    started_at = _parse_dt(str(payload["started_at_utc"])) or now
    elapsed_seconds = max(int((now - started_at).total_seconds()), 0)
    eta_seconds = _eta_seconds(status=status, overall_percent=overall_percent, elapsed_seconds=elapsed_seconds)

    payload.update(
        {
            "case_id": session.case_id,
            "session_id": session.session_id,
            "status": status,
            "current_layer": current_layer,
            "current_layer_name": layer["name"],
            "updated_at_utc": _format_dt(now),
            "overall_percent": overall_percent,
            "elapsed_seconds": elapsed_seconds,
            "eta_seconds": eta_seconds,
            "eta_utc": _format_dt(now + timedelta(seconds=eta_seconds)) if eta_seconds is not None else None,
            "eta_quality": "coarse_weighted_stage_estimate" if eta_seconds is not None else "unavailable",
            "writer_pid": os.getpid(),
            "layers": layers,
            "operator_note": (
                "Progress is shell-readable and audit-adjacent. ETA is a coarse weighted-stage "
                "estimate and is most useful after at least one layer has completed."
            ),
        }
    )
    payload["progress_hash"] = hash_text(_canonical_json({k: v for k, v in payload.items() if k != "progress_hash"}))
    _atomic_write_json(path, payload)
    return path


@contextmanager
def progress_heartbeat(
    *,
    session: CaseSession,
    status: ProgressStatus,
    current_layer: str,
    details: dict[str, Any] | None = None,
    interval_seconds: int = 15,
) -> Iterator[None]:
    stop = threading.Event()
    base_details = dict(details or {})

    def beat() -> None:
        heartbeat_count = 0
        while not stop.wait(max(interval_seconds, 1)):
            heartbeat_count += 1
            payload = dict(base_details)
            payload.update(
                {
                    "heartbeat_count": heartbeat_count,
                    "heartbeat_utc": _format_dt(_now_dt()),
                }
            )
            write_progress_state(
                session=session,
                status=status,
                current_layer=current_layer,
                layer_status="RUNNING",
                details=payload,
            )

    thread = threading.Thread(target=beat, name="blitz-progress-heartbeat", daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=1.0)


def _load_or_initialize(path: Path, *, session: CaseSession, started_at: datetime) -> dict[str, Any]:
    if path.exists():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            payload = {}
        if isinstance(payload, dict) and isinstance(payload.get("layers"), list):
            existing_ids = [str(layer.get("layer_id")) for layer in payload.get("layers", []) if isinstance(layer, dict)]
            expected_ids = [layer_id for layer_id, _, _ in PROGRESS_LAYERS]
            if existing_ids != expected_ids:
                return _initialized_payload(session=session, started_at=started_at)
            return payload
    return _initialized_payload(session=session, started_at=started_at)


def _initialized_payload(*, session: CaseSession, started_at: datetime) -> dict[str, Any]:
    return {
        "schema_version": "progress-state.v1",
        "case_id": session.case_id,
        "session_id": session.session_id,
        "status": "RUNNING",
        "started_at_utc": _format_dt(started_at),
        "updated_at_utc": _format_dt(started_at),
        "overall_percent": 0.0,
        "elapsed_seconds": 0,
        "eta_seconds": None,
        "eta_utc": None,
        "layers": [
            {
                "layer_id": layer_id,
                "name": name,
                "weight": weight,
                "status": "PENDING",
                "percent": 0.0,
                "started_at_utc": None,
                "updated_at_utc": None,
                "completed_at_utc": None,
                "processed_items": None,
                "total_items": None,
                "details": {},
            }
            for layer_id, name, weight in PROGRESS_LAYERS
        ],
    }


def _layer_index(layer_id: str) -> int:
    for index, (candidate, _, _) in enumerate(PROGRESS_LAYERS):
        if candidate == layer_id:
            return index
    raise ValueError(f"unsupported progress layer: {layer_id}")


def _layer_percent(*, processed_items: int | None, total_items: int | None) -> float:
    if processed_items is None or total_items is None or total_items <= 0:
        return 10.0
    return round(min(max(processed_items / total_items, 0.0), 1.0) * 100.0, 2)


def _overall_percent(layers: list[dict[str, Any]]) -> float:
    total_weight = sum(float(layer["weight"]) for layer in layers)
    if total_weight <= 0:
        return 0.0
    completed_weight = sum(float(layer["weight"]) * float(layer["percent"]) / 100.0 for layer in layers)
    return round(min(max(completed_weight / total_weight, 0.0), 1.0) * 100.0, 2)


def _eta_seconds(
    *,
    status: ProgressStatus,
    overall_percent: float,
    elapsed_seconds: int,
) -> int | None:
    if status != "RUNNING" or overall_percent <= 0.0 or overall_percent >= 100.0:
        return None
    return max(int(elapsed_seconds * ((100.0 - overall_percent) / overall_percent)), 0)


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def _canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _now_dt() -> datetime:
    return datetime.now(UTC)


def _format_dt(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _parse_dt(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
