from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from blitz_dfir.core.integrity import hash_text, sha256_file
from blitz_dfir.core.session import CaseSession

SessionStatus = Literal["RUNNING", "COMPLETED", "FAILED", "PARTIAL"]


def write_session_state(
    *,
    session: CaseSession,
    status: SessionStatus,
    phase: str,
    details: dict[str, Any] | None = None,
) -> Path:
    path = session.audit_dir / "session_state.json"
    payload = {
        "schema_version": "session-state.v1",
        "case_id": session.case_id,
        "session_id": session.session_id,
        "status": status,
        "phase": phase,
        "timestamp_utc": _now(),
        "details": details or {},
    }
    payload["state_hash"] = hash_text(_canonical_json(payload))
    _atomic_write_json(path, payload)
    return path


def write_artifact_manifest(
    *,
    session: CaseSession,
    status: SessionStatus,
    excluded_paths: set[Path] | None = None,
) -> Path:
    path = session.findings_dir / "artifact_manifest.json"
    excluded = {path.resolve(), *(item.resolve() for item in (excluded_paths or set()))}
    artifacts = []
    for artifact in sorted(item for item in session.session_root.rglob("*") if item.is_file()):
        resolved = artifact.resolve()
        if resolved in excluded:
            continue
        artifacts.append(
            {
                "path": str(artifact.relative_to(session.session_root)).replace("\\", "/"),
                "size_bytes": artifact.stat().st_size,
                "sha256": sha256_file(artifact),
            }
        )
    payload = {
        "schema_version": "artifact-manifest.v1",
        "case_id": session.case_id,
        "session_id": session.session_id,
        "status": status,
        "timestamp_utc": _now(),
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "self_excluded": str(path.relative_to(session.session_root)).replace("\\", "/"),
    }
    payload["manifest_hash"] = hash_text(_canonical_json(payload))
    _atomic_write_json(path, payload)
    return path


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def _canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
