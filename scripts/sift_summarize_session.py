#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: sift_summarize_session.py SESSION_DIR [EVIDENCE_PATH]", file=sys.stderr)
        return 2

    session = Path(sys.argv[1])
    evidence_path = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    if not session.is_dir():
        print(f"session directory not found: {session}", file=sys.stderr)
        return 2

    output: dict[str, Any] = {
        "session": str(session),
        "session_id": session.name,
        "state": _read_json(session / "audit" / "session_state.json"),
        "case_objective": _case_objective_summary(session / "findings" / "case_objective.json"),
        "investigation_plan": _investigation_plan_summary(session / "findings" / "investigation_plan.json"),
        "evidence_triage": _evidence_triage_summary(session / "findings" / "evidence_triage.json"),
        "stress_report": _read_json(session / "findings" / "stress_report.json"),
        "validation": _validation_summary(session / "findings" / "validation.json"),
        "unknowns": _unknowns_summary(session / "findings" / "unknowns.json"),
        "tool_results": _tool_summary(session / "findings" / "tool_results.json"),
        "full_accounting": _accounting_summary(session / "findings" / "full_accounting.json"),
        "artifact_manifest": _manifest_summary(session / "findings" / "artifact_manifest.json"),
        "timeline_csv": _timeline_summary(session),
        "event_store": _event_store_summary(session / "findings" / "event_store.sqlite"),
    }

    if evidence_path is not None and evidence_path.exists():
        output["evidence"] = {
            "path": str(evidence_path),
            "sha256": _sha256_file(evidence_path),
            "size_bytes": evidence_path.stat().st_size,
        }

    print(json.dumps(output, sort_keys=True, indent=2))
    return 0


def _read_json(path: Path) -> dict[str, Any] | list[Any] | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _validation_summary(path: Path) -> dict[str, Any] | None:
    data = _read_json(path)
    if not isinstance(data, dict):
        return None
    return {
        "passed": data.get("passed"),
        "issue_count": len(data.get("issues", [])),
        "parser_integrity_ok": data.get("parser_integrity_ok"),
        "issue_types": sorted({issue.get("issue_type") for issue in data.get("issues", []) if isinstance(issue, dict)}),
    }


def _case_objective_summary(path: Path) -> dict[str, Any] | None:
    data = _read_json(path)
    if not isinstance(data, dict):
        return None
    return {
        "schema_version": data.get("schema_version"),
        "source": data.get("source"),
        "objective": data.get("objective"),
        "evidence_ids_in_scope": data.get("evidence_ids_in_scope"),
        "success_criteria_count": len(data.get("success_criteria", [])),
        "constraint_count": len(data.get("constraints", [])),
    }


def _investigation_plan_summary(path: Path) -> dict[str, Any] | None:
    data = _read_json(path)
    if not isinstance(data, dict):
        return None
    return {
        "schema_version": data.get("schema_version"),
        "mode": data.get("mode"),
        "prioritized_artifact_families": data.get("prioritized_artifact_families"),
        "evidence_ids_in_scope": data.get("evidence_ids_in_scope"),
        "phase_count": len(data.get("phases", [])),
        "limitation_count": len(data.get("limitations", [])),
    }


def _evidence_triage_summary(path: Path) -> dict[str, Any] | None:
    data = _read_json(path)
    if not isinstance(data, dict):
        return None
    return {
        "schema_version": data.get("schema_version"),
        "evidence_count": data.get("evidence_count"),
        "critical_count": data.get("critical_count"),
        "high_count": data.get("high_count"),
        "medium_count": data.get("medium_count"),
        "low_count": data.get("low_count"),
        "prioritized_evidence_ids": data.get("prioritized_evidence_ids"),
        "limitation_count": len(data.get("limitations", [])),
    }


def _unknowns_summary(path: Path) -> dict[str, Any] | None:
    data = _read_json(path)
    if not isinstance(data, dict):
        return None
    return {
        "unknown_count": data.get("unknown_count"),
        "critical_count": data.get("critical_count"),
        "high_count": data.get("high_count"),
    }


def _tool_summary(path: Path) -> list[dict[str, Any]]:
    data = _read_json(path)
    if not isinstance(data, list):
        return []
    output = []
    for item in data:
        if not isinstance(item, dict):
            continue
        execution = item.get("execution", {})
        outputs = item.get("outputs", {})
        output.append(
            {
                "tool_name": item.get("tool_name"),
                "typed_tool": item.get("typed_tool"),
                "evidence_id": item.get("evidence_id"),
                "exit_code": execution.get("exit_code") if isinstance(execution, dict) else None,
                "timed_out": execution.get("timed_out") if isinstance(execution, dict) else None,
                "duration_ms": execution.get("duration_ms") if isinstance(execution, dict) else None,
                "primary_output": outputs.get("primary_output") if isinstance(outputs, dict) else None,
                "output_hash": outputs.get("output_hash") if isinstance(outputs, dict) else None,
            }
        )
    return output


def _accounting_summary(path: Path) -> dict[str, Any] | None:
    data = _read_json(path)
    if not isinstance(data, dict):
        return None
    artifacts = data.get("artifacts", [])
    return {
        "artifact_count": data.get("artifact_count"),
        "total_rows": data.get("total_rows"),
        "artifact_rows": [
            {
                "evidence_id": artifact.get("evidence_id"),
                "row_count": artifact.get("row_count"),
                "partial": artifact.get("partial"),
                "malformed_count": artifact.get("malformed_count"),
                "counts_by_data_type": artifact.get("counts_by_data_type"),
            }
            for artifact in artifacts
            if isinstance(artifact, dict)
        ],
    }


def _manifest_summary(path: Path) -> dict[str, Any] | None:
    data = _read_json(path)
    if not isinstance(data, dict):
        return None
    return {
        "artifact_count": data.get("artifact_count"),
        "manifest_sha256": data.get("manifest_sha256"),
    }


def _timeline_summary(session: Path) -> list[dict[str, Any]]:
    output = []
    for csv_path in sorted((session / "timelines").glob("*.csv")):
        output.append(
            {
                "path": str(csv_path),
                "size_bytes": csv_path.stat().st_size,
                "line_count": _count_lines(csv_path),
                "sha256": _sha256_file(csv_path),
            }
        )
    return output


def _event_store_summary(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    summary: dict[str, Any] = {"path": str(path), "size_bytes": path.stat().st_size, "sha256": _sha256_file(path)}
    try:
        with sqlite3.connect(path) as conn:
            summary["event_rows"] = conn.execute("select count(*) from event_rows").fetchone()[0]
    except sqlite3.Error as exc:
        summary["error"] = str(exc)
    return summary


def _count_lines(path: Path) -> int:
    total = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            total += chunk.count(b"\n")
    return total


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
