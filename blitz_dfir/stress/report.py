from __future__ import annotations

from pathlib import Path
from typing import Any

from blitz_dfir.accounting.models import FullAccountingSummary
from blitz_dfir.core.session import CaseSession
from blitz_dfir.correction.models import ValidationReport
from blitz_dfir.signal.integrity import SignalIntegrityReport


def build_stress_report(
    *,
    session: CaseSession,
    tool_results: list[dict[str, Any]],
    full_accounting: FullAccountingSummary,
    normalized_event_count: int,
    validation_report: ValidationReport,
    signal_report: SignalIntegrityReport,
) -> dict[str, Any]:
    artifacts = _session_artifacts(session.session_root)
    timed_out_tools = [
        str(result.get("typed_tool") or result.get("tool_name") or "unknown")
        for result in tool_results
        if _dict_value(result, "execution").get("timed_out") is True
    ]
    status = "passed"
    if timed_out_tools or signal_report.critical_count or validation_report.issues:
        status = "needs_review"
    if full_accounting.total_rows == 0 and tool_results:
        status = "failed" if normalized_event_count == 0 else "needs_review"
    return {
        "schema_version": "stress-report.v1",
        "case_id": session.case_id,
        "session_id": session.session_id,
        "status": status,
        "tool_count": len(tool_results),
        "timed_out_tools": timed_out_tools,
        "normalized_event_count": normalized_event_count,
        "full_accounting_total_rows": full_accounting.total_rows,
        "full_accounting_artifacts": full_accounting.artifact_count,
        "validation_passed": validation_report.passed,
        "validation_issue_count": len(validation_report.issues),
        "signal_warning_count": len(signal_report.warnings),
        "signal_critical_count": signal_report.critical_count,
        "signal_high_count": signal_report.high_count,
        "session_artifacts": artifacts,
    }


def _session_artifacts(root: Path) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    if not root.exists():
        return artifacts
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        artifacts.append(
            {
                "path": str(path.relative_to(root)).replace("\\", "/"),
                "size_bytes": path.stat().st_size,
            }
        )
    return artifacts


def _dict_value(value: dict[str, Any], key: str) -> dict[str, Any]:
    item = value.get(key)
    return item if isinstance(item, dict) else {}
