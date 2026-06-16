from __future__ import annotations

import hashlib
import json

from blitz_dfir.audit.audit_log import AuditLogger
from blitz_dfir.core.manifest import load_manifest
from blitz_dfir.core.session import create_session
from blitz_dfir.reporting.agent_trace import build_agent_trace, export_agent_trace, render_agent_journal


def test_agent_trace_writes_judge_readable_trace_and_journal(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    memory = evidence_root / "memory.raw"
    memory.write_bytes(b"memory")
    manifest_path = tmp_path / "case.yaml"
    manifest_path.write_text(
        f"""
case_id: case-agent-trace
evidence_root: evidence
output_root: output
evidence:
  - id: memory
    path: memory.raw
    type: MEMORY
    sha256: {hashlib.sha256(memory.read_bytes()).hexdigest()}
""".strip(),
        encoding="utf-8",
    )
    manifest = load_manifest(manifest_path)
    session = create_session(manifest)
    audit = AuditLogger(session.audit_log_path, session_id=session.session_id, case_id=session.case_id)
    audit.append("tool_request_completed", {"tool": "volatility", "evidence_id": "memory", "exit_code": 0})
    audit.append("plan_change", {"reason": "fallback test", "evidence_id": "memory"})

    trace = build_agent_trace(
        session=session,
        manifest=manifest,
        case_objective={"objective": "Find suspicious memory activity."},
        investigation_plan={"mode": "evidence_first"},
        investigation_guidance={
            "finding_categories": ["memory"],
            "attack_stages": ["execution"],
            "recommended_tools": ["memory", "strings"],
            "recommendations": ["Review process lineage."],
        },
        report_document={
            "findings": [
                {
                    "finding_id": "F-001",
                    "finding": "Suspicious memory process",
                    "evidence_source": ["memory"],
                    "source_tool": ["volatility"],
                    "parser": ["volatility"],
                    "confidence": 0.8,
                    "triage_score": 0.7,
                    "event_ids": ["EVT-1"],
                    "attack_stages": ["execution"],
                    "suspicion_reasons": ["test reason"],
                }
            ]
        },
        validation_report={"passed": False, "issues": [{"severity": "HIGH", "message": "needs review"}]},
        unknowns_report={"unknown_count": 1, "unknowns": [{"severity": "MEDIUM", "message": "gap"}]},
        correction_history={"attempts": [{"status": "recorded"}]},
        contradiction_analysis={"finding_impacts": [{"finding_id": "F-001"}]},
        llm_report_verification={"status": "passed", "reasoning_enabled": True},
        reasoning={
            "hypotheses": [
                {
                    "hypothesis": "Suspicious execution is supported by memory evidence.",
                    "status": "supported",
                    "confidence": 0.6,
                    "evidence_event_ids": ["EVT-1"],
                }
            ]
        },
        tool_results=[
            {
                "typed_tool": "memory",
                "tool_name": "volatility",
                "evidence_id": "memory",
                "execution": {"exit_code": 0, "timed_out": False, "duration_ms": 100},
                "outputs": {"primary_output": "findings/memory.json", "output_hash": "abc"},
                "tool_integrity": {"verified": True},
                "raw_output_returned": False,
            }
        ],
        parser_results=[
            {
                "parser": "volatility",
                "source_tool": "memory",
                "evidence_id": "memory",
                "processed_count": 1,
                "warnings": [],
            }
        ],
        normalized_event_count=1,
        evidence_maturity_report={"summary": {"finding_count": 1, "traceable_finding_count": 1}},
    )

    trace_path = session.findings_dir / "agent_trace.json"
    journal_path = session.reports_dir / "agent_journal.md"
    export_agent_trace(trace, trace_path)
    journal = render_agent_journal(trace, journal_path)

    stored = json.loads(trace_path.read_text(encoding="utf-8"))
    assert stored["schema_version"] == "agent-trace.v1"
    assert stored["raw_evidence_included"] is False
    assert stored["raw_tool_output_included"] is False
    assert stored["summary"]["finding_count"] == 1
    assert stored["findings"][0]["trace_status"] == "tool_execution_linked"
    assert stored["plan_changes"]
    assert "Label: agent journal" in journal
    assert "Three-Claim Trace Table" in journal_path.read_text(encoding="utf-8")
