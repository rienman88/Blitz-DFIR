from __future__ import annotations

import hashlib

from blitz_dfir.audit.audit_log import AuditLogger
from blitz_dfir.audit.progress import write_progress_state
from blitz_dfir.audit.session_integrity import write_session_state
from blitz_dfir.core.manifest import load_manifest
from blitz_dfir.core.session import create_session
from blitz_dfir.reporting.collated_outputs import write_collated_outputs


def test_collated_outputs_write_overall_findings_reports_and_audit(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    evidence = evidence_root / "Security.evtx"
    evidence.write_bytes(b"evtx")
    digest = hashlib.sha256(b"evtx").hexdigest()
    manifest_path = tmp_path / "case.yaml"
    manifest_path.write_text(
        f"""
case_id: case-collated-001
evidence_root: evidence
output_root: output
evidence:
  - id: security
    path: Security.evtx
    type: EVTX
    sha256: {digest}
""".strip(),
        encoding="utf-8",
    )
    manifest = load_manifest(manifest_path)
    session = create_session(manifest)
    audit = AuditLogger(session.audit_log_path, session_id=session.session_id, case_id=session.case_id)
    audit.append("tool_completed", {"tool": "chainsaw", "exit_code": 1})
    write_session_state(session=session, status="RUNNING", phase="unit_test")
    write_progress_state(session=session, status="RUNNING", current_layer="report_generation", layer_status="COMPLETED")

    report_md = session.reports_dir / "report.md"
    report_md.write_text("# Report\n\nEvidence-backed report.\n", encoding="utf-8")
    evidence_maturity = session.reports_dir / "evidence_maturity.md"
    evidence_maturity.write_text("# Evidence Maturity\n", encoding="utf-8")

    paths = write_collated_outputs(
        session=session,
        manifest=manifest,
        report_document={
            "findings": [
                {
                    "finding": "Suspicious execution candidate",
                    "confidence": 0.8,
                    "triage_score": 0.7,
                    "evidence_source": "Security.evtx",
                    "evidence_type": "EVTX",
                    "attack_stages": ["execution"],
                    "suspicion_reasons": ["test reason"],
                }
            ]
        },
        validation_report={"passed": False, "issues": [{"severity": "HIGH", "issue_type": "tool_failed", "message": "tool failed"}]},
        unknowns_report={"unknown_count": 1, "unknowns": []},
        signal_report={"warnings": [{"severity": "HIGH"}]},
        tool_results=[
            {
                "tool_name": "chainsaw",
                "evidence_id": "security",
                "exit_code": 1,
                "timed_out": False,
                "duration_ms": 123,
                "primary_output_path": str(session.findings_dir / "security.json"),
                "stderr_path": str(session.findings_dir / "security.stderr.txt"),
            }
        ],
        parser_results=[],
        normalized_event_count=10,
        artifact_paths={
            "report_markdown": report_md,
            "evidence_maturity_markdown": evidence_maturity,
            "tool_results": session.findings_dir / "tool_results.json",
        },
    )

    assert paths.overall_findings_path.exists()
    assert paths.overall_reports_path.exists()
    assert paths.collated_audit_path.exists()
    assert "Label: overall findings" in paths.overall_findings_path.read_text(encoding="utf-8")
    assert "Failed Or Partial Tool Work" in paths.overall_findings_path.read_text(encoding="utf-8")
    assert "Label: overall reports" in paths.overall_reports_path.read_text(encoding="utf-8")
    assert "Label: collated audit" in paths.collated_audit_path.read_text(encoding="utf-8")
