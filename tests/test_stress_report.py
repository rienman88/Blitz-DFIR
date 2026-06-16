from __future__ import annotations

import hashlib

from blitz_dfir.accounting.models import AccountingArtifact, FullAccountingSummary
from blitz_dfir.core.manifest import load_manifest
from blitz_dfir.core.models import SignalWarning
from blitz_dfir.core.session import create_session
from blitz_dfir.correction.models import ValidationIssue, ValidationReport
from blitz_dfir.signal.integrity import SignalIntegrityReport
from blitz_dfir.stress.report import build_stress_report


def test_stress_report_flags_timeout_and_keeps_artifact_inventory(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    timeline = evidence_root / "timeline.csv"
    timeline.write_text("datetime,message\n2026-05-26T00:00:00Z,event\n", encoding="utf-8")
    digest = hashlib.sha256(timeline.read_bytes()).hexdigest()
    manifest_path = tmp_path / "case.yaml"
    manifest_path.write_text(
        f"""
case_id: stress-case
evidence_root: evidence
output_root: output
evidence:
  - id: timeline
    path: timeline.csv
    type: CSV_TIMELINE
    sha256: {digest}
""".strip(),
        encoding="utf-8",
    )
    session = create_session(load_manifest(manifest_path))
    (session.findings_dir / "marker.txt").write_text("stress marker", encoding="utf-8")
    accounting = FullAccountingSummary(
        event_store_path="findings/event_store.sqlite",
        artifact_count=1,
        total_rows=6000,
        artifacts=(
            AccountingArtifact(
                artifact_id="timeline-psort-1",
                evidence_id="timeline",
                source_tool="psort",
                parser="plaso",
                source_path="timelines/timeline.csv",
                source_size_bytes=1234,
                row_count=6000,
                malformed_count=0,
                partial=True,
                timed_out=True,
                table_name="event_rows",
            ),
        ),
    )
    validation = ValidationReport(
        passed=False,
        issues=(
            ValidationIssue(
                issue_id="ISSUE-1",
                issue_type="PARSER_DEGRADATION_OR_SIGNAL_LOSS",
                severity="HIGH",
                message="tool timed out before final status",
            ),
        ),
    )
    signal = SignalIntegrityReport(
        warnings=(
            SignalWarning(
                warning_type="TOOL_TIMEOUT",
                severity="HIGH",
                artifact="timeline",
                impact="timeout during high-volume export",
                tool="psort",
                confidence_penalty=0.2,
            ),
        ),
        confidence_penalty=0.2,
        critical_count=0,
        high_count=1,
    )

    report = build_stress_report(
        session=session,
        tool_results=[{"typed_tool": "psort", "execution": {"timed_out": True}}],
        full_accounting=accounting,
        normalized_event_count=5000,
        validation_report=validation,
        signal_report=signal,
    )

    assert report["status"] == "needs_review"
    assert report["timed_out_tools"] == ["psort"]
    assert report["full_accounting_total_rows"] == 6000
    assert any(item["path"] == "findings/marker.txt" for item in report["session_artifacts"])


def test_stress_report_fails_when_tool_output_has_no_accounted_rows(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    evidence = evidence_root / "empty.evtx"
    evidence.write_bytes(b"evtx")
    digest = hashlib.sha256(b"evtx").hexdigest()
    manifest_path = tmp_path / "case.yaml"
    manifest_path.write_text(
        f"""
case_id: stress-empty-case
evidence_root: evidence
output_root: output
evidence:
  - id: security
    path: empty.evtx
    type: EVTX
    sha256: {digest}
""".strip(),
        encoding="utf-8",
    )
    session = create_session(load_manifest(manifest_path))

    report = build_stress_report(
        session=session,
        tool_results=[{"typed_tool": "events", "execution": {"timed_out": False}}],
        full_accounting=FullAccountingSummary(
            event_store_path="findings/event_store.sqlite",
            artifact_count=0,
            total_rows=0,
        ),
        normalized_event_count=0,
        validation_report=ValidationReport(passed=True),
        signal_report=SignalIntegrityReport(warnings=(), confidence_penalty=0.0, critical_count=0, high_count=0),
    )

    assert report["status"] == "failed"


def test_stress_report_needs_review_when_normalized_rows_exist_without_full_accounting(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    evidence = evidence_root / "memory.raw"
    evidence.write_bytes(b"memory")
    digest = hashlib.sha256(b"memory").hexdigest()
    manifest_path = tmp_path / "case.yaml"
    manifest_path.write_text(
        f"""
case_id: stress-memory-case
evidence_root: evidence
output_root: output
evidence:
  - id: memory
    path: memory.raw
    type: MEMORY
    sha256: {digest}
""".strip(),
        encoding="utf-8",
    )
    session = create_session(load_manifest(manifest_path))

    report = build_stress_report(
        session=session,
        tool_results=[{"typed_tool": "memory", "execution": {"timed_out": False}}],
        full_accounting=FullAccountingSummary(
            event_store_path="findings/event_store.sqlite",
            artifact_count=0,
            total_rows=0,
        ),
        normalized_event_count=12,
        validation_report=ValidationReport(passed=True),
        signal_report=SignalIntegrityReport(warnings=(), confidence_penalty=0.0, critical_count=0, high_count=0),
    )

    assert report["status"] == "needs_review"
