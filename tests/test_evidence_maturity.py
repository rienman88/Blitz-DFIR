from __future__ import annotations

import hashlib
import json

from blitz_dfir.accounting.models import FullAccountingSummary
from blitz_dfir.audit.audit_log import AuditLogger
from blitz_dfir.core.models import EvidenceCategory, EvidenceManifest, EvidenceRecord, EvidenceType, Pipeline, TrustTier
from blitz_dfir.core.normalization import build_normalized_event
from blitz_dfir.correction.validator import validate_case_outputs
from blitz_dfir.correlation.models import CorrelatedFinding, anchor_from_event, stable_correlation_id
from blitz_dfir.parsers.models import ParserResult
from blitz_dfir.reporting.evidence_maturity import (
    build_evidence_maturity_report,
    export_evidence_maturity_report,
    render_evidence_maturity_markdown,
)
from blitz_dfir.reporting.provenance_visualization import render_finding_provenance_markdown
from blitz_dfir.signal.coverage import build_coverage_report, coverage_from_counts
from blitz_dfir.signal.integrity import summarize_signal_integrity
from blitz_dfir.unknowns.engine import build_unknowns_report


def test_evidence_maturity_report_links_finding_to_event_parser_tool_and_audit(tmp_path):
    evidence_path = tmp_path / "timeline.csv"
    evidence_path.write_text("datetime,message\n2026-05-26T00:00:00Z,cmd.exe\n", encoding="utf-8")
    digest = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    evidence = EvidenceRecord(
        evidence_id="timeline",
        path=evidence_path,
        evidence_type=EvidenceType.CSV_TIMELINE,
        category=EvidenceCategory.DERIVED,
        pipeline=Pipeline.PROCESSED,
        trust_tier=TrustTier.TIER_3_LOW,
        sha256=digest,
        verified=True,
        size_bytes=evidence_path.stat().st_size,
    )
    manifest = EvidenceManifest(
        case_id="case-001",
        evidence_root=tmp_path,
        output_root=tmp_path / "output",
        source_path=tmp_path / "case.yaml",
        evidence=(evidence,),
    )
    event = build_normalized_event(
        evidence=evidence,
        timestamp="2026-05-26T00:00:00Z",
        category="process_execution",
        source_tool="psort",
        source_parser="plaso",
        artifact="C:/Windows/System32/cmd.exe",
        message="cmd.exe execution",
        raw_record_index=1,
    )
    finding = CorrelatedFinding(
        finding_id=stable_correlation_id("FIND", event.event_id),
        finding_type="execution",
        title="Suspicious shell execution",
        summary="Evidence strongly supports shell execution review.",
        category=event.category,
        supporting_event_ids=(event.event_id,),
        evidence=(anchor_from_event(event),),
        confidence=0.7,
        confidence_modifiers=("SINGLE_SOURCE_PENALTY",),
        triage_score=0.65,
        suspicion_reasons=("living-off-the-land binary or shell token observed: cmd.exe",),
    )
    parser_result = ParserResult(
        parser="plaso",
        source_tool="psort",
        evidence_id="timeline",
        records=(),
        processed_count=1,
        malformed_count=0,
    )
    tool_result = {
        "typed_tool": "psort",
        "tool_name": "psort",
        "evidence_id": "timeline",
        "execution": {"exit_code": 0, "duration_ms": 5, "timed_out": False},
        "outputs": {"primary_output": "timelines/timeline.csv", "output_hash": "a" * 64},
        "tool_integrity": {"verified": True},
    }
    coverage = build_coverage_report([coverage_from_counts(artifact_type="Timeline", observed=1, expected=1)])
    signal = summarize_signal_integrity(parser_results=[parser_result], coverage_report=coverage)
    validation = validate_case_outputs(findings=(finding,), signal_report=signal)
    unknowns = build_unknowns_report(
        coverage_report=coverage,
        signal_report=signal,
        validation_report=validation,
        full_accounting=FullAccountingSummary(event_store_path="findings/event_store.sqlite", artifact_count=0, total_rows=0),
    )
    audit_path = tmp_path / "audit.ndjson"
    audit = AuditLogger(audit_path, session_id="sess-test", case_id="case-001")
    audit.append("evidence_verified", {"evidence_id": "timeline"})
    audit.append("analysis_tool_result", {"typed_tool": "psort", "tool_name": "psort", "evidence_id": "timeline"})
    audit.append("parser_completed", {"parser": "plaso", "source_tool": "psort", "evidence_id": "timeline"})

    report = build_evidence_maturity_report(
        case_id="case-001",
        session_id="sess-test",
        manifest=manifest,
        events=(event,),
        findings=(finding,),
        parser_results=(parser_result,),
        tool_results=(tool_result,),
        coverage_report=coverage,
        signal_report=signal,
        validation_report=validation,
        unknowns_report=unknowns,
        full_accounting=FullAccountingSummary(event_store_path="findings/event_store.sqlite", artifact_count=0, total_rows=1),
        audit_log_path=audit_path,
    )

    assert report.summary["traceable_finding_count"] == 1
    assert report.evidence_hash_checks[0].preserved is True
    assert report.finding_traces[0].complete is True
    assert report.finding_traces[0].evidence_chain[0].parser_result is not None
    assert report.finding_traces[0].evidence_chain[0].tool_execution is not None
    payload = json.loads(export_evidence_maturity_report(report))
    assert payload["schema_version"] == "evidence-maturity.v1"
    assert "Finding Traceability" in render_evidence_maturity_markdown(report)
    provenance = render_finding_provenance_markdown(report)
    assert "flowchart LR" in provenance
    assert "Suspicious shell execution" in provenance
