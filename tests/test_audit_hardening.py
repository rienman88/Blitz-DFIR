from __future__ import annotations

import json
import re
from pathlib import Path

from blitz_dfir.audit.audit_log import AuditLogger, tamper_evident_note
from blitz_dfir.audit.execution_trace import (
    record_agent_decision,
    record_confidence_adjustment,
    record_correction_attempt,
    record_correction_history,
    record_coverage_scores,
    record_parser_result,
    record_phase_event,
    record_rerun_trigger,
    record_tool_execution,
    record_validation_report,
)
from blitz_dfir.audit.integrity_log import (
    record_evidence_integrity,
    record_report_integrity,
    record_tool_integrity,
)
from blitz_dfir.core.integrity import hash_text, sha256_file
from blitz_dfir.core.models import EvidenceCategory, EvidenceRecord, EvidenceType, Pipeline, TrustTier
from blitz_dfir.correction.bounded_retry import execute_bounded_corrections
from blitz_dfir.correction.triggers import triggers_from_validation
from blitz_dfir.correction.validator import validate_case_outputs
from blitz_dfir.correlation.models import CorrelatedFinding, anchor_from_event, stable_correlation_id
from blitz_dfir.core.normalization import build_normalized_event
from blitz_dfir.parsers.models import ParserResult
from blitz_dfir.reasoning.models import AnalystDecision, TokenUsage
from blitz_dfir.signal.coverage import build_coverage_report, coverage_from_counts
from blitz_dfir.tools.base import ToolAdapterResult, ToolWarning
from blitz_dfir.tools.provenance import ToolProvenance


def _entries(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _evidence(tmp_path):
    evidence_path = tmp_path / "evidence" / "Security.evtx"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_bytes(b"events")
    return EvidenceRecord(
        evidence_id="security",
        path=evidence_path,
        evidence_type=EvidenceType.EVTX,
        category=EvidenceCategory.RAW,
        pipeline=Pipeline.RAW,
        trust_tier=TrustTier.TIER_1_HIGH,
        sha256=sha256_file(evidence_path),
        verified=True,
        size_bytes=evidence_path.stat().st_size,
    )


def _tool_result(tmp_path):
    provenance = ToolProvenance(
        executable="chainsaw",
        resolved_path=str(tmp_path / "bin" / "chainsaw"),
        expected_sha256="0" * 64,
        actual_sha256="1" * 64,
        verified=False,
        warnings=(),
    )
    return ToolAdapterResult(
        tool_name="chainsaw",
        evidence_id="security",
        command=("chainsaw", "hunt", str(tmp_path / "evidence" / "Security.evtx")),
        cwd=tmp_path,
        primary_output_path=tmp_path / "out.json",
        stdout_path=tmp_path / "stdout.txt",
        stderr_path=tmp_path / "stderr.txt",
        tool_version="test",
        args_hash=hash_text("args"),
        output_hash="2" * 64,
        stdout_hash="3" * 64,
        stderr_hash="4" * 64,
        exit_code=0,
        duration_ms=123,
        timed_out=False,
        warnings=(ToolWarning("TOOL_PROVENANCE", "CRITICAL", "hash mismatch"),),
        provenance=provenance,
    )


def _finding(tmp_path):
    evidence = _evidence(tmp_path)
    event = build_normalized_event(
        evidence=evidence,
        timestamp="2026-05-24T01:00:00Z",
        category="process_execution",
        source_tool="chainsaw",
        source_parser="evtx",
        raw_record_index=1,
        normalized_fields={"processid": "100"},
    )
    return CorrelatedFinding(
        finding_id=stable_correlation_id("FIND", event.event_id),
        finding_type="execution",
        title="Execution candidate",
        summary="Process execution candidate",
        category=event.category,
        supporting_event_ids=(event.event_id,),
        evidence=(anchor_from_event(event),),
        confidence=0.1,
    )


def test_audit_logger_writes_context_schema_iso_timestamp_and_sanitizes_sensitive_values(tmp_path):
    path = tmp_path / "audit" / "session.ndjson"
    logger = AuditLogger(path, session_id="sess-001", case_id="case-001")
    entry = logger.append(
        "phase_event",
        {
            "path": r"C:\Users\Alice\Desktop\case\Security.evtx",
            "api_key": "secret",
            "nested": {"token": "secret-token"},
        },
        correlation_id="CORR-001",
        timestamp_utc="2026-05-24T01:02:03Z",
    )
    payload = _entries(path)[0]

    assert entry.schema_version == "audit.v1"
    assert payload["schema_version"] == "audit.v1"
    assert payload["session_id"] == "sess-001"
    assert payload["case_id"] == "case-001"
    assert payload["correlation_id"] == "CORR-001"
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", payload["timestamp_utc"])
    assert payload["data"]["path"] == "[path-redacted]/Security.evtx"
    assert payload["data"]["api_key"] == "[redacted]"
    assert payload["data"]["nested"]["token"] == "[redacted]"
    assert path.suffix == ".ndjson"
    assert len(path.read_text(encoding="utf-8").splitlines()) == 1
    assert logger.verify_chain() is True


def test_removing_or_editing_prior_entry_breaks_chain_verification(tmp_path):
    path = tmp_path / "audit" / "session.ndjson"
    logger = AuditLogger(path)
    logger.append("one", {"value": 1}, timestamp_utc="2026-05-24T00:00:01Z")
    logger.append("two", {"value": 2}, timestamp_utc="2026-05-24T00:00:02Z")
    logger.append("three", {"value": 3}, timestamp_utc="2026-05-24T00:00:03Z")
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")

    assert logger.verify_chain() is False

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tampered = path.read_text(encoding="utf-8").replace('"value":2', '"value":9')
    path.write_text(tampered, encoding="utf-8")
    assert logger.verify_chain() is False
    assert "not a tamper-proof" in tamper_evident_note()


def test_execution_trace_records_tool_parser_agent_validation_correction_confidence_and_coverage(tmp_path):
    path = tmp_path / "audit" / "session.ndjson"
    logger = AuditLogger(path, session_id="sess-001", case_id="case-001")
    tool_result = _tool_result(tmp_path)
    record_tool_execution(
        logger,
        tool_result,
        sanitized_args={"target": r"C:\Users\Alice\Desktop\Security.evtx"},
    )
    parser_result = ParserResult(
        parser="evtx",
        source_tool="chainsaw",
        evidence_id="security",
        records=(),
        warnings=(),
        processed_count=0,
        malformed_count=1,
        truncated=False,
    )
    record_parser_result(logger, parser_result)
    decision = AnalystDecision(
        decision_id="DEC-001",
        why="Review bounded findings",
        expected="supported hypothesis",
        actual="low confidence",
    )
    record_agent_decision(
        logger,
        decision,
        token_usage=TokenUsage(prompt_tokens=1, completion_tokens=2, total_tokens=3),
    )
    finding = _finding(tmp_path / "case")
    validation = validate_case_outputs(findings=(finding,), confidence_threshold=0.5)
    record_validation_report(logger, validation)
    triggers = triggers_from_validation(validation)
    record_rerun_trigger(logger, triggers[0])
    history = execute_bounded_corrections(
        triggers,
        confidence_before=0.2,
        executor=lambda action: ("SUCCESS", "scoped correction", 0.4),
    )
    record_correction_attempt(logger, history.attempts[0])
    record_correction_history(logger, history)
    record_confidence_adjustment(logger, subject_id="finding-1", before=0.2, after=0.4, reason="rerun")
    coverage = build_coverage_report([coverage_from_counts(artifact_type="EVTX", observed=1, expected=2)])
    record_coverage_scores(logger, coverage)
    record_phase_event(logger, phase="Phase 11", status="completed")

    entries = _entries(path)
    event_types = {entry["event_type"] for entry in entries}
    assert {
        "tool_execution",
        "parser_result",
        "agent_decision",
        "validation_report",
        "rerun_trigger",
        "correction_outcome",
        "correction_history",
        "confidence_adjustment",
        "coverage_scores",
        "phase_event",
    }.issubset(event_types)
    tool_entry = next(entry for entry in entries if entry["event_type"] == "tool_execution")
    assert tool_entry["data"]["tool"] == "chainsaw"
    assert tool_entry["data"]["tool_version"] == "test"
    assert tool_entry["data"]["tool_hash"] == "1" * 64
    assert tool_entry["data"]["sanitized_args"]["target"] == "[path-redacted]/Security.evtx"
    assert tool_entry["data"]["duration_ms"] == 123
    assert tool_entry["data"]["output_hash"] == "2" * 64
    assert tool_entry["data"]["exit_code"] == 0
    assert logger.verify_chain() is True


def test_integrity_log_records_evidence_tool_and_report_hashes(tmp_path):
    path = tmp_path / "audit" / "session.ndjson"
    logger = AuditLogger(path, session_id="sess-001", case_id="case-001")
    evidence = _evidence(tmp_path)
    tool_result = _tool_result(tmp_path)
    report_path = tmp_path / "reports" / "report.json"
    report_path.parent.mkdir()
    report_path.write_text('{"ok":true}', encoding="utf-8")

    record_evidence_integrity(logger, evidence)
    record_tool_integrity(logger, tool_name="chainsaw", provenance=tool_result.provenance)
    record_report_integrity(logger, report_path)

    entries = _entries(path)
    checks = [entry["data"]["check_type"] for entry in entries]
    assert checks == ["evidence_sha256", "tool_provenance", "generated_report_sha256"]
    assert entries[0]["data"]["verified"] is True
    assert entries[1]["data"]["verified"] is False
    assert entries[2]["data"]["sha256"] == sha256_file(report_path)
    assert entries[2]["data"]["report_path"] == "[path-redacted]/report.json"
    assert logger.verify_chain() is True
