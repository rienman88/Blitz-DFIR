from __future__ import annotations

import json

import pytest

from blitz_dfir.audit.audit_log import AuditLogger
from blitz_dfir.core.models import EvidenceCategory, EvidenceRecord, EvidenceType, Pipeline, SignalWarning, TrustTier
from blitz_dfir.core.normalization import build_normalized_event
from blitz_dfir.correlation.confidence import detect_contradictions
from blitz_dfir.correlation.lineage import build_process_lineage
from blitz_dfir.correlation.models import CorrelatedFinding, anchor_from_event, stable_correlation_id
from blitz_dfir.correction.bounded_retry import execute_bounded_corrections
from blitz_dfir.correction.rerun_engine import recovery_action_for_trigger, validate_recovery_action
from blitz_dfir.correction.triggers import triggers_from_validation
from blitz_dfir.correction.validator import downgrade_unverified_findings, validate_case_outputs
from blitz_dfir.correction.models import CorrectionTrigger, RecoveryAction
from blitz_dfir.signal.integrity import summarize_signal_integrity
from blitz_dfir.signal.warnings import (
    event_truncation_warning,
    hash_mismatch_warning,
    missing_artifact_warning,
    parser_crash_warning,
    parser_degradation_warning,
    tool_timeout_warning,
)


def _evidence(tmp_path, evidence_id: str = "security"):
    return EvidenceRecord(
        evidence_id=evidence_id,
        path=tmp_path / f"{evidence_id}.evtx",
        evidence_type=EvidenceType.EVTX,
        category=EvidenceCategory.RAW,
        pipeline=Pipeline.RAW,
        trust_tier=TrustTier.TIER_1_HIGH,
        sha256=evidence_id.encode("utf-8").hex().ljust(64, "0")[:64],
        verified=True,
        size_bytes=10,
    )


def _event(
    tmp_path,
    *,
    evidence_id: str = "security",
    record_index: int = 1,
    fields: dict[str, str] | None = None,
):
    evidence = _evidence(tmp_path, evidence_id=evidence_id)
    return build_normalized_event(
        evidence=evidence,
        timestamp="2026-05-24T01:00:00Z",
        category="process_execution",
        source_tool="chainsaw",
        source_parser="evtx",
        artifact="C:/Windows/System32/cmd.exe",
        message="process execution",
        raw_record_index=record_index,
        normalized_fields=fields or {"processid": str(record_index)},
    )


def _finding(event, *, confidence: float = 0.8, evidence=True):
    anchors = (anchor_from_event(event),) if evidence else ()
    event_ids = (event.event_id,) if evidence else ()
    return CorrelatedFinding(
        finding_id=stable_correlation_id("FIND", event.event_id),
        finding_type="execution",
        title="Execution candidate",
        summary="Process execution candidate",
        category=event.category,
        supporting_event_ids=event_ids,
        evidence=anchors,
        confidence=confidence,
    )


def test_validator_checks_support_confidence_contradictions_lineage_and_parser_integrity(tmp_path):
    event = _event(tmp_path, fields={"process_guid": "abc", "sha256": "a" * 64, "processid": "200", "parentprocessid": "100"})
    other = _event(
        tmp_path,
        evidence_id="memory",
        record_index=2,
        fields={"process_guid": "abc", "sha256": "b" * 64},
    )
    unsupported = _finding(event, confidence=0.2, evidence=False)
    contradictions = detect_contradictions([event, other])
    lineage = build_process_lineage([event])
    signal = summarize_signal_integrity(
        extra_warnings=[
            parser_degradation_warning(artifact="security", parser="evtx", reason="invalid timestamp")
        ]
    )

    report = validate_case_outputs(
        findings=(unsupported,),
        contradictions=contradictions,
        signal_report=signal,
        lineage_links=lineage,
        confidence_threshold=0.5,
        max_contradictions=0,
    )

    issue_types = {issue.issue_type for issue in report.issues}
    assert report.passed is False
    assert "MISSING_EVIDENCE" in issue_types
    assert "LOW_CONFIDENCE" in issue_types
    assert "TIMELINE_GAP_OR_CONTRADICTION" in issue_types
    assert "CONTRADICTION_LIMIT_EXCEEDED" in issue_types
    assert "BROKEN_LINEAGE" in issue_types
    assert "PARSER_DEGRADATION_OR_SIGNAL_LOSS" in issue_types
    assert report.parser_integrity_ok is False


def test_triggers_are_only_approved_reasons(tmp_path):
    event = _event(tmp_path)
    low_confidence = _finding(event, confidence=0.1)
    signal = summarize_signal_integrity(
        extra_warnings=[missing_artifact_warning(artifact="Timeline", missing_source="Registry")]
    )
    report = validate_case_outputs(
        findings=(low_confidence,),
        signal_report=signal,
        confidence_threshold=0.5,
    )

    triggers = triggers_from_validation(report)

    assert triggers
    assert {trigger.reason for trigger in triggers}.issubset(
        {
            "MISSING_EVIDENCE_OR_BROKEN_LINEAGE",
            "LOW_CONFIDENCE",
            "PARSER_DEGRADATION_OR_SIGNAL_LOSS",
            "TIMELINE_GAP_OR_CONTRADICTION",
            "CONTRADICTION_LIMIT_EXCEEDED",
            "TOOL_INTEGRITY_MISMATCH",
        }
    )


def test_recovery_actions_are_scoped_for_known_failure_modes():
    samples = [
        (
            event_truncation_warning(artifact="EVTX", processed_events=5000, estimated_total=9000, tool="chainsaw"),
            "NARROW_EVTX_TIME_RANGE",
        ),
        (
            SignalWarning(
                warning_type="EVENT_TRUNCATION",
                severity="HIGH",
                artifact="strings",
                impact="huge strings output truncated",
            ),
            "FILTER_STRINGS_EXECUTABLE_REGIONS",
        ),
        (
            tool_timeout_warning(artifact="memory", tool="volatility", timeout_seconds=300),
            "RUN_SPECIFIC_VOLATILITY_PLUGIN",
        ),
        (
            SignalWarning(
                warning_type="EVENT_TRUNCATION",
                severity="HIGH",
                artifact="plaso",
                impact="large plaso timeline truncated",
            ),
            "SCOPED_PSORT_FILTER",
        ),
        (
            SignalWarning(
                warning_type="PARTIAL_EXTRACTION",
                severity="HIGH",
                artifact="Memory",
                impact="memory exhaustion caused partial extraction",
            ),
            "CHUNK_MEMORY_EXTRACTION",
        ),
        (
            parser_crash_warning(artifact="pcap", parser="tshark-json", exit_code=1),
            "ALTERNATE_PARSER_FALLBACK",
        ),
        (
            hash_mismatch_warning(artifact="tshark", expected="0" * 64, actual="1" * 64),
            "DOWNGRADE_CONFIDENCE_FLAG_UNVERIFIED",
        ),
    ]

    for warning, expected_action_type in samples:
        signal = summarize_signal_integrity(extra_warnings=[warning])
        report = validate_case_outputs(signal_report=signal)
        triggers = triggers_from_validation(report)
        action_types = {recovery_action_for_trigger(trigger).action_type for trigger in triggers}

        assert expected_action_type in action_types


def test_retry_count_cannot_exceed_two(tmp_path):
    event = _event(tmp_path)
    report = validate_case_outputs(findings=(_finding(event, confidence=0.1),), confidence_threshold=0.5)
    triggers = triggers_from_validation(report)

    with pytest.raises(ValueError):
        execute_bounded_corrections(triggers, confidence_before=0.2, max_retries=3)


def test_correction_cannot_invent_unapproved_tool_chain():
    trigger = CorrectionTrigger(
        trigger_id="TRIG-1",
        reason="LOW_CONFIDENCE",
        severity="MEDIUM",
        source_issue_id="ISSUE-1",
        message="low confidence",
    )
    invented = RecoveryAction(
        action_id="ACT-1",
        action_type="SCOPED_CORRELATION_REVIEW",
        scope="try arbitrary shell",
        rationale="bad action",
        allowed_tools=("execute_shell_cmd",),
    )

    assert recovery_action_for_trigger(trigger).allowed_tools == ()
    with pytest.raises(ValueError):
        validate_recovery_action(invented)


def test_confidence_delta_is_recorded_and_failed_correction_stays_low_confidence(tmp_path):
    event = _event(tmp_path)
    report = validate_case_outputs(findings=(_finding(event, confidence=0.1),), confidence_threshold=0.5)
    triggers = triggers_from_validation(report)

    history = execute_bounded_corrections(
        triggers,
        confidence_before=0.2,
        executor=lambda action: ("FAILED", "scoped rerun did not improve support", 0.9),
    )

    assert history.attempts
    assert history.attempts[0].confidence_delta <= 0
    assert history.status == "FAILED_LOW_CONFIDENCE"
    assert history.final_confidence <= 0.4


def test_tool_integrity_mismatch_downgrades_findings(tmp_path):
    event = _event(tmp_path)
    finding = _finding(event, confidence=0.9)
    warning = hash_mismatch_warning(artifact="chainsaw", expected="0" * 64, actual="1" * 64)

    downgraded = downgrade_unverified_findings((finding,), (warning,))

    assert downgraded[0].confidence == 0.6
    assert "TOOL_INTEGRITY_UNVERIFIED" in downgraded[0].confidence_modifiers
    assert downgraded[0].warnings[0].warning_type == "HASH_MISMATCH"


def test_correction_history_is_written_to_audit_and_report_section(tmp_path):
    event = _event(tmp_path)
    report = validate_case_outputs(findings=(_finding(event, confidence=0.1),), confidence_threshold=0.5)
    triggers = triggers_from_validation(report)
    audit = AuditLogger(tmp_path / "audit" / "session.ndjson")

    history = execute_bounded_corrections(
        triggers,
        confidence_before=0.2,
        executor=lambda action: ("SUCCESS", "scoped correlation improved support", 0.55),
        audit_logger=audit,
    )
    report_section = history.as_report_section()
    audit_text = (tmp_path / "audit" / "session.ndjson").read_text(encoding="utf-8")

    assert report_section["attempts"]
    assert report_section["final_confidence"] == 0.55
    assert "correction_attempt" in audit_text
    assert "correction_history" in audit_text
    assert audit.verify_chain() is True
    json.dumps(report_section)
