from __future__ import annotations

import json

from blitz_dfir.core.models import EvidenceCategory, EvidenceRecord, EvidenceType, Pipeline, TrustTier
from blitz_dfir.core.normalization import build_normalized_event
from blitz_dfir.correction.bounded_retry import execute_bounded_corrections
from blitz_dfir.correction.triggers import triggers_from_validation
from blitz_dfir.correction.validator import validate_case_outputs
from blitz_dfir.correlation.confidence import detect_contradictions
from blitz_dfir.correlation.models import CorrelatedFinding, anchor_from_event, stable_correlation_id
from blitz_dfir.reasoning.models import Hypothesis, ReasoningResult
from blitz_dfir.reasoning.verification import build_llm_report_verification
from blitz_dfir.reporting.html_export import render_html_report
from blitz_dfir.reporting.markdown_export import render_markdown_report
from blitz_dfir.reporting.report_builder import ReportDocument, build_report_document, export_json_report
from blitz_dfir.signal.coverage import build_coverage_report, coverage_from_counts
from blitz_dfir.signal.integrity import summarize_signal_integrity
from blitz_dfir.signal.warnings import hash_mismatch_warning
from blitz_dfir.temporal.analysis import build_attack_stage_timeline, build_temporal_gap_analysis
from blitz_dfir.validation.truth_report import TruthValidationReport


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


def _event(tmp_path, *, evidence_id: str = "security", sha256: str = "a" * 64):
    evidence = _evidence(tmp_path, evidence_id=evidence_id)
    return build_normalized_event(
        evidence=evidence,
        timestamp="2026-05-24T01:00:00Z",
        category="process_execution",
        source_tool="chainsaw",
        source_parser="evtx",
        artifact="<script>alert(1)</script>",
        message="confirmed beyond doubt malicious process",
        raw_record_index=1,
        normalized_fields={"process_guid": "abc", "sha256": sha256, "processid": "100"},
    )


def _finding(event, *, confidence: float = 0.86):
    return CorrelatedFinding(
        finding_id=stable_correlation_id("FIND", event.event_id),
        finding_type="execution",
        title="<script>alert(1)</script> tool output proves execution",
        summary="definitively malicious execution candidate",
        category=event.category,
        supporting_event_ids=(event.event_id,),
        evidence=(anchor_from_event(event),),
        confidence=confidence,
        confidence_modifiers=("SINGLE_SOURCE_PENALTY",),
        triage_score=0.72,
        suspicion_reasons=("living-off-the-land binary or shell token observed: cmd.exe",),
        attack_stages=("execution",),
    )


def _report(tmp_path):
    event = _event(tmp_path)
    other = _event(tmp_path, evidence_id="memory", sha256="b" * 64)
    finding = _finding(event)
    contradictions = detect_contradictions([event, other])
    coverage_report = build_coverage_report(
        [
            coverage_from_counts(artifact_type="EVTX", observed=1, expected=1),
            coverage_from_counts(artifact_type="Memory", observed=0, expected=1),
        ]
    )
    signal_report = summarize_signal_integrity(
        coverage_report=coverage_report,
        extra_warnings=[hash_mismatch_warning(artifact="chainsaw", expected="0" * 64, actual="1" * 64)],
    )
    validation_report = validate_case_outputs(
        findings=(finding,),
        contradictions=contradictions,
        signal_report=signal_report,
    )
    triggers = triggers_from_validation(validation_report)
    correction_history = execute_bounded_corrections(
        triggers,
        confidence_before=0.4,
        executor=lambda action: ("SUCCESS", "scoped correction recorded", 0.55),
    )
    reasoning = ReasoningResult(
        hypotheses=(
            Hypothesis(
                hypothesis="Process execution is suspicious",
                status="supported",
                evidence_event_ids=(event.event_id,),
                rationale="Supported by normalized event only",
                confidence=0.75,
            ),
        ),
        narrative="This is certain and guaranteed.",
        prompt_hash="abc123",
    )
    temporal_gap_analysis = build_temporal_gap_analysis((event, other))
    attack_stage_timeline = build_attack_stage_timeline(events=(event, other), findings=(finding,), stages=())
    llm_report_verification = build_llm_report_verification(
        reasoning=reasoning,
        events=(event, other),
        findings=(finding,),
    )
    return build_report_document(
        case_id="case-001",
        events=(event, other),
        findings=(finding,),
        contradictions=contradictions,
        coverage_report=coverage_report,
        signal_report=signal_report,
        validation_report=validation_report,
        correction_history=correction_history,
        reasoning=reasoning,
        audit_trail_path=str(tmp_path / "audit" / "session.ndjson"),
        parser_versions={"evtx": "test"},
        temporal_gap_analysis=temporal_gap_analysis.model_dump(mode="json"),
        attack_stage_timeline=attack_stage_timeline.model_dump(mode="json"),
        llm_report_verification=llm_report_verification.model_dump(mode="json"),
    )


def test_html_report_escapes_malicious_evidence_content(tmp_path):
    report = _report(tmp_path)
    html = render_html_report(report)

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_markdown_report_is_readable_and_evidence_backed(tmp_path):
    report = _report(tmp_path)
    markdown = render_markdown_report(report)

    assert "# Blitz DFIR Report" in markdown
    assert "## Evidence-Supported Findings" in markdown
    assert "Correlation path" in markdown
    assert "Why suspicious" in markdown
    assert "Triage score" in markdown
    assert "## Temporal Gap Analysis" in markdown
    assert "## Attack-Stage Timeline" in markdown
    assert "## LLM Report Verification" in markdown
    assert report.findings[0].evidence_references[0].event_id in markdown
    assert "<script>" not in markdown


def test_json_findings_validate_against_schema(tmp_path):
    report = _report(tmp_path)
    text = export_json_report(report)
    parsed = ReportDocument.model_validate_json(text)
    payload = json.loads(text)

    assert parsed.findings
    assert set(payload["findings"][0]) >= {
        "finding",
        "evidence_source",
        "source_tool",
        "parser",
        "parser_version",
        "timestamp",
        "confidence",
        "confidence_modifiers",
        "triage_score",
        "suspicion_reasons",
        "correlation_path",
        "evidence_type",
        "recovery_notes",
    }


def test_every_finding_has_evidence_references(tmp_path):
    report = _report(tmp_path)

    assert all(finding.evidence_references for finding in report.findings)
    assert all(finding.evidence_source for finding in report.findings)


def test_report_includes_evidence_credibility_coverage_and_corrections(tmp_path):
    report = _report(tmp_path)

    assert report.coverage["overall_case_coverage"] == 0.5
    assert report.unknown_zones
    assert report.evidence_credibility
    assert report.tool_integrity_status == "unverified"
    assert report.cross_validation["status"] == "issues_found"
    assert report.parser_consensus_score > 0
    assert report.global_case_trust_score > 0
    assert report.self_correction["attempts"]
    assert report.audit_trail_reference
    assert report.confirmed_evidence
    assert report.evidence_supported_findings
    assert report.inferred_analyst_reasoning["evidence_type"] == "INFERRED"
    assert report.temporal_gap_analysis["schema_version"] == "temporal-gap-analysis.v1"
    assert report.attack_stage_timeline["schema_version"] == "attack-stage-timeline.v1"
    assert report.llm_report_verification["schema_version"] == "llm-report-verification.v1"
    assert report.truth_validation["status"] == "not_run"


def test_report_language_avoids_absolute_truth_claims(tmp_path):
    report = _report(tmp_path)
    text = export_json_report(report).lower()

    for forbidden in (
        "confirmed beyond doubt",
        "definitively malicious",
        "i saw everything",
        "tool output proves",
        "certain",
        "guaranteed",
    ):
        assert forbidden not in text
    assert "evidence strongly supports" in render_markdown_report(report).lower() or "coverage x percent" in text


def test_report_deduplicates_repeated_finding_ids(tmp_path):
    event = _event(tmp_path)
    finding = _finding(event)

    report = build_report_document(
        case_id="case-001",
        events=(event,),
        findings=(finding, finding),
        audit_trail_path=str(tmp_path / "audit" / "session.ndjson"),
    )

    assert len(report.findings) == 1
    assert report.findings[0].finding == "<script>alert(1)</script> evidence does not fully establish execution"


def test_report_renders_truth_validation_section(tmp_path):
    event = _event(tmp_path)
    finding = _finding(event)
    truth_report = TruthValidationReport(
        dataset_name="unit-truth",
        precision=1.0,
        recall=0.5,
        f1=0.67,
        matched_findings=1,
        missed_findings=1,
        unexpected_findings=0,
        passed=False,
    )

    report = build_report_document(
        case_id="case-001",
        events=(event,),
        findings=(finding,),
        audit_trail_path=str(tmp_path / "audit" / "session.ndjson"),
        truth_validation_report=truth_report,
    )
    markdown = render_markdown_report(report)
    html = render_html_report(report)

    assert report.truth_validation["status"] == "failed"
    assert report.truth_validation["dataset_name"] == "unit-truth"
    assert "## Truth Validation" in markdown
    assert "unit-truth" in markdown
    assert "Truth Validation" in html
    assert "unit-truth" in html
