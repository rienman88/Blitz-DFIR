from __future__ import annotations

from blitz_dfir.core.models import EvidenceCategory, EvidenceRecord, EvidenceType, Pipeline, TrustTier
from blitz_dfir.core.normalization import build_normalized_event
from blitz_dfir.correlation.models import CorrelatedFinding, anchor_from_event, stable_correlation_id
from blitz_dfir.reasoning.models import Hypothesis, ReasoningResult
from blitz_dfir.reasoning.verification import build_llm_report_verification


def _evidence(tmp_path):
    return EvidenceRecord(
        evidence_id="security",
        path=tmp_path / "security.evtx",
        evidence_type=EvidenceType.EVTX,
        category=EvidenceCategory.RAW,
        pipeline=Pipeline.RAW,
        trust_tier=TrustTier.TIER_1_HIGH,
        sha256="b" * 64,
        verified=True,
        size_bytes=10,
    )


def _event(tmp_path):
    return build_normalized_event(
        evidence=_evidence(tmp_path),
        timestamp="2026-05-24T01:00:00Z",
        category="process_execution",
        source_tool="chainsaw",
        source_parser="evtx",
        artifact="cmd.exe",
        message="process execution",
        raw_record_index=1,
        normalized_fields={"processid": "100"},
    )


def _finding(event):
    return CorrelatedFinding(
        finding_id=stable_correlation_id("FIND", event.event_id),
        finding_type="execution",
        title="Process execution",
        summary="Process execution was observed.",
        category=event.category,
        supporting_event_ids=(event.event_id,),
        evidence=(anchor_from_event(event),),
        confidence=0.75,
        triage_score=0.7,
        attack_stages=("execution",),
    )


def test_llm_verification_not_run_when_reasoning_disabled(tmp_path):
    event = _event(tmp_path)

    report = build_llm_report_verification(reasoning=None, events=(event,), findings=(_finding(event),))

    assert report.status == "not_run"
    assert report.reasoning_enabled is False
    assert report.raw_evidence_sent is False
    assert report.raw_tool_output_sent is False


def test_llm_verification_fails_invalid_or_unsupported_supported_claims(tmp_path):
    event = _event(tmp_path)
    reasoning = ReasoningResult(
        hypotheses=(
            Hypothesis(
                hypothesis="A malicious process is supported",
                status="supported",
                evidence_event_ids=("missing-event",),
                rationale="invalid reference",
                confidence=0.9,
            ),
            Hypothesis(
                hypothesis="Another supported claim has no event",
                status="supported",
                evidence_event_ids=(),
                rationale="missing evidence",
                confidence=0.8,
            ),
        ),
        narrative="Evidence strongly supports bounded findings.",
        prompt_hash="abc123",
    )

    report = build_llm_report_verification(reasoning=reasoning, events=(event,), findings=(_finding(event),))

    assert report.status == "failed"
    assert report.invalid_evidence_reference_count == 1
    assert report.supported_hypotheses_without_evidence == 1

