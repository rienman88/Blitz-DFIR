from __future__ import annotations

from blitz_dfir.core.models import EvidenceCategory, EvidenceRecord, EvidenceType, Pipeline, TrustTier
from blitz_dfir.core.normalization import build_normalized_event
from blitz_dfir.correlation.models import CorrelatedFinding, anchor_from_event, stable_correlation_id
from blitz_dfir.temporal.analysis import build_attack_stage_timeline, build_temporal_gap_analysis


def _evidence(tmp_path):
    return EvidenceRecord(
        evidence_id="memory",
        path=tmp_path / "memory.raw",
        evidence_type=EvidenceType.MEMORY,
        category=EvidenceCategory.RAW,
        pipeline=Pipeline.RAW,
        trust_tier=TrustTier.TIER_1_HIGH,
        sha256="a" * 64,
        verified=True,
        size_bytes=10,
    )


def _event(tmp_path, timestamp: str, *, category: str = "process_execution", index: int = 1):
    return build_normalized_event(
        evidence=_evidence(tmp_path),
        timestamp=timestamp,
        category=category,
        source_tool="volatility",
        source_parser="volatility",
        artifact=f"pid-{index}",
        message=f"event {index}",
        raw_record_index=index,
        normalized_fields={"pid": str(index)},
    )


def test_temporal_gap_analysis_records_large_gaps_and_placeholder_timestamps(tmp_path):
    first = _event(tmp_path, "2026-05-24T01:00:00Z", index=1)
    second = _event(tmp_path, "2026-05-24T04:30:00Z", index=2)
    placeholder = _event(tmp_path, "1970-01-01T00:00:00Z", index=3)

    report = build_temporal_gap_analysis((second, placeholder, first), gap_threshold_seconds=3600)

    assert report.event_count == 3
    assert report.valid_timestamp_count == 2
    assert report.invalid_or_placeholder_timestamp_count == 1
    assert report.gaps
    assert report.gaps[0].duration_seconds == 12_600
    assert report.timestamp_quality == "partial"


def test_attack_stage_timeline_is_finding_and_event_backed(tmp_path):
    event = _event(tmp_path, "2026-05-24T01:00:00Z", category="memory_injection_candidate")
    finding = CorrelatedFinding(
        finding_id=stable_correlation_id("FIND", event.event_id),
        finding_type="memory_injection",
        title="Memory injection candidate",
        summary="Volatility malfind surfaced an executable memory region.",
        category=event.category,
        supporting_event_ids=(event.event_id,),
        evidence=(anchor_from_event(event),),
        confidence=0.82,
        triage_score=0.9,
        suspicion_reasons=("executable memory region",),
        attack_stages=("defense_evasion_or_injection",),
    )

    report = build_attack_stage_timeline(events=(event,), findings=(finding,), stages=())

    assert report.stage_count == 1
    assert report.stages[0].stage == "defense_evasion_or_injection"
    assert report.stages[0].finding_ids == (finding.finding_id,)
    assert report.stages[0].event_ids == (event.event_id,)
    assert report.stages[0].timestamp_quality == "complete"

