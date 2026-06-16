from __future__ import annotations

import pytest

from blitz_dfir.core.models import EvidenceCategory, EvidenceRecord, EvidenceType, Pipeline, TrustTier
from blitz_dfir.core.normalization import build_normalized_event
from blitz_dfir.correlation.confidence import detect_contradictions
from blitz_dfir.correlation.contradiction_analysis import (
    apply_contradiction_penalties,
    build_contradiction_analysis_report,
)
from blitz_dfir.correlation.evidentiary_weighting import build_evidentiary_weighting_report
from blitz_dfir.correlation.models import CorrelatedFinding, anchor_from_event, stable_correlation_id


def test_evidentiary_weighting_scores_multi_source_support(tmp_path):
    registry = _event(
        tmp_path,
        evidence_id="registry",
        evidence_type=EvidenceType.REGISTRY_HIVE,
        source_tool="regripper",
        source_parser="registry",
        fields={"process_guid": "abc", "path": "C:/Temp/payload.exe"},
    )
    memory = _event(
        tmp_path,
        evidence_id="memory",
        evidence_type=EvidenceType.MEMORY,
        source_tool="volatility",
        source_parser="volatility",
        fields={"process_guid": "abc", "path": "C:/Temp/payload.exe"},
        record_index=2,
    )
    prefetch = _event(
        tmp_path,
        evidence_id="prefetch",
        evidence_type=EvidenceType.FILESYSTEM_ARTIFACT,
        source_tool="pecmd",
        source_parser="prefetch",
        fields={"process_guid": "abc", "path": "C:/Temp/payload.exe"},
        record_index=3,
    )
    finding = _finding((registry, memory, prefetch), confidence=0.91)

    report = build_evidentiary_weighting_report(findings=(finding,), events=(registry, memory, prefetch))
    weighted = report.findings[0]

    assert weighted.evidence_weight >= 0.90
    assert weighted.weight_label == "High"
    assert weighted.source_count == 3
    assert {source.evidence_id for source in weighted.sources} == {"registry", "memory", "prefetch"}


def test_cross_source_timestamp_poisoning_creates_contradiction_and_reduces_confidence(tmp_path):
    evtx = _event(
        tmp_path,
        evidence_id="security",
        source_tool="chainsaw",
        source_parser="evtx",
        timestamp="2026-05-24T01:00:00Z",
        fields={"process_guid": "abc", "sha256": "a" * 64},
    )
    memory = _event(
        tmp_path,
        evidence_id="memory",
        evidence_type=EvidenceType.MEMORY,
        source_tool="volatility",
        source_parser="volatility",
        timestamp="2026-05-24T09:30:00Z",
        fields={"process_guid": "abc", "sha256": "b" * 64},
        record_index=2,
    )
    finding = _finding((evtx, memory), confidence=0.92)

    contradictions = detect_contradictions((evtx, memory))
    adjusted = apply_contradiction_penalties((finding,), contradictions)
    report = build_contradiction_analysis_report(
        findings_before=(finding,),
        findings_after=adjusted,
        contradictions=contradictions,
    )

    assert {item.field for item in contradictions} >= {"sha256", "timestamp_utc"}
    assert adjusted[0].confidence < finding.confidence
    assert "CONTRADICTION_PENALTY" in adjusted[0].confidence_modifiers
    assert report.contradiction_score > 0
    assert report.finding_impacts[0].confidence_before == pytest.approx(0.92)
    assert report.finding_impacts[0].confidence_after == pytest.approx(adjusted[0].confidence)


def _evidence(tmp_path, evidence_id: str, evidence_type: EvidenceType) -> EvidenceRecord:
    path = tmp_path / f"{evidence_id}.bin"
    path.write_bytes(b"fixture")
    return EvidenceRecord(
        evidence_id=evidence_id,
        path=path,
        evidence_type=evidence_type,
        category=EvidenceCategory.RAW,
        pipeline=Pipeline.RAW,
        trust_tier=TrustTier.TIER_1_HIGH,
        sha256=evidence_id.encode("utf-8").hex().ljust(64, "0")[:64],
        verified=True,
        size_bytes=path.stat().st_size,
    )


def _event(
    tmp_path,
    *,
    evidence_id: str,
    source_tool: str,
    source_parser: str,
    evidence_type: EvidenceType = EvidenceType.EVTX,
    timestamp: str = "2026-05-24T01:00:00Z",
    fields: dict[str, str] | None = None,
    record_index: int = 1,
):
    evidence = _evidence(tmp_path, evidence_id, evidence_type)
    return build_normalized_event(
        evidence=evidence,
        timestamp=timestamp,
        category="process_execution",
        source_tool=source_tool,
        source_parser=source_parser,
        artifact=fields.get("path", "C:/Temp/payload.exe") if fields else "C:/Temp/payload.exe",
        message="execution evidence",
        raw_record_index=record_index,
        normalized_fields=fields or {},
    )


def _finding(events, *, confidence: float) -> CorrelatedFinding:
    anchors = tuple(anchor_from_event(event) for event in events)
    return CorrelatedFinding(
        finding_id=stable_correlation_id("FIND", *(event.event_id for event in events)),
        finding_type="persistence",
        title="Persistence via Run Key",
        summary="Registry, execution, and runtime artifacts support persistence.",
        category="persistence",
        supporting_event_ids=tuple(event.event_id for event in events),
        evidence=anchors,
        confidence=confidence,
        confidence_modifiers=("MULTI_SOURCE_AGREEMENT",),
        triage_score=0.9,
        suspicion_reasons=("multi-source persistence evidence",),
    )
