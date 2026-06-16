from __future__ import annotations

from blitz_dfir.core.models import EvidenceCategory, EvidenceRecord, EvidenceType, Pipeline, TrustTier
from blitz_dfir.core.normalization import build_normalized_event
from blitz_dfir.correlation.attack_chain import infer_attack_stages
from blitz_dfir.correlation.confidence import assess_confidence, detect_contradictions
from blitz_dfir.correlation.lineage import build_process_lineage
from blitz_dfir.correlation.models import anchor_from_event
from blitz_dfir.correlation.persistence import detect_persistence
from blitz_dfir.correlation.timeline import order_events, stitch_events
from blitz_dfir.correlation.triage import assess_group_suspicion


def _evidence(tmp_path, evidence_id: str = "security", evidence_type: EvidenceType = EvidenceType.EVTX):
    return EvidenceRecord(
        evidence_id=evidence_id,
        path=tmp_path / f"{evidence_id}.evtx",
        evidence_type=evidence_type,
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
    timestamp: str = "2026-05-24T01:00:00Z",
    category: str = "process_execution",
    artifact: str = "C:/Windows/System32/cmd.exe",
    message: str = "event",
    source_tool: str = "chainsaw",
    source_parser: str = "evtx",
    fields: dict[str, str] | None = None,
    record_index: int = 1,
):
    evidence = _evidence(tmp_path, evidence_id=evidence_id)
    return build_normalized_event(
        evidence=evidence,
        timestamp=timestamp,
        category=category,
        source_tool=source_tool,
        source_parser=source_parser,
        artifact=artifact,
        message=message,
        raw_record_index=record_index,
        normalized_fields=fields or {},
    )


def test_timeline_order_and_stitching_are_deterministic(tmp_path):
    late = _event(tmp_path, timestamp="2026-05-24T03:00:00Z", fields={"processid": "200"})
    early = _event(tmp_path, timestamp="2026-05-24T01:00:00Z", fields={"processid": "100"})
    duplicate_subject = _event(
        tmp_path,
        timestamp="2026-05-24T02:00:00Z",
        fields={"processid": "100"},
        record_index=2,
    )

    ordered = order_events([late, duplicate_subject, early])
    groups = stitch_events([late, duplicate_subject, early])

    assert [event.timestamp_utc for event in ordered] == [
        "2026-05-24T01:00:00Z",
        "2026-05-24T02:00:00Z",
        "2026-05-24T03:00:00Z",
    ]
    assert any(group.subject == "100" and len(group.event_ids) == 2 for group in groups)
    assert groups == stitch_events([early, late, duplicate_subject])


def test_process_lineage_is_traceable_to_supporting_events(tmp_path):
    parent = _event(
        tmp_path,
        timestamp="2026-05-24T01:00:00Z",
        artifact="C:/Windows/explorer.exe",
        fields={"processid": "100"},
    )
    child = _event(
        tmp_path,
        timestamp="2026-05-24T01:01:00Z",
        artifact="C:/Windows/System32/cmd.exe",
        fields={"newprocessid": "200", "parentprocessid": "100"},
        record_index=2,
    )

    links = build_process_lineage([child, parent])

    assert len(links) == 1
    assert links[0].child_process_id == "200"
    assert links[0].parent_process_id == "100"
    assert links[0].child_event_id == child.event_id
    assert links[0].parent_event_id == parent.event_id
    assert {anchor.event_id for anchor in links[0].evidence} == {parent.event_id, child.event_id}


def test_persistence_finding_requires_evidence_reference_and_single_source_penalty(tmp_path):
    event = _event(
        tmp_path,
        category="service_install",
        artifact="HKLM/System/CurrentControlSet/Services/evilsvc",
        message="service installed",
        fields={"path": "C:/Temp/evil.exe"},
    )

    findings = detect_persistence([event])

    assert len(findings) == 1
    assert findings[0].evidence
    assert findings[0].evidence[0].raw_reference.record_index == 1
    assert "SINGLE_SOURCE_PENALTY" in findings[0].confidence_modifiers
    assert findings[0].confidence < 0.90
    assert findings[0].triage_score > 0.5
    assert findings[0].suspicion_reasons


def test_multi_source_agreement_improves_confidence(tmp_path):
    first = anchor_from_event(_event(tmp_path, evidence_id="security"))
    second = anchor_from_event(
        _event(
            tmp_path,
            evidence_id="memory",
            source_tool="volatility",
            source_parser="volatility",
            record_index=2,
        )
    )

    single = assess_confidence((first,))
    multi = assess_confidence((first, second))

    assert "SINGLE_SOURCE_PENALTY" in single.modifiers
    assert "MULTI_SOURCE_AGREEMENT" in multi.modifiers
    assert multi.score > single.score
    assert multi.agreement_score == 1.0


def test_triage_score_explains_suspicious_execution(tmp_path):
    event = _event(
        tmp_path,
        artifact="C:/Users/Public/powershell.exe",
        message="powershell -EncodedCommand AAAA",
        fields={"path": "C:/Users/Public/powershell.exe", "commandline": "powershell -EncodedCommand AAAA"},
    )

    score, reasons = assess_group_suspicion((event,))

    assert score >= 0.5
    assert any("living-off-the-land" in reason for reason in reasons)
    assert any("high-signal" in reason for reason in reasons)
    assert any("user-writable" in reason for reason in reasons)


def test_triage_score_explains_suspicious_memory_process(tmp_path):
    event = _event(
        tmp_path,
        category="memory_process",
        artifact="powershell.exe",
        message="",
        source_tool="volatility",
        source_parser="volatility",
        fields={"pid": "4242", "imagefilename": "powershell.exe"},
    )

    score, reasons = assess_group_suspicion((event,))

    assert score >= 0.5
    assert any("memory process inventory" in reason for reason in reasons)
    assert any("memory process name" in reason for reason in reasons)


def test_cross_source_disagreement_raises_contradiction(tmp_path):
    disk = _event(
        tmp_path,
        evidence_id="disk",
        fields={"process_guid": "abc", "sha256": "aaa"},
    )
    memory = _event(
        tmp_path,
        evidence_id="memory",
        source_tool="volatility",
        source_parser="volatility",
        fields={"process_guid": "abc", "sha256": "bbb"},
        record_index=2,
    )

    contradictions = detect_contradictions([disk, memory])

    assert len(contradictions) == 1
    assert contradictions[0].subject == "abc"
    assert contradictions[0].field == "sha256"
    assert {anchor.event_id for anchor in contradictions[0].evidence} == {disk.event_id, memory.event_id}


def test_attack_chain_stage_inference_uses_deterministic_categories(tmp_path):
    network = _event(
        tmp_path,
        category="network_flow",
        artifact="10.0.0.1->10.0.0.2",
        fields={"dns_query": "example.test", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"},
    )
    persistence = _event(tmp_path, category="service_install", record_index=2)

    stages = infer_attack_stages([persistence, network], findings=detect_persistence([persistence]))

    assert {stage.stage for stage in stages} == {"command_and_control_or_discovery", "persistence"}
    assert all(stage.evidence or stage.stage == "persistence" for stage in stages)


def test_attack_chain_stage_inference_maps_memory_categories(tmp_path):
    memory_process = _event(
        tmp_path,
        category="memory_process",
        artifact="powershell.exe",
        source_tool="volatility",
        source_parser="volatility",
    )
    injected_region = _event(
        tmp_path,
        category="memory_injection_candidate",
        artifact="powershell.exe",
        source_tool="volatility",
        source_parser="volatility",
        record_index=2,
    )

    stages = infer_attack_stages([memory_process, injected_region])

    assert {stage.stage for stage in stages} == {"defense_evasion_or_injection", "execution"}
