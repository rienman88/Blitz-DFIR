from __future__ import annotations

from datetime import UTC, datetime

from blitz_dfir.core.models import (
    EvidenceCategory,
    EvidenceRecord,
    EvidenceType,
    Pipeline,
    SignalWarning,
    TrustTier,
)
from blitz_dfir.core import normalization
from blitz_dfir.core.normalization import (
    UNKNOWN_TIMESTAMP_UTC,
    build_normalized_event,
    normalize_hash,
    normalize_parser_result,
    normalize_parser_results,
    normalize_path,
    normalize_timestamp,
    normalize_username,
)
from blitz_dfir.parsers.models import ParsedRecord, ParserResult


def _evidence(tmp_path, *, category=EvidenceCategory.RAW, trust_tier=TrustTier.TIER_1_HIGH):
    return EvidenceRecord(
        evidence_id="security",
        path=tmp_path / "Security.evtx",
        evidence_type=EvidenceType.EVTX,
        category=category,
        pipeline=Pipeline.RAW,
        trust_tier=trust_tier,
        sha256="A" * 64,
        verified=True,
        size_bytes=10,
    )


def _record(
    *,
    evidence_id: str = "security",
    timestamp: str | None = "2026-05-24T01:02:03Z",
    event_type: str = "4688",
    artifact: str = "C:\\Windows\\Temp\\evil.exe",
    fields: dict[str, str] | None = None,
    evidence_type: EvidenceCategory = EvidenceCategory.RAW,
    trust_tier: TrustTier = TrustTier.TIER_1_HIGH,
    raw_reference: str | None = "12",
    warnings: tuple[SignalWarning, ...] = (),
) -> ParsedRecord:
    return ParsedRecord(
        parser="evtx",
        source_tool="chainsaw",
        evidence_id=evidence_id,
        evidence_type=evidence_type,
        trust_tier=trust_tier,
        timestamp=timestamp,
        event_type=event_type,
        artifact=artifact,
        message="Process created",
        raw_reference=raw_reference,
        fields=fields or {},
        warnings=warnings,
    )


def test_normalized_event_is_stable_for_same_inputs(tmp_path):
    evidence = _evidence(tmp_path)
    timestamp = datetime(2026, 5, 24, 1, 2, 3, tzinfo=UTC)

    first = build_normalized_event(
        evidence=evidence,
        timestamp=timestamp,
        category="process_execution",
        source_tool="chainsaw",
        source_parser="evtx_parser",
        raw_path="Security.evtx",
        confidence=0.9,
    )
    second = build_normalized_event(
        evidence=evidence,
        timestamp=timestamp,
        category="process_execution",
        source_tool="chainsaw",
        source_parser="evtx_parser",
        raw_path="Security.evtx",
        confidence=0.9,
    )

    assert first.event_id == second.event_id
    assert first.timestamp_utc == "2026-05-24T01:02:03Z"
    assert first.evidence_type is EvidenceCategory.RAW
    assert first.trust_level is TrustTier.TIER_1_HIGH
    assert first.trust_tier is TrustTier.TIER_1_HIGH


def test_timestamp_path_hash_and_username_normalization_are_deterministic():
    assert normalize_timestamp("2026-05-24T09:02:03+08:00") == "2026-05-24T01:02:03Z"
    assert normalize_timestamp("1716531723") == "2024-05-24T06:22:03Z"
    assert normalize_timestamp("not-a-date") == UNKNOWN_TIMESTAMP_UTC
    assert normalize_path("c:\\Users\\Alice\\..\\Temp\\evil.exe") == "C:/Users/Alice/../Temp/evil.exe"
    assert normalize_hash(" AA BB ") == "aabb"
    assert normalize_username("DOMAIN\\Alice") == "domain/alice"


def test_parser_record_normalization_is_stable_sorted_and_preserves_provenance(tmp_path):
    evidence = _evidence(tmp_path)
    records = [
        _record(timestamp="2026-05-24T03:00:00Z", raw_reference="2"),
        _record(timestamp="2026-05-24T01:00:00Z", raw_reference="1"),
    ]
    result = ParserResult(
        parser="evtx",
        source_tool="chainsaw",
        evidence_id=evidence.evidence_id,
        records=tuple(records),
        warnings=(),
        processed_count=2,
        malformed_count=0,
    )

    first = normalize_parser_result(result, evidence=evidence)
    second = normalize_parser_result(result, evidence=evidence)

    assert [event.timestamp_utc for event in first.events] == [
        "2026-05-24T01:00:00Z",
        "2026-05-24T03:00:00Z",
    ]
    assert [event.event_id for event in first.events] == [event.event_id for event in second.events]
    assert first.events[0].provenance == {
        "parser": "evtx",
        "source_event_type": "4688",
        "source_tool": "chainsaw",
    }
    assert first.events[0].raw_reference.record_index == 1
    assert first.events[0].raw_reference.original_hash == "a" * 64


def test_common_fields_are_canonicalized_during_normalization(tmp_path):
    evidence = _evidence(tmp_path)
    parsed = _record(
        fields={
            "UserName": "DOMAIN\\Alice",
            "SHA256": "ABCDEF",
            "FileName": "c:\\Windows\\Temp\\evil.exe",
        }
    )
    result = ParserResult(
        parser="evtx",
        source_tool="chainsaw",
        evidence_id=evidence.evidence_id,
        records=(parsed,),
        warnings=(),
        processed_count=1,
        malformed_count=0,
    )

    event = normalize_parser_result(result, evidence=evidence).events[0]

    assert event.category == "process_execution"
    assert event.artifact == "C:/Windows/Temp/evil.exe"
    assert event.normalized_fields["username"] == "domain/alice"
    assert event.normalized_fields["user"] == "domain/alice"
    assert event.normalized_fields["sha256"] == "abcdef"
    assert event.normalized_fields["filename"] == "C:/Windows/Temp/evil.exe"


def test_volatility_plugins_normalize_to_memory_categories(tmp_path):
    evidence = EvidenceRecord(
        evidence_id="memory",
        path=tmp_path / "memory.raw",
        evidence_type=EvidenceType.MEMORY,
        category=EvidenceCategory.RAW,
        pipeline=Pipeline.RAW,
        trust_tier=TrustTier.TIER_1_HIGH,
        sha256="c" * 64,
        verified=True,
        size_bytes=10,
    )
    result = ParserResult(
        parser="volatility",
        source_tool="volatility",
        evidence_id="memory",
        records=(
            ParsedRecord(
                parser="volatility",
                source_tool="volatility",
                evidence_id="memory",
                evidence_type=EvidenceCategory.RAW,
                trust_tier=TrustTier.TIER_1_HIGH,
                timestamp="2026-05-24T01:02:03Z",
                event_type="windows.pslist",
                artifact="powershell.exe",
                message="",
                raw_reference="4242",
                fields={"PID": "4242", "ImageFileName": "powershell.exe"},
            ),
            ParsedRecord(
                parser="volatility",
                source_tool="volatility",
                evidence_id="memory",
                evidence_type=EvidenceCategory.RAW,
                trust_tier=TrustTier.TIER_1_HIGH,
                timestamp="2026-05-24T01:02:04Z",
                event_type="windows.malfind",
                artifact="evil.exe",
                message="PAGE_EXECUTE_READWRITE",
                raw_reference="4096",
                fields={"PID": "4243", "Process": "evil.exe"},
            ),
        ),
        warnings=(),
        processed_count=2,
        malformed_count=0,
    )

    normalized = normalize_parser_result(result, evidence=evidence)

    assert [event.category for event in normalized.events] == [
        "memory_process",
        "memory_injection_candidate",
    ]


def test_inferred_record_is_not_upgraded_to_raw_or_derived(tmp_path):
    evidence = _evidence(tmp_path, category=EvidenceCategory.RAW, trust_tier=TrustTier.TIER_1_HIGH)
    inferred = _record(
        evidence_type=EvidenceCategory.INFERRED,
        trust_tier=TrustTier.TIER_4_VERY_LOW,
    )
    result = ParserResult(
        parser="evtx",
        source_tool="chainsaw",
        evidence_id=evidence.evidence_id,
        records=(inferred,),
        warnings=(),
        processed_count=1,
        malformed_count=0,
    )

    event = normalize_parser_result(result, evidence=evidence).events[0]

    assert event.evidence_type is EvidenceCategory.INFERRED
    assert event.trust_level is TrustTier.TIER_4_VERY_LOW


def test_pcap_triage_records_normalize_network_metadata(tmp_path):
    evidence = EvidenceRecord(
        evidence_id="capture",
        path=tmp_path / "capture.pcap",
        evidence_type=EvidenceType.PCAP,
        category=EvidenceCategory.RAW,
        pipeline=Pipeline.RAW,
        trust_tier=TrustTier.TIER_1_HIGH,
        sha256="b" * 64,
        verified=True,
        size_bytes=10,
    )
    records = (
        ParsedRecord(
            parser="pcap",
            source_tool="tshark",
            evidence_id="capture",
            evidence_type=EvidenceCategory.RAW,
            trust_tier=TrustTier.TIER_1_HIGH,
            timestamp="1716531723",
            event_type="network_flow",
            artifact="10.0.0.1->10.0.0.2",
            message="example.test",
            raw_reference="1",
            fields={
                "ip.src": "['10.0.0.1']",
                "ip.dst": "['10.0.0.2']",
                "dns.qry.name": "['example.test']",
                "tcp.dstport": "['4444']",
                "frame.len": "['128']",
            },
        ),
        ParsedRecord(
            parser="pcap",
            source_tool="tshark",
            evidence_id="capture",
            evidence_type=EvidenceCategory.RAW,
            trust_tier=TrustTier.TIER_1_HIGH,
            timestamp="1716531724",
            event_type="network_flow",
            artifact="10.0.0.1->10.0.0.3",
            message="www.example.test",
            raw_reference="2",
            fields={"http.host": "['www.example.test']", "http.request.uri": "['/index']"},
        ),
        ParsedRecord(
            parser="pcap",
            source_tool="tshark",
            evidence_id="capture",
            evidence_type=EvidenceCategory.RAW,
            trust_tier=TrustTier.TIER_1_HIGH,
            timestamp="1716531725",
            event_type="network_flow",
            artifact="10.0.0.1->10.0.0.4",
            message="login.example.test",
            raw_reference="3",
            fields={"tls.handshake.extensions_server_name": "['login.example.test']"},
        ),
    )
    result = ParserResult(
        parser="pcap",
        source_tool="tshark",
        evidence_id="capture",
        records=records,
        warnings=(),
        processed_count=3,
        malformed_count=0,
    )

    normalized = normalize_parser_result(result, evidence=evidence)

    assert [event.category for event in normalized.events] == [
        "network_dns",
        "network_http",
        "network_tls",
    ]
    assert normalized.events[0].normalized_fields["src_ip"] == "10.0.0.1"
    assert normalized.events[0].normalized_fields["dst_ip"] == "10.0.0.2"
    assert normalized.events[0].normalized_fields["dns_query"] == "example.test"
    assert normalized.events[0].normalized_fields["byte_count"] == "128"
    assert normalized.events[0].normalized_fields["unusual_port"] == "4444"
    assert normalized.events[1].normalized_fields["http_host"] == "www.example.test"
    assert normalized.events[2].normalized_fields["tls_sni"] == "login.example.test"


def test_normalized_batch_cap_behavior_is_warned(monkeypatch):
    monkeypatch.setattr(normalization, "get_max_events", lambda: 3)
    records = tuple(_record(raw_reference=str(index)) for index in range(4))
    result = ParserResult(
        parser="evtx",
        source_tool="chainsaw",
        evidence_id="security",
        records=records,
        warnings=(),
        processed_count=4,
        malformed_count=0,
    )

    normalized = normalize_parser_results([result])

    assert normalized.truncated is True
    assert normalized.processed_count == 3
    assert len(normalized.events) == 3
    assert any(warning.warning_type == "EVENT_TRUNCATION" for warning in normalized.warnings)
