from __future__ import annotations

import csv
import json
import sqlite3
from pathlib import Path

import pytest

from blitz_dfir.core.models import EvidenceCategory, EvidenceRecord, EvidenceType, Pipeline, TrustTier
from blitz_dfir.core.normalization import build_normalized_event
from blitz_dfir.core.session import CaseSession
from blitz_dfir.correlation.sqlite_backend import correlate_normalized_events_sqlite
from blitz_dfir.pipeline import analyze
from blitz_dfir.sanitization.sanitizer import DEFAULT_MAX_EVENTS, configure_max_events


def test_sqlite_backed_normalization_streams_to_store_and_keeps_analysis_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_root = tmp_path / "output" / "sess-test"
    timelines_dir = session_root / "timelines"
    findings_dir = session_root / "findings"
    reports_dir = session_root / "reports"
    audit_dir = session_root / "audit"
    for directory in (timelines_dir, findings_dir, reports_dir, audit_dir):
        directory.mkdir(parents=True)

    csv_path = timelines_dir / "rd01-plaso.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["datetime", "message", "source", "filename", "display_name"],
        )
        writer.writeheader()
        for index in range(1, 12):
            writer.writerow(
                {
                    "datetime": f"2026-05-28T00:00:{index:02d}Z",
                    "message": f"event {index}",
                    "source": "EVT",
                    "filename": "C:/Windows/System32/cmd.exe",
                    "display_name": str(index),
                }
            )

    session = CaseSession(
        case_id="case",
        session_id="sess-test",
        session_root=session_root,
        reports_dir=reports_dir,
        audit_dir=audit_dir,
        findings_dir=findings_dir,
        timelines_dir=timelines_dir,
        audit_log_path=audit_dir / "sess-test.ndjson",
    )
    evidence = EvidenceRecord(
        evidence_id="rd01-plaso",
        path=tmp_path / "case.plaso",
        evidence_type=EvidenceType.PLASO,
        category=EvidenceCategory.DERIVED,
        pipeline=Pipeline.PROCESSED,
        trust_tier=TrustTier.TIER_2_MEDIUM_HIGH,
        sha256="0" * 64,
        verified=True,
        size_bytes=1,
    )

    monkeypatch.setenv("BLITZ_SQLITE_NORMALIZATION", "1")
    monkeypatch.setenv("BLITZ_ANALYSIS_EVENT_LIMIT", "5")
    configure_max_events(10)
    try:
        result = analyze._try_sqlite_backed_normalization(
            session=session,
            tool_results=[
                {
                    "typed_tool": "psort",
                    "tool_name": "psort",
                    "evidence_id": "rd01-plaso",
                    "outputs": {"primary_output": "timelines/rd01-plaso.csv"},
                }
            ],
            evidence_by_id={"rd01-plaso": evidence},
        )
    finally:
        configure_max_events(DEFAULT_MAX_EVENTS)

    assert result is not None
    assert result.processed_count == 10
    assert len(result.events) == 5
    assert result.truncated is True

    connection = sqlite3.connect(findings_dir / "event_store.sqlite")
    try:
        row = connection.execute("SELECT COUNT(*) FROM normalized_events").fetchone()
        category_row = connection.execute(
            """
            SELECT evidence_id, evidence_type, trust_level, COUNT(*)
            FROM normalized_events
            GROUP BY evidence_id, evidence_type, trust_level
            """
        ).fetchone()
    finally:
        connection.close()
    assert row is not None
    row_count = row[0]
    assert row_count == 10
    assert category_row == ("rd01-plaso", "DERIVED", "TIER_2_MEDIUM_HIGH", 10)


def test_full_sql_normalization_uses_bounded_memory_window_without_losing_store_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_root = tmp_path / "output" / "sess-full-sql"
    timelines_dir = session_root / "timelines"
    findings_dir = session_root / "findings"
    reports_dir = session_root / "reports"
    audit_dir = session_root / "audit"
    for directory in (timelines_dir, findings_dir, reports_dir, audit_dir):
        directory.mkdir(parents=True)

    csv_path = timelines_dir / "large-plaso.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["datetime", "message", "source", "filename", "display_name"],
        )
        writer.writeheader()
        for index in range(1, 31):
            writer.writerow(
                {
                    "datetime": f"2026-05-28T00:02:{index:02d}Z",
                    "message": f"event {index}",
                    "source": "EVT",
                    "filename": "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                    "display_name": str(index),
                }
            )

    session = CaseSession(
        case_id="case",
        session_id="sess-full-sql",
        session_root=session_root,
        reports_dir=reports_dir,
        audit_dir=audit_dir,
        findings_dir=findings_dir,
        timelines_dir=timelines_dir,
        audit_log_path=audit_dir / "sess-full-sql.ndjson",
    )
    evidence = EvidenceRecord(
        evidence_id="large-plaso",
        path=tmp_path / "case.plaso",
        evidence_type=EvidenceType.PLASO,
        category=EvidenceCategory.DERIVED,
        pipeline=Pipeline.PROCESSED,
        trust_tier=TrustTier.TIER_2_MEDIUM_HIGH,
        sha256="0" * 64,
        verified=True,
        size_bytes=1,
    )

    monkeypatch.setenv("BLITZ_SQLITE_NORMALIZATION", "1")
    monkeypatch.setenv("BLITZ_ANALYSIS_EVENT_LIMIT", "2000000")
    monkeypatch.setenv("BLITZ_SQLITE_ANALYSIS_EVENT_MEMORY_LIMIT", "7")
    configure_max_events(30)
    try:
        result = analyze._try_sqlite_backed_normalization(
            session=session,
            tool_results=[
                {
                    "typed_tool": "psort",
                    "tool_name": "psort",
                    "evidence_id": "large-plaso",
                    "outputs": {"primary_output": "timelines/large-plaso.csv"},
                }
            ],
            evidence_by_id={"large-plaso": evidence},
            full_sql_correlation=True,
        )
    finally:
        configure_max_events(DEFAULT_MAX_EVENTS)

    assert result is not None
    assert result.processed_count == 30
    assert len(result.events) == 7

    with sqlite3.connect(findings_dir / "event_store.sqlite") as connection:
        row = connection.execute("SELECT COUNT(*) FROM normalized_events").fetchone()
    assert row is not None
    assert row[0] == 30


def test_sqlite_backed_normalization_streams_disk_triage_jsonl(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_root = tmp_path / "output" / "sess-disk"
    findings_dir = session_root / "findings"
    for directory in (findings_dir, session_root / "timelines", session_root / "reports", session_root / "audit"):
        directory.mkdir(parents=True)

    summary_path = findings_dir / "disk.disk_triage.json"
    entries_path = findings_dir / "disk.disk_triage.entries.jsonl"
    with entries_path.open("w", encoding="utf-8") as handle:
        for index in range(1, 8):
            handle.write(
                json.dumps(
                    {
                        "partition": {"slot": "raw", "start": 0, "description": "raw filesystem fallback"},
                        "entry": {
                            "partition_start": 0,
                            "path": f"/Windows/System32/winevt/Logs/Test{index}.evtx",
                            "inode": str(index),
                            "mode": "r/r",
                            "size": 100 + index,
                            "mtime": f"2026-05-28T00:01:{index:02d}Z",
                            "artifact_family": "windows_event_log",
                            "risk_tags": [],
                        },
                    }
                )
                + "\n"
            )
    summary_path.write_text(
        json.dumps(
            {
                "schema_version": "blitz-disk-triage.v1",
                "entry_count": 7,
                "entries_output": entries_path.name,
                "entries_output_format": "jsonl",
                "entries_omitted_from_summary": 7,
                "warnings": [],
                "partitions": [{"slot": "raw", "start": 0, "description": "raw filesystem fallback", "entries": []}],
            }
        ),
        encoding="utf-8",
    )

    session = CaseSession(
        case_id="case",
        session_id="sess-disk",
        session_root=session_root,
        reports_dir=session_root / "reports",
        audit_dir=session_root / "audit",
        findings_dir=findings_dir,
        timelines_dir=session_root / "timelines",
        audit_log_path=session_root / "audit" / "sess-disk.ndjson",
    )
    evidence = EvidenceRecord(
        evidence_id="disk",
        path=tmp_path / "disk.E01",
        evidence_type=EvidenceType.E01,
        category=EvidenceCategory.RAW,
        pipeline=Pipeline.RAW,
        trust_tier=TrustTier.TIER_1_HIGH,
        sha256="0" * 64,
        verified=True,
        size_bytes=1,
    )

    monkeypatch.setenv("BLITZ_SQLITE_NORMALIZATION", "1")
    monkeypatch.setenv("BLITZ_ANALYSIS_EVENT_LIMIT", "2")
    configure_max_events(10)
    try:
        result = analyze._try_sqlite_backed_normalization(
            session=session,
            tool_results=[
                {
                    "typed_tool": "disk_triage",
                    "tool_name": "disk_triage",
                    "evidence_id": "disk",
                    "outputs": {"primary_output": "findings/disk.disk_triage.json"},
                }
            ],
            evidence_by_id={"disk": evidence},
        )
    finally:
        configure_max_events(DEFAULT_MAX_EVENTS)

    assert result is not None
    assert result.processed_count == 7
    assert len(result.events) == 2
    assert result.truncated is False

    with sqlite3.connect(findings_dir / "event_store.sqlite") as connection:
        row = connection.execute("SELECT COUNT(*) FROM normalized_events").fetchone()
        source_row = connection.execute(
            "SELECT source_tool, source_parser, evidence_id, COUNT(*) FROM normalized_events GROUP BY 1, 2, 3"
        ).fetchone()
    assert row is not None
    assert row[0] == 7
    assert source_row == ("disk_triage", "disk_triage", "disk", 7)


def test_normalized_store_replacement_uses_staging_table(tmp_path: Path) -> None:
    store_path = tmp_path / "event_store.sqlite"
    connection = sqlite3.connect(store_path)
    try:
        analyze._initialize_normalized_event_store(connection)
        connection.execute(
            """
            INSERT INTO normalized_events (
                row_number,
                event_id,
                timestamp_utc,
                category,
                artifact,
                message,
                source_tool,
                source_parser,
                evidence_id,
                evidence_type,
                trust_level,
                confidence,
                raw_reference_json,
                normalized_fields_json,
                provenance_json,
                warnings_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                1,
                "OLD",
                "2026-05-28T00:00:00Z",
                "timeline_event",
                "old",
                "old",
                "psort",
                "plaso",
                "rd01-plaso",
                "DERIVED",
                "TIER_2_MEDIUM_HIGH",
                1.0,
                "{}",
                "{}",
                "{}",
                "[]",
            ),
        )
        connection.commit()

        analyze._initialize_normalized_event_store(connection, table_name="normalized_events_next")
        connection.execute(
            """
            INSERT INTO normalized_events_next (
                row_number,
                event_id,
                timestamp_utc,
                category,
                artifact,
                message,
                source_tool,
                source_parser,
                evidence_id,
                evidence_type,
                trust_level,
                confidence,
                raw_reference_json,
                normalized_fields_json,
                provenance_json,
                warnings_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                1,
                "NEW",
                "2026-05-28T00:00:00Z",
                "timeline_event",
                "new",
                "new",
                "psort",
                "plaso",
                "rd01-plaso",
                "DERIVED",
                "TIER_2_MEDIUM_HIGH",
                1.0,
                "{}",
                "{}",
                "{}",
                "[]",
            ),
        )

        before = connection.execute("SELECT event_id FROM normalized_events").fetchone()
        assert before is not None
        assert before[0] == "OLD"

        analyze._replace_normalized_event_store(
            connection,
            staging_table="normalized_events_next",
            target_table="normalized_events",
        )
        after = connection.execute("SELECT event_id FROM normalized_events").fetchone()
    finally:
        connection.close()

    assert after is not None
    assert after[0] == "NEW"


def test_in_memory_normalized_events_materialize_to_sqlite_store(tmp_path: Path) -> None:
    session_root = tmp_path / "output" / "sess-test"
    findings_dir = session_root / "findings"
    session = CaseSession(
        case_id="case",
        session_id="sess-test",
        session_root=session_root,
        reports_dir=session_root / "reports",
        audit_dir=session_root / "audit",
        findings_dir=findings_dir,
        timelines_dir=session_root / "timelines",
        audit_log_path=session_root / "audit" / "sess-test.ndjson",
    )
    evidence = EvidenceRecord(
        evidence_id="memory",
        path=tmp_path / "memory.raw",
        evidence_type=EvidenceType.MEMORY,
        category=EvidenceCategory.RAW,
        pipeline=Pipeline.RAW,
        trust_tier=TrustTier.TIER_1_HIGH,
        sha256="0" * 64,
        verified=True,
        size_bytes=1,
    )
    event = build_normalized_event(
        evidence=evidence,
        timestamp="2026-05-24T01:00:02Z",
        category="windows.pslist",
        source_tool="volatility",
        source_parser="volatility",
        artifact="powershell.exe",
        message="powershell.exe -EncodedCommand AAAA",
        raw_record_index=1,
        normalized_fields={"commandline": "powershell.exe -EncodedCommand AAAA"},
    )

    store_path = analyze._write_in_memory_normalized_events_to_sqlite(session=session, events=(event,))

    with sqlite3.connect(store_path) as connection:
        row = connection.execute("SELECT COUNT(*) FROM normalized_events").fetchone()
    assert row is not None
    assert row[0] == 1

    result = correlate_normalized_events_sqlite(store_path, finding_limit=10, support_event_limit=10)
    assert result.rows_scanned == 1
    assert result.findings


def test_empty_in_memory_normalized_events_create_sqlite_table_without_crashing(tmp_path: Path) -> None:
    session_root = tmp_path / "output" / "sess-empty"
    session = CaseSession(
        case_id="case",
        session_id="sess-empty",
        session_root=session_root,
        reports_dir=session_root / "reports",
        audit_dir=session_root / "audit",
        findings_dir=session_root / "findings",
        timelines_dir=session_root / "timelines",
        audit_log_path=session_root / "audit" / "sess-empty.ndjson",
    )

    store_path = analyze._write_in_memory_normalized_events_to_sqlite(session=session, events=())
    result = correlate_normalized_events_sqlite(store_path, finding_limit=10, support_event_limit=10)

    assert result.rows_scanned == 0
    assert result.candidate_count == 0
    assert result.findings == ()


def test_sqlite_event_store_checkpoint_truncates_wal_before_manifest(tmp_path: Path) -> None:
    store_path = tmp_path / "event_store.sqlite"
    connection = sqlite3.connect(store_path)
    try:
        analyze._configure_sqlite_for_streaming(connection)
        analyze._initialize_normalized_event_store(connection)
        connection.execute(
            """
            INSERT INTO normalized_events (
                row_number,
                event_id,
                timestamp_utc,
                category,
                artifact,
                message,
                source_tool,
                source_parser,
                evidence_id,
                evidence_type,
                trust_level,
                confidence,
                raw_reference_json,
                normalized_fields_json,
                provenance_json,
                warnings_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                1,
                "EVT-1",
                "2026-05-28T00:00:00Z",
                "timeline_event",
                "artifact",
                "message",
                "psort",
                "plaso",
                "rd01-plaso",
                "DERIVED",
                "TIER_2_MEDIUM_HIGH",
                1.0,
                "{}",
                "{}",
                "{}",
                "[]",
            ),
        )
        connection.commit()
        assert store_path.with_name(store_path.name + "-wal").exists()
    finally:
        connection.close()

    result = analyze._checkpoint_sqlite_event_store(store_path)

    assert result["status"] == "completed"
    assert result["journal_mode"] == "delete"
    assert result["wal_exists_after"] is False
    with sqlite3.connect(store_path) as verify:
        row = verify.execute("SELECT COUNT(*) FROM normalized_events").fetchone()
    assert row is not None
    assert row[0] == 1
