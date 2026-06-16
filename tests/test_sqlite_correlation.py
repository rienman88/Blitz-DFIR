from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from blitz_dfir.correlation.sqlite_backend import correlate_normalized_events_sqlite


def test_sqlite_correlation_scans_full_store_and_loads_only_support_events(tmp_path: Path) -> None:
    store_path = tmp_path / "event_store.sqlite"
    connection = sqlite3.connect(store_path)
    try:
        connection.execute(
            """
            CREATE TABLE normalized_events (
                row_number INTEGER PRIMARY KEY,
                event_id TEXT NOT NULL,
                timestamp_utc TEXT NOT NULL,
                category TEXT NOT NULL,
                artifact TEXT NOT NULL,
                message TEXT NOT NULL,
                source_tool TEXT NOT NULL,
                source_parser TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                trust_level TEXT NOT NULL,
                confidence REAL NOT NULL,
                raw_reference_json TEXT NOT NULL,
                normalized_fields_json TEXT NOT NULL,
                provenance_json TEXT NOT NULL,
                warnings_json TEXT NOT NULL
            )
            """
        )
        rows = [
            (
                1,
                "EVT-001",
                "2026-05-28T00:00:01Z",
                "timeline_event",
                "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                "powershell -EncodedCommand AAAA",
                "psort",
                "plaso",
                "rd01-plaso",
                "DERIVED",
                "TIER_2_MEDIUM_HIGH",
                1.0,
                json.dumps({"evidence_id": "rd01-plaso", "record_index": 1}),
                json.dumps({"commandline": "powershell -EncodedCommand AAAA"}),
                json.dumps({"parser": "plaso"}),
                "[]",
            ),
            (
                2,
                "EVT-002",
                "2026-05-28T00:00:02Z",
                "timeline_event",
                "C:/Windows/System32/calc.exe",
                "ordinary event",
                "psort",
                "plaso",
                "rd01-plaso",
                "DERIVED",
                "TIER_2_MEDIUM_HIGH",
                1.0,
                json.dumps({"evidence_id": "rd01-plaso", "record_index": 2}),
                json.dumps({"commandline": "calc.exe"}),
                json.dumps({"parser": "plaso"}),
                "[]",
            ),
            (
                3,
                "EVT-003",
                "2026-05-28T00:00:03Z",
                "timeline_event",
                "HKLM/System/CurrentControlSet/Services/test",
                "service persistence reference",
                "psort",
                "plaso",
                "rd01-plaso",
                "DERIVED",
                "TIER_2_MEDIUM_HIGH",
                1.0,
                json.dumps({"evidence_id": "rd01-plaso", "record_index": 3}),
                json.dumps({"path": "HKLM/System/CurrentControlSet/Services/test"}),
                json.dumps({"parser": "plaso"}),
                "[]",
            ),
        ]
        connection.executemany(
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
            rows,
        )
        connection.commit()
    finally:
        connection.close()

    result = correlate_normalized_events_sqlite(store_path, finding_limit=10, support_event_limit=2)

    assert result.rows_scanned == 3
    assert result.candidate_count >= 1
    assert result.findings
    assert 1 <= len(result.support_events) <= 2

    connection = sqlite3.connect(store_path)
    try:
        candidate_row = connection.execute("SELECT COUNT(*) FROM sql_correlation_candidates").fetchone()
    finally:
        connection.close()
    assert candidate_row is not None
    assert candidate_row[0] == len(result.findings)


def test_sqlite_correlation_dedupes_findings_and_uses_specific_titles(tmp_path: Path) -> None:
    store_path = tmp_path / "event_store.sqlite"
    connection = sqlite3.connect(store_path)
    try:
        connection.execute(
            """
            CREATE TABLE normalized_events (
                row_number INTEGER PRIMARY KEY,
                event_id TEXT NOT NULL,
                timestamp_utc TEXT NOT NULL,
                category TEXT NOT NULL,
                artifact TEXT NOT NULL,
                message TEXT NOT NULL,
                source_tool TEXT NOT NULL,
                source_parser TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                trust_level TEXT NOT NULL,
                confidence REAL NOT NULL,
                raw_reference_json TEXT NOT NULL,
                normalized_fields_json TEXT NOT NULL,
                provenance_json TEXT NOT NULL,
                warnings_json TEXT NOT NULL
            )
            """
        )
        duplicate_event = (
            "EVT-DUP",
            "2026-05-28T00:00:01Z",
            "evt",
            "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
            "powershell -EncodedCommand AAAA",
            "psort",
            "plaso",
            "rd01-plaso",
            "DERIVED",
            "TIER_2_MEDIUM_HIGH",
            1.0,
            json.dumps({"evidence_id": "rd01-plaso", "record_index": 1}),
            json.dumps({"commandline": "powershell -EncodedCommand AAAA"}),
            json.dumps({"parser": "plaso"}),
            "[]",
        )
        connection.executemany(
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
            [
                (1, *duplicate_event),
                (2, *duplicate_event),
            ],
        )
        connection.commit()
    finally:
        connection.close()

    result = correlate_normalized_events_sqlite(store_path, finding_limit=10, support_event_limit=10)

    finding_ids = [finding.finding_id for finding in result.findings]
    assert len(finding_ids) == len(set(finding_ids))
    assert any("living-off-the-land execution indicators" in finding.title for finding in result.findings)
    assert all(not finding.title.endswith(": evt") for finding in result.findings)


def test_sqlite_correlation_flags_suspicious_memory_process_rows(tmp_path: Path) -> None:
    store_path = tmp_path / "event_store.sqlite"
    connection = sqlite3.connect(store_path)
    try:
        connection.execute(
            """
            CREATE TABLE normalized_events (
                row_number INTEGER PRIMARY KEY,
                event_id TEXT NOT NULL,
                timestamp_utc TEXT NOT NULL,
                category TEXT NOT NULL,
                artifact TEXT NOT NULL,
                message TEXT NOT NULL,
                source_tool TEXT NOT NULL,
                source_parser TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                trust_level TEXT NOT NULL,
                confidence REAL NOT NULL,
                raw_reference_json TEXT NOT NULL,
                normalized_fields_json TEXT NOT NULL,
                provenance_json TEXT NOT NULL,
                warnings_json TEXT NOT NULL
            )
            """
        )
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
                "EVT-MEM-001",
                "2026-05-28T00:00:01Z",
                "memory_process",
                "powershell.exe",
                "",
                "volatility",
                "volatility",
                "rocba-memory",
                "RAW",
                "TIER_1_HIGH",
                1.0,
                json.dumps({"evidence_id": "rocba-memory", "record_index": 4242}),
                json.dumps({"pid": "4242", "imagefilename": "powershell.exe"}),
                json.dumps({"parser": "volatility", "source_event_type": "windows.pslist"}),
                "[]",
            ),
        )
        connection.commit()
    finally:
        connection.close()

    result = correlate_normalized_events_sqlite(store_path, finding_limit=10, support_event_limit=10)

    assert result.candidate_count == 1
    assert result.findings
    assert any("memory-process indicators" in finding.title for finding in result.findings)
    assert any("memory process name or command token merits review" in finding.suspicion_reasons for finding in result.findings)
