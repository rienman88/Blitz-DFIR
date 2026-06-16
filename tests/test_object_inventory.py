from __future__ import annotations

import hashlib
import json
import sqlite3

from blitz_dfir.core.manifest import load_manifest
from blitz_dfir.core.normalization import build_normalized_event
from blitz_dfir.inventory.object_inventory import build_object_inventory_report


def test_object_inventory_extracts_entities_from_normalized_events(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    timeline = evidence_root / "timeline.csv"
    timeline.write_text("timeline", encoding="utf-8")
    manifest_path = tmp_path / "case.yaml"
    manifest_path.write_text(
        f"""
case_id: object-case
evidence_root: evidence
output_root: output
evidence:
  - id: timeline
    path: timeline.csv
    type: CSV_TIMELINE
    sha256: {hashlib.sha256(b"timeline").hexdigest()}
""".strip(),
        encoding="utf-8",
    )
    manifest = load_manifest(manifest_path)
    event = build_normalized_event(
        evidence=manifest.evidence[0],
        timestamp="2026-05-29T00:00:00Z",
        category="process_execution",
        source_tool="direct_parse",
        source_parser="plaso",
        artifact=r"C:\Windows\System32\powershell.exe",
        message="powershell -EncodedCommand AAAA",
        normalized_fields={
            "user": "DOMAIN/Alice",
            "processid": "4242",
            "commandline": "powershell -EncodedCommand AAAA",
            "sha256": "a" * 64,
        },
    )

    report = build_object_inventory_report(
        case_id=manifest.case_id,
        manifest=manifest,
        events=(event,),
    )

    values = {(item.object_type, item.value) for item in report.items}
    assert report.source == "in_memory_normalized_events"
    assert report.normalized_event_count == 1
    assert ("user", "DOMAIN/Alice") in values
    assert ("process_id", "processid:4242") in values
    assert any(item.object_type == "hash" for item in report.items)
    assert any("living_off_the_land" in item.risk_tags for item in report.items)
    assert any(item.object_type == "command_line" for item in report.items)


def test_object_inventory_scans_sqlite_normalized_store(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    timeline = evidence_root / "timeline.csv"
    timeline.write_text("timeline", encoding="utf-8")
    manifest_path = tmp_path / "case.yaml"
    manifest_path.write_text(
        f"""
case_id: object-sqlite-case
evidence_root: evidence
output_root: output
evidence:
  - id: timeline
    path: timeline.csv
    type: CSV_TIMELINE
    sha256: {hashlib.sha256(b"timeline").hexdigest()}
""".strip(),
        encoding="utf-8",
    )
    manifest = load_manifest(manifest_path)
    store = tmp_path / "event_store.sqlite"
    with sqlite3.connect(store) as connection:
        connection.execute(
            """
            CREATE TABLE normalized_events (
                row_number INTEGER PRIMARY KEY,
                event_id TEXT NOT NULL,
                timestamp_utc TEXT NOT NULL,
                category TEXT NOT NULL,
                artifact TEXT NOT NULL,
                message TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                normalized_fields_json TEXT NOT NULL
            )
            """
        )
        connection.executemany(
            """
            INSERT INTO normalized_events (
                row_number, event_id, timestamp_utc, category, artifact, message, evidence_id,
                normalized_fields_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    1,
                    "EVT-1",
                    "2026-05-29T00:00:00Z",
                    "network_dns",
                    "10.0.0.1->8.8.8.8",
                    "DNS query for evil.example from 10.0.0.1",
                    "timeline",
                    json.dumps({"dns_query": "evil.example", "src_ip": "10.0.0.1"}),
                ),
                (
                    2,
                    "EVT-2",
                    "2026-05-29T00:01:00Z",
                    "registry_persistence",
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    r"Set HKCU\Software\Microsoft\Windows\CurrentVersion\Run to C:\Users\Alice\AppData\bad.exe",
                    "timeline",
                    json.dumps({"user": "alice"}),
                ),
            ],
        )

    report = build_object_inventory_report(
        case_id=manifest.case_id,
        manifest=manifest,
        events=(),
        store_path=store,
    )

    assert report.source == "sqlite_normalized_events"
    assert report.normalized_event_count == 2
    assert report.event_category_counts["network_dns"] == 1
    assert report.object_mention_counts["network_ip"] >= 2
    assert any(item.object_type == "registry_key" for item in report.items)
    assert any(item.object_type == "domain" and item.value == "evil.example" for item in report.items)
    assert any(item.object_type == "file_path" for item in report.items)
