from __future__ import annotations

import csv
import hashlib
import json
import sqlite3

from blitz_dfir.accounting.event_store import build_full_accounting
from blitz_dfir.core.models import (
    EvidenceCategory,
    EvidenceManifest,
    EvidenceRecord,
    EvidenceType,
    Pipeline,
    TrustTier,
)
from blitz_dfir.core.session import create_session
from blitz_dfir.sanitization.sanitizer import MAX_EVENTS


def test_full_accounting_streams_all_csv_rows_into_event_store(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    plaso = evidence_root / "case.plaso"
    plaso.write_bytes(b"plaso")
    evidence = EvidenceRecord(
        evidence_id="plaso",
        path=plaso,
        evidence_type=EvidenceType.PLASO,
        category=EvidenceCategory.DERIVED,
        pipeline=Pipeline.PROCESSED,
        trust_tier=TrustTier.TIER_2_MEDIUM_HIGH,
        sha256=hashlib.sha256(b"plaso").hexdigest(),
        verified=True,
        size_bytes=plaso.stat().st_size,
        internally_generated=True,
    )
    manifest = EvidenceManifest(
        case_id="case-accounting",
        evidence_root=evidence_root,
        output_root=tmp_path / "output",
        source_path=tmp_path / "case.yaml",
        evidence=(evidence,),
    )
    session = create_session(manifest)
    timeline_dir = session.session_root / "timelines"
    timeline_dir.mkdir(parents=True, exist_ok=True)
    csv_path = timeline_dir / "plaso.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=("datetime", "source", "parser", "data_type", "message"),
        )
        writer.writeheader()
        row_total = MAX_EVENTS + 25
        for index in range(1, row_total + 1):
            writer.writerow(
                {
                    "datetime": f"2026-05-{((index - 1) % 28) + 1:02d}T00:00:00Z",
                    "source": "EVT",
                    "parser": "winevtx",
                    "data_type": "windows:evtx:record",
                    "message": f"event {index}",
                }
            )
    summary = build_full_accounting(
        session=session,
        tool_results=[
            {
                "typed_tool": "psort",
                "tool_name": "psort",
                "evidence_id": "plaso",
                "execution": {"timed_out": True},
                "outputs": {"primary_output": "timelines/plaso.csv"},
            }
        ],
    )

    assert summary.total_rows == row_total
    assert summary.artifacts[0].timed_out is True
    assert summary.artifacts[0].counts_by_parser == {"winevtx": row_total}
    with sqlite3.connect(session.findings_dir / "event_store.sqlite") as connection:
        row_count = connection.execute("SELECT COUNT(*) FROM event_rows").fetchone()[0]
    assert row_count == row_total


def test_full_accounting_streams_json_tool_rows_into_event_store(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    memory = evidence_root / "memory.raw"
    memory.write_bytes(b"memory")
    evidence = EvidenceRecord(
        evidence_id="memory",
        path=memory,
        evidence_type=EvidenceType.MEMORY,
        category=EvidenceCategory.RAW,
        pipeline=Pipeline.RAW,
        trust_tier=TrustTier.TIER_1_HIGH,
        sha256=hashlib.sha256(b"memory").hexdigest(),
        verified=True,
        size_bytes=memory.stat().st_size,
    )
    manifest = EvidenceManifest(
        case_id="case-json-accounting",
        evidence_root=evidence_root,
        output_root=tmp_path / "output",
        source_path=tmp_path / "case.yaml",
        evidence=(evidence,),
    )
    session = create_session(manifest)
    findings_dir = session.session_root / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    json_path = findings_dir / "memory.windows_pslist.json"
    json_path.write_text(
        json.dumps(
            [
                {"ImageFileName": "System", "PID": 4, "CreateTime": "2020-11-11T08:13:00Z"},
                {"ImageFileName": "cmd.exe", "PID": 4242, "CreateTime": "2020-11-11T08:14:00Z"},
            ]
        ),
        encoding="utf-8",
    )

    summary = build_full_accounting(
        session=session,
        tool_results=[
            {
                "typed_tool": "memory",
                "tool_name": "volatility",
                "evidence_id": "memory",
                "execution": {"timed_out": False},
                "outputs": {"primary_output": "findings/memory.windows_pslist.json"},
            }
        ],
    )

    assert summary.total_rows == 2
    assert summary.artifact_count == 1
    assert summary.artifacts[0].source_tool == "memory"
    assert summary.artifacts[0].parser == "volatility"
    assert summary.artifacts[0].counts_by_data_type == {"json": 2}
    with sqlite3.connect(session.findings_dir / "event_store.sqlite") as connection:
        row_count = connection.execute("SELECT COUNT(*) FROM event_rows").fetchone()[0]
    assert row_count == 2
