from __future__ import annotations

import json
import hashlib
from pathlib import Path

from blitz_dfir.core.models import EvidenceCategory, EvidenceRecord, EvidenceType, Pipeline, TrustTier
from blitz_dfir.parsers.disk_triage_parser import parse_disk_triage_json


def _evidence(tmp_path: Path) -> EvidenceRecord:
    path = tmp_path / "disk.E01"
    path.write_bytes(b"e01")
    return EvidenceRecord(
        evidence_id="disk",
        path=path,
        evidence_type=EvidenceType.E01,
        category=EvidenceCategory.RAW,
        pipeline=Pipeline.RAW,
        trust_tier=TrustTier.TIER_1_HIGH,
        sha256=hashlib.sha256(b"e01").hexdigest(),
        verified=True,
        size_bytes=path.stat().st_size,
    )


def test_disk_triage_parser_normalizes_high_value_and_suspicious_paths(tmp_path):
    payload = {
        "warnings": [{"severity": "HIGH", "reason": "mmls produced no selected partitions"}],
        "partitions": [
            {
                "start": 2048,
                "description": "NTFS / exFAT",
                "warnings": [{"severity": "LOW", "reason": "fls stderr contained recoverable noise"}],
                "entries": [
                    {
                        "partition_start": 2048,
                        "path": "/Windows/System32/winevt/Logs/Security.evtx",
                        "inode": "12",
                        "mode": "r/r",
                        "size": 1234,
                        "mtime": "2026-05-20T07:10:00Z",
                        "artifact_family": "windows_event_log",
                        "risk_tags": [],
                    },
                    {
                        "partition_start": 2048,
                        "path": "/Users/Alice/Downloads/dropper.exe",
                        "inode": "13",
                        "mode": "r/r",
                        "size": 4321,
                        "mtime": "2026-05-20T07:12:00Z",
                        "artifact_family": "",
                        "risk_tags": ["downloaded_executable_or_script"],
                    },
                ],
            }
        ],
    }

    result = parse_disk_triage_json(json.dumps(payload), _evidence(tmp_path))

    assert result.parser == "disk_triage"
    assert result.source_tool == "disk_triage"
    assert result.processed_count == 2
    assert result.records[0].event_type == "windows_event_log"
    assert result.records[1].event_type == "disk_suspicious_path"
    assert result.records[1].fields["risk_tags"] == "downloaded_executable_or_script"
    assert {warning.warning_type for warning in result.warnings} == {
        "DISK_TRIAGE_WARNING",
        "DISK_TRIAGE_PARTITION_WARNING",
    }
