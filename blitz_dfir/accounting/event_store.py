from __future__ import annotations

import csv
import json
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any

from blitz_dfir.accounting.models import AccountingArtifact, FullAccountingSummary
from blitz_dfir.core.integrity import hash_text, sha256_file
from blitz_dfir.core.session import CaseSession


def build_full_accounting(
    *,
    session: CaseSession,
    tool_results: list[dict[str, Any]],
) -> FullAccountingSummary:
    store_path = session.findings_dir / "event_store.sqlite"
    store_path.parent.mkdir(parents=True, exist_ok=True)
    artifacts: list[AccountingArtifact] = []
    with sqlite3.connect(store_path) as connection:
        _initialize_store(connection)
        connection.commit()
        for index, result in enumerate(tool_results, 1):
            artifact = _account_tool_result(
                connection=connection,
                session=session,
                result=result,
                artifact_index=index,
            )
            if artifact is not None:
                artifacts.append(artifact)
        _create_indexes(connection)
        connection.commit()
    return FullAccountingSummary(
        event_store_path=_relative_path(store_path, session),
        artifact_count=len(artifacts),
        total_rows=sum(artifact.row_count for artifact in artifacts),
        artifacts=tuple(artifacts),
    )


def _initialize_store(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS event_rows (
            artifact_id TEXT NOT NULL,
            evidence_id TEXT NOT NULL,
            source_tool TEXT NOT NULL,
            parser TEXT NOT NULL,
            row_number INTEGER NOT NULL,
            row_hash TEXT NOT NULL,
            timestamp TEXT,
            category TEXT,
            source TEXT,
            data_type TEXT,
            artifact TEXT,
            message TEXT,
            raw_json TEXT NOT NULL,
            PRIMARY KEY (artifact_id, row_number)
        )
        """
    )


def _create_indexes(connection: sqlite3.Connection) -> None:
    connection.execute("CREATE INDEX IF NOT EXISTS idx_event_rows_evidence ON event_rows(evidence_id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_event_rows_timestamp ON event_rows(timestamp)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_event_rows_source ON event_rows(source)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_event_rows_data_type ON event_rows(data_type)")


def _account_tool_result(
    *,
    connection: sqlite3.Connection,
    session: CaseSession,
    result: dict[str, Any],
    artifact_index: int,
) -> AccountingArtifact | None:
    outputs = _dict_value(result, "outputs")
    primary = outputs.get("primary_output")
    if not isinstance(primary, str):
        return None
    source_path = (session.session_root / primary).resolve()
    if not source_path.exists() or not source_path.is_file():
        return None
    tool = str(result.get("typed_tool") or result.get("tool_name") or "unknown")
    parser = _parser_for_tool(tool)
    evidence_id = str(result.get("evidence_id") or f"artifact-{artifact_index}")
    artifact_id = f"{evidence_id}-{tool}-{artifact_index}"
    execution = _dict_value(result, "execution")
    suffix = source_path.suffix.lower()
    if suffix == ".csv":
        row_count, malformed_count, counters = _stream_csv_to_store(
            connection=connection,
            source_path=source_path,
            artifact_id=artifact_id,
            evidence_id=evidence_id,
            source_tool=tool,
            parser=parser,
        )
    elif suffix == ".json":
        row_count, malformed_count, counters = _stream_json_to_store(
            connection=connection,
            source_path=source_path,
            artifact_id=artifact_id,
            evidence_id=evidence_id,
            source_tool=tool,
            parser=parser,
        )
    else:
        return None
    return AccountingArtifact(
        artifact_id=artifact_id,
        evidence_id=evidence_id,
        source_tool=tool,
        parser=parser,
        source_path=_relative_path(source_path, session),
        source_sha256=sha256_file(source_path),
        source_size_bytes=source_path.stat().st_size,
        row_count=row_count,
        malformed_count=malformed_count,
        partial=bool(execution.get("timed_out")),
        timed_out=bool(execution.get("timed_out")),
        table_name="event_rows",
        counts_by_source=dict(sorted(counters["source"].items())),
        counts_by_parser=dict(sorted(counters["parser"].items())),
        counts_by_data_type=dict(sorted(counters["data_type"].items())),
        counts_by_day=dict(sorted(counters["day"].items())),
    )


def _stream_csv_to_store(
    *,
    connection: sqlite3.Connection,
    source_path: Path,
    artifact_id: str,
    evidence_id: str,
    source_tool: str,
    parser: str,
) -> tuple[int, int, dict[str, Counter[str]]]:
    counters: dict[str, Counter[str]] = {
        "source": Counter(),
        "parser": Counter(),
        "data_type": Counter(),
        "day": Counter(),
    }
    malformed_count = 0
    row_count = 0
    insert_rows: list[tuple[str, str, str, str, int, str, str, str, str, str, str, str, str]] = []
    with source_path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            return 0, 1, counters
        for row_number, row in enumerate(reader, 1):
            row_count = row_number
            timestamp = _first(row, "datetime", "timestamp", "date")
            category = _first(row, "event_type", "source", "parser")
            source = _first(row, "source", "source_long")
            data_type = _first(row, "data_type")
            row_parser = _first(row, "parser")
            artifact = _first(row, "filename", "display_name", "source_long", "source")
            message = _first(row, "message", "description")
            if not timestamp:
                malformed_count += 1
            _increment(counters["source"], source)
            _increment(counters["parser"], row_parser)
            _increment(counters["data_type"], data_type)
            _increment(counters["day"], _day(timestamp))
            raw_json = json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            insert_rows.append(
                (
                    artifact_id,
                    evidence_id,
                    source_tool,
                    parser,
                    row_number,
                    hash_text(raw_json),
                    timestamp,
                    category,
                    source,
                    data_type,
                    artifact,
                    message,
                    raw_json,
                )
            )
            if len(insert_rows) >= 5000:
                _insert_rows(connection, insert_rows)
                connection.commit()
                insert_rows.clear()
    if insert_rows:
        _insert_rows(connection, insert_rows)
        connection.commit()
    return row_count, malformed_count, counters


def _stream_json_to_store(
    *,
    connection: sqlite3.Connection,
    source_path: Path,
    artifact_id: str,
    evidence_id: str,
    source_tool: str,
    parser: str,
) -> tuple[int, int, dict[str, Counter[str]]]:
    counters: dict[str, Counter[str]] = {
        "source": Counter(),
        "parser": Counter(),
        "data_type": Counter(),
        "day": Counter(),
    }
    try:
        payload = json.loads(source_path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return 0, 1, counters

    rows = _json_rows(payload)
    malformed_count = 0
    insert_rows: list[tuple[str, str, str, str, int, str, str, str, str, str, str, str, str]] = []
    data_type = source_path.suffix.lower().lstrip(".") or "json"
    category = source_path.stem
    for row_number, row in enumerate(rows, 1):
        normalized_row = row if isinstance(row, dict) else {"value": row}
        timestamp = _first(normalized_row, "datetime", "timestamp", "date", "CreateTime", "TimeCreated", "ExitTime")
        row_category = _first(normalized_row, "event_type", "source", "parser") or category
        source = _first(normalized_row, "source", "source_long") or source_tool
        row_parser = _first(normalized_row, "parser") or parser
        artifact = _first(
            normalized_row,
            "ImageFileName",
            "Name",
            "Process",
            "Owner",
            "LocalAddr",
            "ForeignAddr",
            "Cmd",
            "CommandLine",
        )
        message = _first(normalized_row, "Args", "CommandLine", "Cmd", "Description", "Details")
        _increment(counters["source"], source)
        _increment(counters["parser"], row_parser)
        _increment(counters["data_type"], data_type)
        _increment(counters["day"], _day(timestamp))
        raw_json = json.dumps(normalized_row, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        insert_rows.append(
            (
                artifact_id,
                evidence_id,
                source_tool,
                parser,
                row_number,
                hash_text(raw_json),
                timestamp,
                row_category,
                source,
                data_type,
                artifact,
                message,
                raw_json,
            )
        )
        if len(insert_rows) >= 5000:
            _insert_rows(connection, insert_rows)
            connection.commit()
            insert_rows.clear()
    if insert_rows:
        _insert_rows(connection, insert_rows)
        connection.commit()
    return len(rows), malformed_count, counters


def _json_rows(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        rows = payload.get("rows")
        if isinstance(rows, list):
            columns = payload.get("columns")
            if isinstance(columns, list):
                return [_row_from_columns(columns, row) for row in rows]
            return rows
        return [payload]
    return [{"value": payload}]


def _row_from_columns(columns: list[Any], row: Any) -> dict[str, Any]:
    if isinstance(row, dict):
        return row
    if not isinstance(row, list):
        return {"value": row}
    return {str(column): row[index] if index < len(row) else None for index, column in enumerate(columns)}


def _insert_rows(
    connection: sqlite3.Connection,
    rows: list[tuple[str, str, str, str, int, str, str, str, str, str, str, str, str]],
) -> None:
    connection.executemany(
        """
        INSERT OR REPLACE INTO event_rows (
            artifact_id,
            evidence_id,
            source_tool,
            parser,
            row_number,
            row_hash,
            timestamp,
            category,
            source,
            data_type,
            artifact,
            message,
            raw_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )


def _parser_for_tool(tool: str) -> str:
    return {
        "psort": "plaso",
        "disk_triage": "disk_triage",
        "events": "evtx",
        "pcap": "pcap",
        "memory": "volatility",
        "strings": "strings",
        "yara": "yara",
    }.get(tool, "unknown")


def _first(row: dict[str, str], *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if value:
            return str(value)
    return ""


def _increment(counter: Counter[str], value: str) -> None:
    counter[value or "unknown"] += 1


def _day(timestamp: str) -> str:
    if len(timestamp) >= 10 and timestamp[4:5] == "-" and timestamp[7:8] == "-":
        return timestamp[:10]
    return "unknown"


def _dict_value(value: dict[str, Any], key: str) -> dict[str, Any]:
    item = value.get(key)
    return item if isinstance(item, dict) else {}


def _relative_path(path: Path, session: CaseSession) -> str:
    try:
        return str(path.resolve().relative_to(session.session_root.resolve())).replace("\\", "/")
    except ValueError:
        return str(path)
