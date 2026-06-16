from __future__ import annotations

import json
from typing import Any

from blitz_dfir.core.models import EvidenceRecord, SignalWarning
from blitz_dfir.parsers.common import make_record
from blitz_dfir.parsers.models import ParsedRecord, ParserResult
from blitz_dfir.parsers.parser_validation import (
    build_parser_result,
    malformed_record_warning,
    parser_degradation_warning,
    validate_parser_compatibility,
)


def parse_volatility_json(text: str, evidence: EvidenceRecord, *, plugin: str = "volatility") -> ParserResult:
    validate_parser_compatibility("volatility", evidence)
    warnings: list[SignalWarning] = []
    records: list[ParsedRecord] = []
    malformed = 0
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        warnings.append(parser_degradation_warning(artifact=evidence.evidence_id, reason="invalid JSON"))
        return build_parser_result(
            parser="volatility",
            source_tool="volatility",
            evidence=evidence,
            records=[],
            warnings=warnings,
            malformed_count=1,
        )
    items = _items(payload)
    for index, item in enumerate(items, 1):
        if not isinstance(item, dict):
            malformed += 1
            warnings.append(
                malformed_record_warning(
                    artifact=evidence.evidence_id,
                    reason="row is not an object",
                    index=index,
                )
            )
            continue
        record_warnings: list[SignalWarning] = []
        records.append(
            make_record(
                parser="volatility",
                source_tool="volatility",
                evidence=evidence,
                timestamp=_timestamp_for_item(item),
                event_type=plugin,
                artifact=_artifact_for_item(item, plugin=plugin),
                message=_message_for_item(item, plugin=plugin),
                raw_reference=_raw_reference_for_item(item),
                fields=item,
                warnings=record_warnings,
            )
        )
        warnings.extend(record_warnings)
    return build_parser_result(
        parser="volatility",
        source_tool="volatility",
        evidence=evidence,
        records=records,
        warnings=warnings,
        malformed_count=malformed,
    )


def _items(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        tree_grid = payload.get("TreeGrid")
        if isinstance(tree_grid, dict):
            columns = _column_names(tree_grid.get("columns")) or _column_names(payload.get("columns"))
            for key in ("rows", "data", "items", "children", "__children"):
                value = tree_grid.get(key)
                if isinstance(value, list):
                    return _rows_to_items(value, columns)
        if isinstance(tree_grid, list):
            return _rows_to_items(tree_grid, _column_names(payload.get("columns")))
        columns = _column_names(payload.get("columns"))
        for key in ("rows", "data", "TreeGrid", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                return _rows_to_items(value, columns)
    return []


def _column_names(columns: Any) -> list[str]:
    if not isinstance(columns, list):
        return []
    names: list[str] = []
    for column in columns:
        if isinstance(column, str):
            name = column
        elif isinstance(column, dict):
            name = str(column.get("name") or column.get("title") or "")
        else:
            name = ""
        name = name.strip()
        if name:
            names.append(name)
    return names


def _rows_to_items(rows: list[Any], columns: list[str]) -> list[Any]:
    items: list[Any] = []
    for row in rows:
        if isinstance(row, dict):
            child_rows = _child_rows(row)
            item = {key: value for key, value in row.items() if key not in {"children", "__children"}}
            items.append(item)
            if child_rows:
                items.extend(_rows_to_items(child_rows, columns))
            continue
        if isinstance(row, list | tuple) and columns:
            values = list(row)
            child_rows = values.pop() if len(values) > len(columns) and isinstance(values[-1], list) else None
            items.append(dict(zip(columns, values)))
            if child_rows:
                items.extend(_rows_to_items(child_rows, columns))
            continue
        items.append(row)
    return items


def _child_rows(row: dict[str, Any]) -> list[Any]:
    for key in ("children", "__children"):
        value = row.get(key)
        if isinstance(value, list):
            return value
    return []


def _timestamp_for_item(item: dict[str, Any]) -> Any:
    for key in ("CreateTime", "Create Time", "Created", "Time"):
        value = item.get(key)
        if value not in (None, ""):
            return value
    return ""


def _artifact_for_item(item: dict[str, Any], *, plugin: str) -> Any:
    if plugin == "windows.netscan":
        local = _address_port(item.get("LocalAddr"), item.get("LocalPort"))
        remote = _address_port(item.get("ForeignAddr"), item.get("ForeignPort"))
        if local or remote:
            return f"{local or '?'}->{remote or '?'}"
    for key in ("ImageFileName", "Name", "Process", "Owner", "PID"):
        value = item.get(key)
        if value not in (None, ""):
            return value
    return "memory_artifact"


def _message_for_item(item: dict[str, Any], *, plugin: str) -> str:
    if plugin == "windows.netscan":
        proto = item.get("Proto") or item.get("Protocol") or ""
        state = item.get("State") or ""
        owner = item.get("Owner") or item.get("Process") or ""
        return " ".join(str(value) for value in (proto, state, owner) if value not in (None, ""))
    if plugin == "windows.malfind":
        return " ".join(
            str(value)
            for value in (
                item.get("Process"),
                item.get("Protection"),
                item.get("Tag"),
                item.get("File output"),
            )
            if value not in (None, "")
        )
    for key in ("CommandLine", "Cmd", "Args", "Arguments", "Path"):
        value = item.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def _raw_reference_for_item(item: dict[str, Any]) -> Any:
    for key in ("Offset", "Offset(V)", "Offset(P)", "Virtual", "Start VPN", "PID"):
        value = item.get(key)
        if value not in (None, ""):
            return value
    return None


def _address_port(address: Any, port: Any) -> str:
    if address in (None, ""):
        return ""
    if port in (None, ""):
        return str(address)
    return f"{address}:{port}"
