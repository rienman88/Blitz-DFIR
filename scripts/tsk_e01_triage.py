#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PARTITION_RE = re.compile(r"^\s*(?P<slot>\d+):\s+(?P<start>\d+)\s+(?P<end>\d+)\s+(?P<length>\d+)\s+(?P<description>.+?)\s*$")
INTERESTING_PARTITION_TOKENS = ("ntfs", "fat", "exfat", "basic data", "linux", "ext")

HIGH_VALUE_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"/windows/system32/winevt/logs/.*\.evtx$", "windows_event_log"),
    (r"/windows/prefetch/.*\.pf$", "windows_prefetch"),
    (r"/windows/appcompat/programs/amcache\.hve$", "amcache"),
    (r"/windows/system32/sru/srudb\.dat$", "sru_database"),
    (r"/windows/system32/config/(sam|system|software|security|default)$", "registry_hive"),
    (r"/users/[^/]+/ntuser\.dat$", "user_registry_hive"),
    (r"/users/[^/]+/appdata/local/microsoft/windows/usrclass\.dat$", "user_registry_hive"),
    (r"/windows/system32/tasks/.+", "scheduled_task"),
    (r"/programdata/microsoft/windows/start menu/programs/startup/.+", "startup_item"),
    (r"/users/[^/]+/appdata/roaming/microsoft/windows/start menu/programs/startup/.+", "startup_item"),
    (r"/users/[^/]+/appdata/roaming/microsoft/windows/powershell/psreadline/consolehost_history\.txt$", "powershell_history"),
    (r"/users/[^/]+/appdata/roaming/microsoft/windows/recent/.+\.lnk$", "lnk_shortcut"),
    (r"/users/[^/]+/appdata/local/google/chrome/user data/.+", "browser_artifact"),
    (r"/users/[^/]+/appdata/roaming/mozilla/firefox/profiles/.+", "browser_artifact"),
)

SUSPICIOUS_PATH_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"/appdata/(local|roaming)/temp/.+\.(exe|dll|ps1|vbs|js|bat|cmd)$", "user_temp_executable"),
    (r"/users/[^/]+/downloads/.+\.(exe|dll|ps1|vbs|js|bat|cmd)$", "downloaded_executable_or_script"),
    (r"/programdata/.+\.(exe|dll|ps1|vbs|js|bat|cmd)$", "programdata_executable_or_script"),
    (r"/windows/tasks/.+", "legacy_task"),
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Bounded Sleuth Kit triage for E01/DD evidence.")
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--max-partitions", type=int, default=8)
    parser.add_argument("--max-entries", type=int, default=3_000_000)
    parser.add_argument("--max-seconds-per-partition", type=int, default=1800)
    parser.add_argument("--entries-output")
    parser.add_argument("--summary-entry-limit", type=int, default=1000)
    args = parser.parse_args()

    evidence = Path(args.evidence)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    entries_output = Path(args.entries_output) if args.entries_output else output.with_name(f"{output.stem}.entries.jsonl")
    entries_output.parent.mkdir(parents=True, exist_ok=True)
    summary_entry_limit = max(args.summary_entry_limit, 0)

    payload: dict[str, Any] = {
        "schema_version": "blitz-disk-triage.v1",
        "evidence_path": str(evidence),
        "strategy": "sleuthkit_partition_fls_bounded",
        "limits": {
            "max_partitions": args.max_partitions,
            "max_entries": args.max_entries,
            "max_seconds_per_partition": args.max_seconds_per_partition,
            "summary_entry_limit": summary_entry_limit,
        },
        "entries_output": entries_output.name,
        "entries_output_path": str(entries_output),
        "entries_output_format": "jsonl",
        "tool_paths": {
            "mmls": shutil.which("mmls"),
            "fls": shutil.which("fls"),
        },
        "warnings": [],
        "partitions": [],
    }

    if payload["tool_paths"]["fls"] is None:
        payload["warnings"].append({"severity": "CRITICAL", "reason": "fls executable not found"})
        output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return 1

    partitions = _partitions(evidence, payload)
    selected = _select_partitions(partitions, args.max_partitions)
    if not selected:
        selected = [{"slot": "raw", "start": 0, "end": None, "length": None, "description": "raw filesystem fallback"}]
        payload["warnings"].append({"severity": "HIGH", "reason": "mmls produced no selected partitions; tried raw filesystem fallback"})

    remaining = max(args.max_entries, 1)
    with entries_output.open("w", encoding="utf-8") as entries_handle:
        for partition in selected:
            partition_result, used = _enumerate_partition(
                evidence=evidence,
                partition=partition,
                max_entries=remaining,
                timeout_seconds=args.max_seconds_per_partition,
                entries_handle=entries_handle,
                summary_entry_limit=summary_entry_limit,
            )
            payload["partitions"].append(partition_result)
            remaining -= used
            if remaining <= 0:
                payload["warnings"].append(
                    {
                        "severity": "HIGH",
                        "reason": "global disk triage entry cap reached",
                        "processed_entries": args.max_entries,
                        "configured_max_entries": args.max_entries,
                    }
                )
                break

    payload["entry_count"] = sum(int(partition.get("entry_count") or 0) for partition in payload["partitions"])
    payload["high_value_entry_count"] = sum(
        int(partition.get("high_value_entry_count") or 0) for partition in payload["partitions"]
    )
    payload["truncated"] = any(bool(partition.get("truncated")) for partition in payload["partitions"])
    payload["entries_omitted_from_summary"] = max(
        payload["entry_count"] - sum(len(partition.get("entries", ())) for partition in payload["partitions"]),
        0,
    )
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0 if payload["entry_count"] else 1


def _partitions(evidence: Path, payload: dict[str, Any]) -> list[dict[str, Any]]:
    if payload["tool_paths"]["mmls"] is None:
        payload["warnings"].append({"severity": "HIGH", "reason": "mmls executable not found; using raw filesystem fallback"})
        return []
    completed = subprocess.run(
        ["mmls", str(evidence)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        errors="replace",
        timeout=300,
        check=False,
    )
    payload["mmls"] = {
        "exit_code": completed.returncode,
        "stderr_tail": completed.stderr[-4000:],
    }
    partitions: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        match = PARTITION_RE.match(line)
        if not match:
            continue
        item = {
            "slot": match.group("slot"),
            "start": int(match.group("start")),
            "end": int(match.group("end")),
            "length": int(match.group("length")),
            "description": match.group("description").strip(),
        }
        partitions.append(item)
    return partitions


def _select_partitions(partitions: list[dict[str, Any]], max_partitions: int) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for partition in partitions:
        description = str(partition["description"]).lower()
        if "unallocated" in description or "metadata" in description:
            continue
        if any(token in description for token in INTERESTING_PARTITION_TOKENS):
            selected.append(partition)
    return selected[: max(max_partitions, 1)]


def _enumerate_partition(
    *,
    evidence: Path,
    partition: dict[str, Any],
    max_entries: int,
    timeout_seconds: int,
    entries_handle: Any,
    summary_entry_limit: int,
) -> tuple[dict[str, Any], int]:
    command = ["fls", "-r", "-m", "/", "-o", str(partition["start"]), str(evidence)]
    result: dict[str, Any] = {
        "slot": partition.get("slot"),
        "start": partition.get("start"),
        "description": partition.get("description"),
        "command": command[:-1] + ["[evidence]"],
        "entries": [],
        "entries_sample_count": 0,
        "entries_omitted_from_summary": 0,
        "warnings": [],
        "truncated": False,
    }
    used = 0
    high_value_used = 0
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
    )
    assert process.stdout is not None
    try:
        for line in process.stdout:
            entry = _parse_bodyfile_line(line, partition_start=int(partition["start"]))
            if entry is None:
                continue
            if entry.get("artifact_family"):
                high_value_used += 1
            _write_entry_jsonl(entries_handle, entry=entry, partition=partition)
            if len(result["entries"]) < summary_entry_limit:
                result["entries"].append(entry)
            used += 1
            if used >= max_entries:
                result["truncated"] = True
                process.kill()
                break
        try:
            stderr = process.communicate(timeout=timeout_seconds)[1]
        except subprocess.TimeoutExpired:
            process.kill()
            stderr = process.communicate()[1]
            result["warnings"].append({"severity": "HIGH", "reason": "fls timed out and was stopped"})
    finally:
        if process.poll() is None:
            process.kill()
    result["exit_code"] = process.returncode
    result["stderr_tail"] = (stderr or "")[-4000:]
    if process.returncode not in (0, -9, None):
        result["warnings"].append({"severity": "HIGH", "reason": f"fls exited {process.returncode}"})
    result["entry_count"] = used
    result["high_value_entry_count"] = high_value_used
    result["entries_sample_count"] = len(result["entries"])
    result["entries_omitted_from_summary"] = max(used - len(result["entries"]), 0)
    return result, used


def _write_entry_jsonl(entries_handle: Any, *, entry: dict[str, Any], partition: dict[str, Any]) -> None:
    record = {
        "partition": {
            "slot": partition.get("slot"),
            "start": partition.get("start"),
            "description": partition.get("description"),
        },
        "entry": entry,
    }
    entries_handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")


def _parse_bodyfile_line(line: str, *, partition_start: int) -> dict[str, Any] | None:
    parts = line.rstrip("\n").split("|")
    if len(parts) < 11:
        return None
    name = "|".join(parts[1:-9]).strip()
    inode, mode, uid, gid, size, atime, mtime, ctime, crtime = parts[-9:]
    normalized_path = _normalize_path(name)
    family = _artifact_family(normalized_path)
    risk_tags = _risk_tags(normalized_path)
    return {
        "partition_start": partition_start,
        "path": normalized_path,
        "inode": inode,
        "mode": mode,
        "uid": uid,
        "gid": gid,
        "size": _int_or_none(size),
        "atime": _timestamp(atime),
        "mtime": _timestamp(mtime),
        "ctime": _timestamp(ctime),
        "crtime": _timestamp(crtime),
        "artifact_family": family,
        "risk_tags": risk_tags,
    }


def _normalize_path(value: str) -> str:
    path = value.replace("\\", "/")
    path = re.sub(r"/+", "/", path)
    if not path.startswith("/"):
        path = "/" + path
    return path


def _artifact_family(path: str) -> str:
    lowered = path.lower()
    for pattern, family in HIGH_VALUE_PATTERNS:
        if re.search(pattern, lowered):
            return family
    return ""


def _risk_tags(path: str) -> list[str]:
    lowered = path.lower()
    tags: list[str] = []
    for pattern, tag in SUSPICIOUS_PATH_PATTERNS:
        if re.search(pattern, lowered):
            tags.append(tag)
    return tags


def _timestamp(value: str) -> str | None:
    parsed = _int_or_none(value)
    if not parsed or parsed < 0:
        return None
    try:
        return datetime.fromtimestamp(parsed, tz=UTC).isoformat().replace("+00:00", "Z")
    except (OSError, OverflowError, ValueError):
        return None


def _int_or_none(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


if __name__ == "__main__":
    raise SystemExit(main())
