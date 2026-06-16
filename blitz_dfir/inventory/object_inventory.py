from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from blitz_dfir.core.models import EvidenceManifest, NormalizedEvent
from blitz_dfir.inventory.models import (
    EvidenceInventoryReport,
    ObjectInventoryItem,
    ObjectInventoryReport,
)

DEFAULT_MAX_OBJECTS_PER_TYPE = 2_000
MAX_EVIDENCE_IDS_PER_OBJECT = 8
MAX_EVENT_IDS_PER_OBJECT = 5
MAX_OBJECT_VALUE_CHARS = 512

FIELD_OBJECT_TYPES = {
    "user": (
        "user",
        "username",
        "accountname",
        "targetusername",
        "subjectusername",
        "domainuser",
        "user_name",
    ),
    "process_image": (
        "process",
        "processname",
        "newprocessname",
        "image",
        "imagepath",
        "application",
    ),
    "process_id": (
        "pid",
        "ppid",
        "processid",
        "newprocessid",
        "parentprocessid",
    ),
    "file_path": (
        "path",
        "filepath",
        "file_name",
        "filename",
        "targetfilename",
        "objectname",
        "target",
    ),
    "command_line": ("commandline",),
    "hash": ("md5", "sha1", "sha256"),
    "network_ip": ("src_ip", "dst_ip", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst"),
    "network_port": ("src_port", "dst_port", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport"),
    "domain": ("dns_query", "http_host", "tls_sni", "dns.qry.name"),
    "url_path": ("url", "uri", "http_uri", "http.request.uri"),
    "registry_key": ("registry_key", "keypath", "key_path", "registry_path"),
}

LOLBIN_TERMS = (
    "powershell",
    "cmd.exe",
    "rundll32",
    "regsvr32",
    "mshta",
    "wscript",
    "cscript",
    "certutil",
    "bitsadmin",
    "wmic",
    "schtasks",
)

PERSISTENCE_TERMS = (
    "currentversion/run",
    "currentversion\\run",
    "currentversion/runonce",
    "currentversion\\runonce",
    "services/",
    "services\\",
    "scheduled task",
    "startup",
    "winlogon",
)

USER_WRITABLE_TERMS = (
    "/users/",
    "\\users\\",
    "/appdata/",
    "\\appdata\\",
    "/temp/",
    "\\temp\\",
    "/programdata/",
    "\\programdata\\",
)

IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]{2,}$", re.I)
HASH_RE = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", re.I)
IP_TOKEN_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_TOKEN_RE = re.compile(r"\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b", re.I)
WINDOWS_PATH_RE = re.compile(r"\b[A-Za-z]:[\\/][^\s\"'<>|]+")
REGISTRY_PATH_RE = re.compile(
    r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|"
    r"HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)[\\/][^\s\"']+",
    re.I,
)
DOMAIN_TOKEN_RE = re.compile(r"\b[a-z0-9][a-z0-9.-]{1,253}\.[a-z]{2,24}\b", re.I)


@dataclass
class _ObjectStats:
    event_count: int = 0
    first_seen_utc: str | None = None
    last_seen_utc: str | None = None
    evidence_ids: set[str] = field(default_factory=set)
    sample_event_ids: list[str] = field(default_factory=list)
    risk_tags: set[str] = field(default_factory=set)

    def update(
        self,
        *,
        timestamp_utc: str,
        evidence_id: str,
        event_id: str,
        risk_tags: Iterable[str],
    ) -> None:
        self.event_count += 1
        if self.first_seen_utc is None or timestamp_utc < self.first_seen_utc:
            self.first_seen_utc = timestamp_utc
        if self.last_seen_utc is None or timestamp_utc > self.last_seen_utc:
            self.last_seen_utc = timestamp_utc
        if len(self.evidence_ids) < MAX_EVIDENCE_IDS_PER_OBJECT:
            self.evidence_ids.add(evidence_id)
        if len(self.sample_event_ids) < MAX_EVENT_IDS_PER_OBJECT and event_id not in self.sample_event_ids:
            self.sample_event_ids.append(event_id)
        self.risk_tags.update(risk_tags)


@dataclass
class _InventoryAccumulator:
    max_objects_per_type: int
    objects: dict[str, dict[str, _ObjectStats]] = field(default_factory=lambda: defaultdict(dict))
    object_mention_counts: Counter[str] = field(default_factory=Counter)
    omitted_object_mentions_by_type: Counter[str] = field(default_factory=Counter)
    event_category_counts: Counter[str] = field(default_factory=Counter)
    evidence_event_counts: Counter[str] = field(default_factory=Counter)
    normalized_event_count: int = 0

    def add_event(
        self,
        *,
        event_id: str,
        timestamp_utc: str,
        category: str,
        artifact: str,
        message: str,
        evidence_id: str,
        fields: Mapping[str, str],
    ) -> None:
        self.normalized_event_count += 1
        self.event_category_counts[category] += 1
        self.evidence_event_counts[evidence_id] += 1
        seen_in_event: set[tuple[str, str]] = set()
        for object_type, value in _iter_event_objects(
            category=category,
            artifact=artifact,
            message=message,
            fields=fields,
        ):
            key = (object_type, value)
            if key in seen_in_event:
                continue
            seen_in_event.add(key)
            self.object_mention_counts[object_type] += 1
            bucket = self.objects[object_type]
            if value not in bucket:
                if len(bucket) >= self.max_objects_per_type:
                    self.omitted_object_mentions_by_type[object_type] += 1
                    continue
                bucket[value] = _ObjectStats()
            bucket[value].update(
                timestamp_utc=timestamp_utc,
                evidence_id=evidence_id,
                event_id=event_id,
                risk_tags=_risk_tags(object_type, value, category),
            )


def build_object_inventory_report(
    *,
    case_id: str,
    manifest: EvidenceManifest,
    events: tuple[NormalizedEvent, ...],
    store_path: Path | None = None,
    evidence_inventory: EvidenceInventoryReport | None = None,
    max_objects_per_type: int = DEFAULT_MAX_OBJECTS_PER_TYPE,
) -> ObjectInventoryReport:
    accumulator = _InventoryAccumulator(max_objects_per_type=max_objects_per_type)
    source = "in_memory_normalized_events"
    if store_path is not None and _scan_sqlite_normalized_events(store_path, accumulator):
        source = "sqlite_normalized_events"
    else:
        _scan_in_memory_events(events, accumulator)

    manifest_evidence_ids = tuple(evidence.evidence_id for evidence in manifest.evidence)
    evidence_without_events = tuple(
        evidence_id for evidence_id in manifest_evidence_ids if evidence_id not in accumulator.evidence_event_counts
    )
    unchecked = _unchecked_or_unsupported_evidence(evidence_inventory)
    items = _report_items(accumulator)
    object_type_counts = {object_type: len(values) for object_type, values in sorted(accumulator.objects.items())}
    notes = _notes(accumulator=accumulator, evidence_without_events=evidence_without_events, unchecked=unchecked)
    return ObjectInventoryReport(
        case_id=case_id,
        source=source,
        normalized_event_count=accumulator.normalized_event_count,
        object_count=len(items),
        object_mention_count=sum(accumulator.object_mention_counts.values()),
        object_type_counts=object_type_counts,
        object_mention_counts=dict(sorted(accumulator.object_mention_counts.items())),
        event_category_counts=dict(sorted(accumulator.event_category_counts.items())),
        evidence_event_counts=dict(sorted(accumulator.evidence_event_counts.items())),
        evidence_without_normalized_events=evidence_without_events,
        unchecked_or_unsupported_evidence=unchecked,
        omitted_object_mentions_by_type=dict(sorted(accumulator.omitted_object_mentions_by_type.items())),
        max_objects_per_type=max_objects_per_type,
        items=items,
        notes=notes,
    )


def _scan_sqlite_normalized_events(store_path: Path, accumulator: _InventoryAccumulator) -> bool:
    if not store_path.exists():
        return False
    connection = sqlite3.connect(store_path)
    connection.row_factory = sqlite3.Row
    try:
        table = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'normalized_events'"
        ).fetchone()
        if table is None:
            return False
        cursor = connection.execute(
            """
            SELECT event_id, timestamp_utc, category, artifact, message, evidence_id, normalized_fields_json
            FROM normalized_events
            ORDER BY row_number
            """
        )
        while True:
            rows = cursor.fetchmany(5000)
            if not rows:
                break
            for row in rows:
                accumulator.add_event(
                    event_id=str(row["event_id"]),
                    timestamp_utc=str(row["timestamp_utc"]),
                    category=str(row["category"]),
                    artifact=str(row["artifact"]),
                    message=str(row["message"]),
                    evidence_id=str(row["evidence_id"]),
                    fields=_json_fields(str(row["normalized_fields_json"])),
                )
    finally:
        connection.close()
    return True


def _scan_in_memory_events(events: tuple[NormalizedEvent, ...], accumulator: _InventoryAccumulator) -> None:
    for event in events:
        accumulator.add_event(
            event_id=event.event_id,
            timestamp_utc=event.timestamp_utc,
            category=event.category,
            artifact=event.artifact,
            message=event.message,
            evidence_id=event.evidence_id,
            fields=event.normalized_fields,
        )


def _json_fields(value: str) -> dict[str, str]:
    try:
        payload = json.loads(value)
    except json.JSONDecodeError:
        return {}
    if not isinstance(payload, dict):
        return {}
    return {str(key): str(item) for key, item in payload.items() if item is not None}


def _iter_event_objects(
    *,
    category: str,
    artifact: str,
    message: str,
    fields: Mapping[str, str],
) -> Iterator[tuple[str, str]]:
    normalized_fields = {str(key).lower(): str(value).strip() for key, value in fields.items()}
    for object_type, field_names in FIELD_OBJECT_TYPES.items():
        for field_name in field_names:
            value = normalized_fields.get(field_name.lower(), "")
            if not value:
                continue
            if object_type == "process_id":
                yield object_type, _object_value(f"{field_name}:{value}")
            elif object_type == "hash" and HASH_RE.match(value):
                yield object_type, _object_value(f"{field_name}:{value.lower()}")
            else:
                yield object_type, _object_value(value)
    yield from _objects_from_artifact(category=category, artifact=artifact)
    yield from _objects_from_text(message)


def _objects_from_artifact(*, category: str, artifact: str) -> Iterator[tuple[str, str]]:
    value = artifact.strip()
    if not value:
        return
    if "->" in value:
        for part in value.split("->"):
            candidate = part.strip()
            if _looks_like_ip(candidate):
                yield "network_ip", _object_value(candidate)
        return
    lowered = value.lower()
    if _looks_like_registry(lowered):
        yield "registry_key", _object_value(value)
    if _looks_like_ip(value):
        yield "network_ip", _object_value(value)
    if _looks_like_path(value):
        yield "file_path", _object_value(value)
    if "process" in category.lower() or lowered.endswith((".exe", ".dll", ".ps1", ".bat", ".cmd")):
        yield "process_image", _object_value(value)


def _objects_from_text(message: str) -> Iterator[tuple[str, str]]:
    text = str(message or "")
    if not text:
        return
    seen: set[tuple[str, str]] = set()
    for path in WINDOWS_PATH_RE.findall(text):
        item = ("file_path", _object_value(path.rstrip(".,;)]}")))
        if item not in seen:
            seen.add(item)
            yield item
    for registry_path in REGISTRY_PATH_RE.findall(text):
        item = ("registry_key", _object_value(registry_path.rstrip(".,;)]}")))
        if item not in seen:
            seen.add(item)
            yield item
    for ip in IP_TOKEN_RE.findall(text):
        item = ("network_ip", _object_value(ip))
        if item not in seen:
            seen.add(item)
            yield item
    for digest in HASH_TOKEN_RE.findall(text):
        item = ("hash", _object_value(digest.lower()))
        if item not in seen:
            seen.add(item)
            yield item
    for domain in DOMAIN_TOKEN_RE.findall(text):
        cleaned = domain.lower().rstrip(".,;)]}")
        if cleaned.endswith((".exe", ".dll", ".ps1", ".bat", ".cmd", ".log", ".evtx")):
            continue
        item = ("domain", _object_value(cleaned))
        if item not in seen:
            seen.add(item)
            yield item
    if any(term in text.lower() for term in LOLBIN_TERMS):
        yield "command_line", _object_value(text)


def _object_value(value: str) -> str:
    text = " ".join(str(value).strip().split())
    return text[:MAX_OBJECT_VALUE_CHARS]


def _looks_like_path(value: str) -> bool:
    return "/" in value or "\\" in value or re.match(r"^[a-zA-Z]:", value) is not None


def _looks_like_ip(value: str) -> bool:
    return IP_RE.match(value.strip()) is not None


def _looks_like_registry(value: str) -> bool:
    lowered = value.lower()
    return lowered.startswith(("hkey_", "hkcu", "hklm")) or "currentversion\\run" in lowered


def _risk_tags(object_type: str, value: str, category: str) -> tuple[str, ...]:
    haystack = f"{object_type} {value} {category}".lower()
    tags: list[str] = []
    if any(term in haystack for term in LOLBIN_TERMS):
        tags.append("living_off_the_land")
    if any(term in haystack for term in PERSISTENCE_TERMS):
        tags.append("persistence_related")
    if any(term in haystack for term in USER_WRITABLE_TERMS):
        tags.append("user_writable_location")
    if object_type in {"network_ip", "domain", "url_path"}:
        tags.append("network_observable")
    if object_type == "hash":
        tags.append("file_hash")
    return tuple(dict.fromkeys(tags))


def _report_items(accumulator: _InventoryAccumulator) -> tuple[ObjectInventoryItem, ...]:
    items: list[ObjectInventoryItem] = []
    for object_type in sorted(accumulator.objects):
        values = accumulator.objects[object_type]
        for value, stats in sorted(values.items(), key=lambda item: (-item[1].event_count, item[0])):
            items.append(
                ObjectInventoryItem(
                    object_type=object_type,
                    value=value,
                    event_count=stats.event_count,
                    first_seen_utc=stats.first_seen_utc,
                    last_seen_utc=stats.last_seen_utc,
                    evidence_ids=tuple(sorted(stats.evidence_ids)),
                    sample_event_ids=tuple(stats.sample_event_ids),
                    risk_tags=tuple(sorted(stats.risk_tags)),
                )
            )
    return tuple(items)


def _unchecked_or_unsupported_evidence(
    evidence_inventory: EvidenceInventoryReport | None,
) -> tuple[str, ...]:
    if evidence_inventory is None:
        return ()
    return tuple(
        item.evidence_id
        for item in evidence_inventory.items
        if item.recommended_tool == "unsupported" or item.tool_status not in {"AVAILABLE", "NOT_REQUIRED"}
    )


def _notes(
    *,
    accumulator: _InventoryAccumulator,
    evidence_without_events: tuple[str, ...],
    unchecked: tuple[str, ...],
) -> tuple[str, ...]:
    notes: list[str] = []
    if accumulator.omitted_object_mentions_by_type:
        notes.append("object listing is bounded per type; omitted mention counts are reported separately")
    if evidence_without_events:
        notes.append("some manifest evidence produced no normalized events")
    if unchecked:
        notes.append("some evidence was unsupported or assigned to an unavailable tool")
    return tuple(notes)
