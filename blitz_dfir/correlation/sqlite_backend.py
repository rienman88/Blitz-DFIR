from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from blitz_dfir.core.models import EvidenceCategory, NormalizedEvent, RawReference, SignalWarning, TrustTier
from blitz_dfir.correlation.attack_chain import infer_attack_stages
from blitz_dfir.correlation.confidence import assess_confidence
from blitz_dfir.correlation.models import AttackStage, CorrelatedFinding, EvidenceAnchor, stable_correlation_id

PERSISTENCE_SQL_TERMS = (
    "currentversion/run",
    "currentversion\\run",
    "currentversion/runonce",
    "currentversion\\runonce",
    "services/",
    "services\\",
    "scheduled task",
    "schtasks",
    "startup",
    "winlogon",
)

LOLBIN_SQL_TERMS = (
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

HIGH_SIGNAL_SQL_TERMS = (
    "encodedcommand",
    "frombase64string",
    "downloadstring",
    "invoke-expression",
    "mimikatz",
    "sekurlsa",
    "credential",
    "dump",
)

AUTH_SQL_TERMS = (
    "privileged_logon",
    "explicit_credential_logon",
    "authentication_failure",
)

USER_WRITABLE_SQL_TERMS = (
    "/users/",
    "\\users\\",
    "/appdata/",
    "\\appdata\\",
    "/temp/",
    "\\temp\\",
    "/programdata/",
    "\\programdata\\",
)

MEMORY_PROCESS_CATEGORIES = (
    "memory_process",
    "memory_process_tree",
    "memory_process_scan",
)

MEMORY_HIGH_SIGNAL_CATEGORIES = (
    "memory_injection_candidate",
)

MEMORY_PROCESS_SQL_TERMS = (
    "powershell.exe",
    "powershell",
    "cmd.exe",
    "rundll32.exe",
    "rundll32",
    "regsvr32.exe",
    "regsvr32",
    "mshta.exe",
    "mshta",
    "wscript.exe",
    "cscript.exe",
    "wmic.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "psexec",
    "procdump",
    "mimikatz",
)


@dataclass(frozen=True)
class SQLiteCorrelationResult:
    findings: tuple[CorrelatedFinding, ...]
    support_events: tuple[NormalizedEvent, ...]
    stages: tuple[AttackStage, ...]
    rows_scanned: int
    candidate_count: int
    backend: str = "sqlite"


def correlate_normalized_events_sqlite(
    store_path: Path,
    *,
    finding_limit: int = 500,
    support_event_limit: int = 5000,
) -> SQLiteCorrelationResult:
    connection = sqlite3.connect(store_path)
    connection.row_factory = sqlite3.Row
    try:
        _require_normalized_events(connection)
        _initialize_candidate_store(connection)
        connection.execute("DELETE FROM sql_correlation_candidates")
        rows_scanned = _count_rows(connection)
        candidate_count = _count_sql_candidates(connection)
        findings = _build_sql_findings(
            connection,
            rows_scanned=rows_scanned,
            candidate_count=candidate_count,
            finding_limit=finding_limit,
        )
        support_event_ids = _support_event_ids(findings, support_event_limit)
        support_events = _load_events_by_id(connection, support_event_ids)
        _write_candidate_rows(connection, findings)
        connection.commit()
    finally:
        connection.close()

    return SQLiteCorrelationResult(
        findings=findings,
        support_events=support_events,
        stages=infer_attack_stages(support_events, findings=findings),
        rows_scanned=rows_scanned,
        candidate_count=candidate_count,
    )


def _require_normalized_events(connection: sqlite3.Connection) -> None:
    table = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'normalized_events'"
    ).fetchone()
    if table is None:
        raise ValueError("full SQL correlation requires normalized_events table")


def _initialize_candidate_store(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS sql_correlation_candidates (
            finding_id TEXT PRIMARY KEY,
            finding_type TEXT NOT NULL,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            triage_score REAL NOT NULL,
            event_count INTEGER NOT NULL,
            first_seen_utc TEXT NOT NULL,
            last_seen_utc TEXT NOT NULL,
            suspicion_reasons_json TEXT NOT NULL,
            supporting_event_ids_json TEXT NOT NULL
        )
        """
    )


def _count_rows(connection: sqlite3.Connection) -> int:
    row = connection.execute("SELECT COUNT(*) FROM normalized_events").fetchone()
    return int(row[0]) if row else 0


def _count_sql_candidates(connection: sqlite3.Connection) -> int:
    row = connection.execute(f"SELECT COUNT(*) FROM ({_scored_events_sql()}) WHERE triage_score >= 0.5").fetchone()
    return int(row[0]) if row else 0


def _build_sql_findings(
    connection: sqlite3.Connection,
    *,
    rows_scanned: int,
    candidate_count: int,
    finding_limit: int,
) -> tuple[CorrelatedFinding, ...]:
    findings: list[CorrelatedFinding] = []
    findings.extend(_build_campaign_findings(connection, rows_scanned=rows_scanned))
    remaining = max(finding_limit - len(findings), 0)
    if remaining:
        rows = connection.execute(
            f"""
            SELECT *
            FROM ({_scored_events_sql()})
            WHERE triage_score >= 0.5
            ORDER BY triage_score DESC, timestamp_utc ASC, event_id ASC
            LIMIT ?
            """,
            (remaining,),
        ).fetchall()
        for row in rows:
            findings.append(_finding_from_scored_row(row, rows_scanned=rows_scanned, candidate_count=candidate_count))
    return tuple(_dedupe_findings(findings)[:finding_limit])


def _build_campaign_findings(
    connection: sqlite3.Connection,
    *,
    rows_scanned: int,
) -> list[CorrelatedFinding]:
    findings: list[CorrelatedFinding] = []
    for label, category_like, minimum_count, stage in (
        ("Long-horizon authentication activity", "%auth%", 25, "initial_access_or_lateral_movement"),
        ("Long-horizon credential activity", "%credential%", 10, "privilege_or_credential_use"),
        ("Long-horizon persistence activity", "%persist%", 1, "persistence"),
    ):
        row = connection.execute(
            """
            SELECT COUNT(*) AS count,
                   MIN(timestamp_utc) AS first_seen,
                   MAX(timestamp_utc) AS last_seen,
                   MIN(event_id) AS event_id,
                   MIN(evidence_id) AS evidence_id,
                   MIN(source_tool) AS source_tool,
                   MIN(source_parser) AS source_parser,
                   MIN(raw_reference_json) AS raw_reference_json,
                   MIN(trust_level) AS trust_level
            FROM normalized_events
            WHERE LOWER(category) LIKE ?
               OR LOWER(message) LIKE ?
               OR LOWER(normalized_fields_json) LIKE ?
            """,
            (category_like, category_like, category_like),
        ).fetchone()
        if row is None or int(row["count"] or 0) < minimum_count or not row["event_id"]:
            continue
        anchor = _anchor_from_row(row)
        confidence = assess_confidence((anchor,))
        findings.append(
            CorrelatedFinding(
                finding_id=stable_correlation_id(
                    "FIND",
                    "sql_campaign",
                    label,
                    str(row["count"]),
                    str(row["first_seen"]),
                ),
                finding_type="sql_campaign_activity",
                title=label,
                summary=(
                    f"SQLite full-correlation scan observed {int(row['count'])} matching event(s) "
                    f"across {rows_scanned} normalized row(s), from {row['first_seen']} to {row['last_seen']}."
                ),
                category="campaign_activity",
                supporting_event_ids=(str(row["event_id"]),),
                evidence=(anchor,),
                confidence=confidence.score,
                confidence_modifiers=confidence.modifiers,
                triage_score=0.75,
                suspicion_reasons=(
                    "long-horizon activity pattern detected by SQL aggregation across the normalized event store",
                ),
                attack_stages=(stage,),
            )
        )
    return findings


def _finding_from_scored_row(
    row: sqlite3.Row,
    *,
    rows_scanned: int,
    candidate_count: int,
) -> CorrelatedFinding:
    reasons = tuple(str(reason) for reason in json.loads(str(row["suspicion_reasons_json"])) if reason)
    anchor = _anchor_from_row(row)
    confidence = assess_confidence((anchor,))
    attack_stages = _attack_stages_from_scored_row(row)
    return CorrelatedFinding(
        finding_id=stable_correlation_id("FIND", "sql_event", str(row["event_id"]), str(row["triage_score"])),
        finding_type="sql_suspicious_event",
        title=_sql_finding_title(row, attack_stages=attack_stages),
        summary=(
            f"SQLite full-correlation scan evaluated {rows_scanned} normalized row(s), "
            f"identified {candidate_count} candidate row(s), and selected this single-source timeline "
            "event for analyst review."
        ),
        category=str(row["category"]),
        supporting_event_ids=(str(row["event_id"]),),
        evidence=(anchor,),
        confidence=confidence.score,
        confidence_modifiers=confidence.modifiers,
        triage_score=float(row["triage_score"]),
        suspicion_reasons=reasons,
        warnings=_warnings_from_json(str(row["warnings_json"])),
        attack_stages=attack_stages,
    )


def _dedupe_findings(findings: list[CorrelatedFinding]) -> list[CorrelatedFinding]:
    deduped: list[CorrelatedFinding] = []
    seen: set[str] = set()
    for finding in findings:
        if finding.finding_id in seen:
            continue
        seen.add(finding.finding_id)
        deduped.append(finding)
    return deduped


def _sql_finding_title(
    row: sqlite3.Row,
    *,
    attack_stages: tuple[str, ...],
) -> str:
    haystack = _row_haystack(row)
    category = str(row["category"]).strip()
    category_label = category.upper() if category and category.lower() != "evt" else "Windows timeline"
    credential_terms = ("mimikatz", "sekurlsa", "credential", "privileged", "explicit_credential_logon")
    if "privilege_or_credential_use" in attack_stages or any(term in haystack for term in credential_terms):
        return f"{category_label} event with credential or privileged-logon indicators"
    if category.lower().startswith("memory_"):
        return f"{category_label} event with memory-process indicators"
    if "persistence" in attack_stages:
        return f"{category_label} event with persistence indicators"
    if "execution" in attack_stages:
        return f"{category_label} event with living-off-the-land execution indicators"
    if str(row["warnings_json"]) != "[]":
        return f"{category_label} event with parser or signal warnings"
    return f"{category_label} event selected by SQL correlation"


def _scored_events_sql() -> str:
    return f"""
    SELECT
      row_number,
      event_id,
      timestamp_utc,
      category,
      artifact,
      message,
      source_tool,
      source_parser,
      evidence_id,
      trust_level,
      raw_reference_json,
      normalized_fields_json,
      warnings_json,
      MIN(
        1.0,
        0.05
        + CASE WHEN LOWER(category) IN ('service_install','scheduled_task','registry_persistence','autorun')
               THEN 0.55 ELSE 0 END
        + CASE WHEN {_like_any_sql("category", AUTH_SQL_TERMS)}
               THEN 0.30 ELSE 0 END
        + CASE WHEN {_haystack_like_any_sql(PERSISTENCE_SQL_TERMS)} THEN 0.35 ELSE 0 END
        + CASE WHEN {_haystack_like_any_sql(LOLBIN_SQL_TERMS)} THEN 0.20 ELSE 0 END
        + CASE WHEN {_haystack_like_any_sql(HIGH_SIGNAL_SQL_TERMS)} THEN 0.30 ELSE 0 END
        + CASE WHEN {_haystack_like_any_sql(USER_WRITABLE_SQL_TERMS)} THEN 0.15 ELSE 0 END
        + CASE WHEN LOWER(category) IN {_sql_string_tuple(MEMORY_PROCESS_CATEGORIES)}
               THEN 0.15 ELSE 0 END
        + CASE WHEN LOWER(category) IN {_sql_string_tuple(MEMORY_HIGH_SIGNAL_CATEGORIES)}
               THEN 0.60 ELSE 0 END
        + CASE WHEN LOWER(category) IN {_sql_string_tuple(MEMORY_PROCESS_CATEGORIES)}
                    AND {_haystack_like_any_sql(MEMORY_PROCESS_SQL_TERMS)}
               THEN 0.35 ELSE 0 END
        + CASE WHEN warnings_json != '[]' THEN 0.05 ELSE 0 END
      ) AS triage_score,
      json_array(
        CASE WHEN LOWER(category) IN ('service_install','scheduled_task','registry_persistence','autorun')
             THEN 'event category indicates a persistence-capable change' END,
        CASE WHEN {_haystack_like_any_sql(PERSISTENCE_SQL_TERMS)}
             THEN 'artifact or message references a common persistence location or scheduled task' END,
        CASE WHEN {_haystack_like_any_sql(LOLBIN_SQL_TERMS)}
             THEN 'living-off-the-land binary or shell token observed' END,
        CASE WHEN {_haystack_like_any_sql(HIGH_SIGNAL_SQL_TERMS)}
             THEN 'high-signal command or credential-analysis token observed' END,
        CASE WHEN {_haystack_like_any_sql(USER_WRITABLE_SQL_TERMS)}
             THEN 'path references a user-writable or temporary execution location' END,
        CASE WHEN LOWER(category) IN {_sql_string_tuple(MEMORY_PROCESS_CATEGORIES)}
             THEN 'memory process inventory row requires host-artifact correlation' END,
        CASE WHEN LOWER(category) IN {_sql_string_tuple(MEMORY_HIGH_SIGNAL_CATEGORIES)}
             THEN 'memory plugin output indicates possible injected or suspicious memory region' END,
        CASE WHEN LOWER(category) IN {_sql_string_tuple(MEMORY_PROCESS_CATEGORIES)}
                  AND {_haystack_like_any_sql(MEMORY_PROCESS_SQL_TERMS)}
             THEN 'memory process name or command token merits review' END,
        CASE WHEN warnings_json != '[]'
             THEN 'source event carried parser or signal warnings requiring analyst review' END
      ) AS suspicion_reasons_json
    FROM normalized_events
    """


def _haystack_like_any_sql(terms: tuple[str, ...]) -> str:
    haystack = "LOWER(category || ' ' || artifact || ' ' || message || ' ' || normalized_fields_json)"
    return " OR ".join(f"{haystack} LIKE '%{_sql_escape(term.lower())}%'" for term in terms)


def _like_any_sql(column: str, terms: tuple[str, ...]) -> str:
    return " OR ".join(f"LOWER({column}) LIKE '%{_sql_escape(term.lower())}%'" for term in terms)


def _sql_escape(value: str) -> str:
    return value.replace("'", "''")


def _sql_string_tuple(values: tuple[str, ...]) -> str:
    return "(" + ",".join(f"'{_sql_escape(value.lower())}'" for value in values) + ")"


def _attack_stages_from_scored_row(row: sqlite3.Row) -> tuple[str, ...]:
    haystack = _row_haystack(row)
    stages: list[str] = []
    if any(term in haystack for term in PERSISTENCE_SQL_TERMS):
        stages.append("persistence")
    if any(term in haystack for term in LOLBIN_SQL_TERMS + HIGH_SIGNAL_SQL_TERMS):
        stages.append("execution")
    if str(row["category"]).lower() in MEMORY_HIGH_SIGNAL_CATEGORIES:
        stages.append("defense_evasion_or_injection")
    if str(row["category"]).lower() in MEMORY_PROCESS_CATEGORIES and any(
        term in haystack for term in MEMORY_PROCESS_SQL_TERMS
    ):
        stages.append("execution")
    if "credential" in haystack or "privileged" in haystack:
        stages.append("privilege_or_credential_use")
    if "auth" in str(row["category"]).lower() or "logon" in haystack:
        stages.append("initial_access_or_lateral_movement")
    return tuple(dict.fromkeys(stages))


def _row_haystack(row: sqlite3.Row) -> str:
    return " ".join(
        [
            str(row["category"]),
            str(row["artifact"]),
            str(row["message"]),
            str(row["normalized_fields_json"]),
        ]
    ).lower()


def _anchor_from_row(row: sqlite3.Row) -> EvidenceAnchor:
    raw_reference = RawReference.model_validate(json.loads(str(row["raw_reference_json"])))
    return EvidenceAnchor(
        event_id=str(row["event_id"]),
        evidence_id=str(row["evidence_id"]),
        source_tool=str(row["source_tool"]),
        source_parser=str(row["source_parser"]),
        raw_reference=raw_reference,
        trust_level=TrustTier(str(row["trust_level"])),
    )


def _support_event_ids(findings: tuple[CorrelatedFinding, ...], limit: int) -> tuple[str, ...]:
    event_ids: list[str] = []
    seen: set[str] = set()
    for finding in findings:
        for event_id in finding.supporting_event_ids:
            if event_id in seen:
                continue
            seen.add(event_id)
            event_ids.append(event_id)
            if len(event_ids) >= limit:
                return tuple(event_ids)
    return tuple(event_ids)


def _load_events_by_id(connection: sqlite3.Connection, event_ids: tuple[str, ...]) -> tuple[NormalizedEvent, ...]:
    if not event_ids:
        return ()
    placeholders = ",".join("?" for _ in event_ids)
    rows = connection.execute(
        f"""
        SELECT *
        FROM normalized_events
        WHERE event_id IN ({placeholders})
        ORDER BY timestamp_utc, event_id
        """,
        event_ids,
    ).fetchall()
    return tuple(_event_from_row(row) for row in rows)


def _event_from_row(row: sqlite3.Row) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=str(row["event_id"]),
        timestamp_utc=str(row["timestamp_utc"]),
        category=str(row["category"]),
        artifact=str(row["artifact"]),
        message=str(row["message"]),
        source_tool=str(row["source_tool"]),
        source_parser=str(row["source_parser"]),
        evidence_id=str(row["evidence_id"]),
        evidence_type=EvidenceCategory(str(row["evidence_type"])),
        trust_level=TrustTier(str(row["trust_level"])),
        trust_tier=TrustTier(str(row["trust_level"])),
        raw_reference=RawReference.model_validate(json.loads(str(row["raw_reference_json"]))),
        confidence=float(row["confidence"]),
        normalized_fields={
            str(key): str(value)
            for key, value in json.loads(str(row["normalized_fields_json"])).items()
        },
        provenance=json.loads(str(row["provenance_json"])),
        warnings=_warnings_from_json(str(row["warnings_json"])),
    )


def _warnings_from_json(value: str) -> tuple[SignalWarning, ...]:
    payload = json.loads(value)
    if not isinstance(payload, list):
        return ()
    warnings: list[SignalWarning] = []
    for item in payload:
        if isinstance(item, dict):
            warnings.append(SignalWarning.model_validate(item))
    return tuple(warnings)


def _write_candidate_rows(connection: sqlite3.Connection, findings: tuple[CorrelatedFinding, ...]) -> None:
    rows = [
        (
            finding.finding_id,
            finding.finding_type,
            finding.title,
            finding.category,
            finding.triage_score,
            len(finding.supporting_event_ids),
            _first_seen_from_finding(finding),
            _last_seen_from_finding(finding),
            json.dumps(finding.suspicion_reasons, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
            json.dumps(finding.supporting_event_ids, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
        )
        for finding in findings
    ]
    connection.executemany(
        """
        INSERT OR REPLACE INTO sql_correlation_candidates (
            finding_id,
            finding_type,
            title,
            category,
            triage_score,
            event_count,
            first_seen_utc,
            last_seen_utc,
            suspicion_reasons_json,
            supporting_event_ids_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )


def _first_seen_from_finding(finding: CorrelatedFinding) -> str:
    return finding.summary.split(" from ", 1)[-1].split(" to ", 1)[0] if " from " in finding.summary else ""


def _last_seen_from_finding(finding: CorrelatedFinding) -> str:
    return finding.summary.rsplit(" to ", 1)[-1].rstrip(".") if " to " in finding.summary else ""
