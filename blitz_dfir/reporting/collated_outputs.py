from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from blitz_dfir.core.manifest import dump_manifest_summary
from blitz_dfir.core.models import EvidenceManifest
from blitz_dfir.core.session import CaseSession


@dataclass(frozen=True)
class CollatedOutputPaths:
    overall_findings_path: Path
    overall_reports_path: Path
    collated_audit_path: Path


def write_collated_outputs(
    *,
    session: CaseSession,
    manifest: EvidenceManifest,
    report_document: Any,
    validation_report: Any,
    unknowns_report: Any,
    signal_report: Any,
    tool_results: list[dict[str, Any]],
    parser_results: list[dict[str, Any]],
    normalized_event_count: int,
    artifact_paths: Mapping[str, Path],
) -> CollatedOutputPaths:
    overall_findings_path = session.findings_dir / "overall_findings.md"
    overall_reports_path = session.reports_dir / "overall_reports.md"
    collated_audit_path = session.audit_dir / "collated_audit.md"

    overall_findings_path.write_text(
        render_overall_findings(
            session=session,
            manifest=manifest,
            report_document=report_document,
            validation_report=validation_report,
            unknowns_report=unknowns_report,
            signal_report=signal_report,
            tool_results=tool_results,
            parser_results=parser_results,
            normalized_event_count=normalized_event_count,
            artifact_paths=artifact_paths,
        ),
        encoding="utf-8",
    )
    overall_reports_path.write_text(
        render_overall_reports(session=session, artifact_paths=artifact_paths),
        encoding="utf-8",
    )
    collated_audit_path.write_text(
        render_collated_audit(session=session, artifact_paths=artifact_paths),
        encoding="utf-8",
    )
    return CollatedOutputPaths(
        overall_findings_path=overall_findings_path,
        overall_reports_path=overall_reports_path,
        collated_audit_path=collated_audit_path,
    )


def render_overall_findings(
    *,
    session: CaseSession,
    manifest: EvidenceManifest,
    report_document: Any,
    validation_report: Any,
    unknowns_report: Any,
    signal_report: Any,
    tool_results: list[dict[str, Any]],
    parser_results: list[dict[str, Any]],
    normalized_event_count: int,
    artifact_paths: Mapping[str, Path],
) -> str:
    report = _dump(report_document)
    validation = _dump(validation_report)
    unknowns = _dump(unknowns_report)
    signal = _dump(signal_report)
    manifest_summary = dump_manifest_summary(manifest)
    findings = report.get("findings") if isinstance(report.get("findings"), list) else []

    lines = [
        "# Overall Findings",
        "",
        "Label: overall findings",
        "",
        "## Run Summary",
        "",
        f"- Case: `{session.case_id}`",
        f"- Session: `{session.session_id}`",
        f"- Evidence records: `{len(manifest.evidence)}`",
        f"- Normalized events: `{normalized_event_count}`",
        f"- Report findings: `{len(findings)}`",
        f"- Validation passed: `{validation.get('passed')}`",
        f"- Unknown count: `{unknowns.get('unknown_count', 0)}`",
        f"- Signal warnings: `{len(signal.get('warnings', ()) or ())}`",
        "",
        "## Evidence Registered",
        "",
        "| Evidence ID | Type | Verified | Size Bytes | Path |",
        "| --- | --- | --- | ---: | --- |",
    ]
    for item in manifest_summary["evidence"]:
        lines.append(
            "| "
            f"`{item['evidence_id']}` | `{item['evidence_type']}` | `{item['verified']}` | "
            f"{item['size_bytes']} | `{item['path']}` |"
        )

    lines.extend(
        [
            "",
            "## Tool Execution Coverage",
            "",
            "| Tool | Evidence ID | Exit | Timed Out | Duration ms | Primary Output | Stderr |",
            "| --- | --- | ---: | --- | ---: | --- | --- |",
        ]
    )
    for result in tool_results:
        lines.append(
            "| "
            f"`{result.get('tool_name', '')}` | `{result.get('evidence_id', '')}` | "
            f"`{result.get('exit_code', '')}` | `{result.get('timed_out', '')}` | "
            f"{result.get('duration_ms', '')} | `{_rel(session, result.get('primary_output_path'))}` | "
            f"`{_rel(session, result.get('stderr_path'))}` |"
        )
    if not tool_results:
        lines.append("| none | none |  |  |  |  |  |")

    failed = [result for result in tool_results if result.get("exit_code") not in (0, "0", None)]
    if failed:
        lines.extend(["", "## Failed Or Partial Tool Work", ""])
        for result in failed:
            lines.append(
                f"- `{result.get('tool_name')}` on `{result.get('evidence_id')}` exited "
                f"`{result.get('exit_code')}`. Check `{_rel(session, result.get('stderr_path'))}`."
            )

    lines.extend(
        [
            "",
            "## Parser Coverage",
            "",
            "| Parser | Evidence ID | Processed | Warnings | Source |",
            "| --- | --- | ---: | ---: | --- |",
        ]
    )
    for result in parser_results:
        lines.append(
            "| "
            f"`{result.get('parser_name', result.get('source_parser', ''))}` | "
            f"`{result.get('evidence_id', '')}` | `{result.get('processed_count', result.get('record_count', ''))}` | "
            f"`{len(result.get('warnings', ()) or ())}` | `{result.get('source_path', result.get('source', ''))}` |"
        )
    if not parser_results:
        lines.append("| none | none |  |  |  |")

    lines.extend(["", "## Evidence-Supported Findings", ""])
    if findings:
        for index, finding in enumerate(findings, 1):
            lines.extend(
                [
                    f"### Finding {index}: {finding.get('finding', finding.get('title', 'Untitled finding'))}",
                    "",
                    f"- Confidence: `{finding.get('confidence')}`",
                    f"- Triage score: `{finding.get('triage_score')}`",
                    f"- Evidence source: `{finding.get('evidence_source')}`",
                    f"- Evidence type: `{finding.get('evidence_type')}`",
                    f"- Attack stages: `{', '.join(finding.get('attack_stages', ()) or ())}`",
                    f"- Suspicion reasons: `{'; '.join(finding.get('suspicion_reasons', ()) or ())}`",
                    "",
                ]
            )
    else:
        lines.append("No report findings were produced.")

    lines.extend(["", "## Validation And Unknowns", ""])
    for issue in validation.get("issues", ()) or ():
        if isinstance(issue, dict):
            lines.append(f"- `{issue.get('severity', '')}` `{issue.get('issue_type', '')}`: {issue.get('message', '')}")
    for unknown in unknowns.get("unknowns", ()) or ():
        if isinstance(unknown, dict):
            lines.append(f"- Unknown `{unknown.get('severity', '')}` `{unknown.get('unknown_type', '')}`: {unknown.get('message', '')}")
    if not validation.get("issues") and not unknowns.get("unknowns"):
        lines.append("No validation issues or unknown zones were recorded.")

    lines.extend(["", "## Source Artifacts", ""])
    for label, path in sorted(artifact_paths.items()):
        lines.append(f"- `{label}`: `{_rel(session, path)}`")
    lines.append("")
    return "\n".join(lines)


def render_overall_reports(*, session: CaseSession, artifact_paths: Mapping[str, Path]) -> str:
    sections = [
        "# Overall Reports",
        "",
        "Label: overall reports",
        "",
        "This document collates the judge-readable report documents generated for this session.",
        "",
    ]
    report_order = (
        "report_markdown",
        "case_objective_markdown",
        "investigation_plan_markdown",
        "evidence_triage_markdown",
        "temporal_gap_analysis_markdown",
        "attack_stage_timeline_markdown",
        "evidentiary_weighting_markdown",
        "contradiction_analysis_markdown",
        "llm_report_verification_markdown",
        "evidence_maturity_markdown",
        "finding_provenance_markdown",
        "agent_journal_markdown",
    )
    for label in report_order:
        path = artifact_paths.get(label)
        if path is None:
            continue
        sections.extend(
            [
                f"## {_title(label)}",
                "",
                f"Source: `{_rel(session, path)}`",
                "",
                _read_text(path),
                "",
            ]
        )
    return "\n".join(sections).rstrip() + "\n"


def render_collated_audit(*, session: CaseSession, artifact_paths: Mapping[str, Path]) -> str:
    lines = [
        "# Collated Audit",
        "",
        "Label: collated audit",
        "",
        "This document collates audit-adjacent state, progress, artifact index, and hash-chain events.",
        "",
        "Note: this rollup is generated before final artifact hashing completes so the artifact manifest can hash it. "
        "The authoritative terminal audit events remain in the session `.ndjson` audit log referenced below.",
        "",
        "## Session State",
        "",
        "```json",
        _read_json_pretty(session.audit_dir / "session_state.json"),
        "```",
        "",
        "## Progress Summary",
        "",
        "```json",
        _read_json_pretty(session.audit_dir / "progress.json"),
        "```",
        "",
    ]

    artifact_manifest = artifact_paths.get("artifact_manifest")
    if artifact_manifest and artifact_manifest.exists():
        lines.extend(["## Artifact Manifest", "", "```json", _read_json_pretty(artifact_manifest), "```", ""])

    lines.extend(["## Audit Event Log", ""])
    audit_events = _read_audit_events(session.audit_log_path)
    if audit_events:
        for event in audit_events:
            data = event.get("data", {}) if isinstance(event.get("data"), dict) else {}
            actor = data.get("actor", "")
            component = data.get("component", "")
            detail = _compact_detail(data)
            lines.append(
                f"- `{event.get('sequence')}` `{event.get('timestamp_utc')}` "
                f"`{event.get('event_type')}` actor=`{actor}` component=`{component}` {detail}"
            )
    else:
        lines.append("No audit events were available.")
    lines.append("")
    return "\n".join(lines)


def _dump(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        dumped = value.model_dump(mode="json")
        return dumped if isinstance(dumped, dict) else {}
    return value if isinstance(value, dict) else {}


def _rel(session: CaseSession, value: Any) -> str:
    if value is None:
        return ""
    path = Path(str(value))
    try:
        return str(path.resolve().relative_to(session.session_root.resolve())).replace("\\", "/")
    except (OSError, ValueError):
        return str(value)


def _title(label: str) -> str:
    return label.replace("_", " ").title()


def _read_text(path: Path, *, max_chars: int | None = None) -> str:
    if max_chars is None:
        max_chars = _max_collated_chars()
    if not path.exists():
        return "_Missing source artifact._\n"
    text = path.read_text(encoding="utf-8", errors="replace")
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n\n_Section truncated in collated report; see source artifact for full content._\n"


def _read_json_pretty(path: Path) -> str:
    if not path.exists():
        return "{}"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return json.dumps({"unparsed": _read_text(path, max_chars=20_000)}, indent=2, ensure_ascii=True)
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True)


def _read_audit_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            events.append(payload)
    return events


def _compact_detail(data: dict[str, Any], *, max_items: int = 6) -> str:
    ignored = {"actor", "component", "boundary", "behavior"}
    parts: list[str] = []
    for key in sorted(k for k in data if k not in ignored)[:max_items]:
        value = data[key]
        if isinstance(value, (dict, list, tuple)):
            value = json.dumps(value, sort_keys=True, ensure_ascii=True)[:160]
        parts.append(f"{key}=`{value}`")
    return " ".join(parts)


def _max_collated_chars() -> int:
    raw = os.environ.get("BLITZ_COLLATED_SECTION_CHAR_LIMIT", "")
    try:
        return min(max(int(raw), 10_000), 1_000_000)
    except ValueError:
        return 250_000
