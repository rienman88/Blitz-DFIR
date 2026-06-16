from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Mapping

from blitz_dfir.core.manifest import dump_manifest_summary
from blitz_dfir.core.models import EvidenceManifest
from blitz_dfir.core.session import CaseSession

TRACE_SCHEMA_VERSION = "agent-trace.v1"


def build_agent_trace(
    *,
    session: CaseSession,
    manifest: EvidenceManifest,
    case_objective: Any,
    investigation_plan: Any,
    investigation_guidance: Any,
    report_document: Any,
    validation_report: Any,
    unknowns_report: Any,
    correction_history: Any,
    contradiction_analysis: Any,
    llm_report_verification: Any,
    reasoning: Any,
    tool_results: list[dict[str, Any]],
    parser_results: list[dict[str, Any]],
    normalized_event_count: int,
    evidence_maturity_report: Any | None = None,
) -> dict[str, Any]:
    report = _dump(report_document)
    objective = _dump(case_objective)
    plan = _dump(investigation_plan)
    guidance = _dump(investigation_guidance)
    validation = _dump(validation_report)
    unknowns = _dump(unknowns_report)
    corrections = _dump(correction_history)
    contradiction = _dump(contradiction_analysis)
    llm_verification = _dump(llm_report_verification)
    maturity = _dump(evidence_maturity_report)
    audit_events = _read_audit_events(session.audit_log_path)

    findings = report.get("findings") if isinstance(report.get("findings"), list) else []
    trace_findings = [
        _finding_trace(finding=finding, tool_results=tool_results, audit_events=audit_events)
        for finding in findings
        if isinstance(finding, dict)
    ]

    hypotheses = _deterministic_hypotheses(guidance=guidance, findings=trace_findings)
    hypotheses.extend(_reasoning_hypotheses(reasoning))

    trace = {
        "schema_version": TRACE_SCHEMA_VERSION,
        "generated_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "case_id": session.case_id,
        "session_id": session.session_id,
        "evidence_type": "DERIVED",
        "raw_evidence_included": False,
        "raw_tool_output_included": False,
        "mission": {
            "objective": objective.get("objective") or "Evidence-first DFIR investigation",
            "source": objective.get("source") or "case_objective",
            "success_criteria": objective.get("success_criteria", ()),
            "constraints": objective.get("constraints", ()),
        },
        "evidence_scope": dump_manifest_summary(manifest),
        "observations": _observations(
            normalized_event_count=normalized_event_count,
            findings=trace_findings,
            validation=validation,
            unknowns=unknowns,
            tool_results=tool_results,
            parser_results=parser_results,
            guidance=guidance,
            maturity=maturity,
        ),
        "hypotheses": hypotheses,
        "actions": _tool_actions(tool_results=tool_results, audit_events=audit_events),
        "parser_actions": _parser_actions(parser_results),
        "plan_changes": _plan_changes(audit_events=audit_events, guidance=guidance, validation=validation),
        "corrections": _corrections(corrections),
        "contradictions": _contradictions(contradiction),
        "unknowns": _unknowns(unknowns),
        "findings": trace_findings,
        "validation": {
            "passed": validation.get("passed"),
            "issue_count": len(validation.get("issues", ()) or ()),
            "issues": validation.get("issues", ()) or (),
            "parser_integrity_ok": validation.get("parser_integrity_ok"),
        },
        "llm_report_verification": {
            "status": llm_verification.get("status", "not_run"),
            "reasoning_enabled": llm_verification.get("reasoning_enabled", False),
            "raw_evidence_sent": llm_verification.get("raw_evidence_sent", False),
            "raw_tool_output_sent": llm_verification.get("raw_tool_output_sent", False),
            "invalid_evidence_reference_count": llm_verification.get("invalid_evidence_reference_count", 0),
            "supported_hypotheses_without_evidence": llm_verification.get(
                "supported_hypotheses_without_evidence", 0
            ),
        },
        "audit_reference": {
            "audit_log": str(session.audit_log_path),
            "audit_event_count": len(audit_events),
            "notable_event_types": sorted({str(event.get("event_type")) for event in audit_events if event}),
        },
        "guardrails": {
            "mcp_typed_allowlist": True,
            "evidence_id_required": True,
            "generic_shell_exposed": False,
            "raw_output_returned_to_agent": False,
            "llm_can_create_findings": False,
            "claim_boundary": (
                "Findings remain deterministic Blitz outputs. LLM reasoning and this journal are derived "
                "explanations over bounded summaries and audit state."
            ),
        },
    }
    trace["summary"] = {
        "finding_count": len(trace_findings),
        "hypothesis_count": len(hypotheses),
        "tool_action_count": len(trace["actions"]),
        "plan_change_count": len(trace["plan_changes"]),
        "correction_count": len(trace["corrections"]),
        "unknown_count": len(trace["unknowns"]),
        "validation_passed": trace["validation"]["passed"],
    }
    return trace


def export_agent_trace(trace: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(trace, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def render_agent_journal(trace: Mapping[str, Any], path: Path | None = None) -> str:
    summary = _dict(trace.get("summary"))
    mission = _dict(trace.get("mission"))
    validation = _dict(trace.get("validation"))
    guardrails = _dict(trace.get("guardrails"))
    llm = _dict(trace.get("llm_report_verification"))
    lines = [
        "# Agent Journal",
        "",
        "Label: agent journal",
        "",
        "This document reconstructs Blitz's investigative arc from deterministic audit and report artifacts. "
        "It is not raw evidence and it does not create findings.",
        "",
        "## Mission",
        "",
        f"- Case: `{trace.get('case_id')}`",
        f"- Session: `{trace.get('session_id')}`",
        f"- Objective: {_text(mission.get('objective'))}",
        f"- Raw evidence included: `{trace.get('raw_evidence_included')}`",
        f"- Raw tool output included: `{trace.get('raw_tool_output_included')}`",
        "",
        "## Execution Summary",
        "",
        f"- Findings traced: `{summary.get('finding_count', 0)}`",
        f"- Hypotheses recorded: `{summary.get('hypothesis_count', 0)}`",
        f"- Tool actions: `{summary.get('tool_action_count', 0)}`",
        f"- Plan changes/recoveries: `{summary.get('plan_change_count', 0)}`",
        f"- Corrections: `{summary.get('correction_count', 0)}`",
        f"- Unknowns: `{summary.get('unknown_count', 0)}`",
        f"- Validation passed: `{summary.get('validation_passed')}`",
        "",
        "## Guardrails",
        "",
        f"- MCP typed allowlist: `{guardrails.get('mcp_typed_allowlist')}`",
        f"- Evidence ID required: `{guardrails.get('evidence_id_required')}`",
        f"- Generic shell exposed: `{guardrails.get('generic_shell_exposed')}`",
        f"- Raw output returned to agent: `{guardrails.get('raw_output_returned_to_agent')}`",
        f"- LLM can create findings: `{guardrails.get('llm_can_create_findings')}`",
        f"- LLM verification status: `{llm.get('status', 'not_run')}`",
        "",
        "## Observations",
        "",
    ]
    for observation in _list(trace.get("observations")):
        if isinstance(observation, dict):
            lines.append(f"- `{observation.get('type', 'observation')}`: {_text(observation.get('message'))}")
    if not _list(trace.get("observations")):
        lines.append("- No observations were recorded.")

    lines.extend(["", "## Hypotheses", ""])
    for hypothesis in _list(trace.get("hypotheses")):
        if isinstance(hypothesis, dict):
            lines.append(
                f"- `{hypothesis.get('status', 'needs_validation')}` confidence `{hypothesis.get('confidence', 0)}`: "
                f"{_text(hypothesis.get('statement') or hypothesis.get('hypothesis'))}"
            )
            basis = hypothesis.get("basis_findings") or hypothesis.get("evidence_event_ids") or ()
            if basis:
                lines.append(f"  Basis: `{', '.join(str(item) for item in basis)}`")
    if not _list(trace.get("hypotheses")):
        lines.append("- No hypotheses were recorded.")

    lines.extend(["", "## Plan Changes And Recovery", ""])
    plan_changes = _list(trace.get("plan_changes"))
    for item in plan_changes:
        if isinstance(item, dict):
            lines.append(
                f"- `{item.get('event_type', item.get('type', 'plan_change'))}` "
                f"at `{item.get('timestamp_utc', 'unknown')}`: {_text(item.get('reason') or item.get('summary'))}"
            )
    if not plan_changes:
        lines.append("- No plan changes or recovery events were recorded.")

    lines.extend(["", "## Three-Claim Trace Table", ""])
    lines.extend(
        [
            "| Finding | Trace status | Confidence | Tool evidence | Supporting events |",
            "| --- | --- | ---: | --- | --- |",
        ]
    )
    for finding in _list(trace.get("findings"))[:25]:
        if not isinstance(finding, dict):
            continue
        tool_text = "; ".join(
            f"{tool.get('tool_name') or tool.get('typed_tool')} on {tool.get('evidence_id')} exit={tool.get('exit_code')}"
            for tool in _list(finding.get("tool_trace"))[:4]
            if isinstance(tool, dict)
        )
        lines.append(
            "| "
            f"`{_md(finding.get('finding_id'))}` {_md(finding.get('title'))} | "
            f"`{_md(finding.get('trace_status'))}` | "
            f"`{finding.get('confidence', 0)}` | "
            f"{_md(tool_text or 'not linked')} | "
            f"`{', '.join(str(item) for item in _list(finding.get('supporting_event_ids'))[:8])}` |"
        )
    if not _list(trace.get("findings")):
        lines.append("| none | no findings |  |  |  |")

    lines.extend(["", "## Validation And Unknowns", ""])
    lines.append(f"- Validation issue count: `{validation.get('issue_count', 0)}`")
    for issue in _list(validation.get("issues"))[:20]:
        if isinstance(issue, dict):
            lines.append(
                f"- `{issue.get('severity', '')}` `{issue.get('issue_type', '')}`: {_text(issue.get('message'))}"
            )
    for unknown in _list(trace.get("unknowns"))[:20]:
        if isinstance(unknown, dict):
            lines.append(
                f"- Unknown `{unknown.get('severity', '')}` `{unknown.get('unknown_type', '')}`: "
                f"{_text(unknown.get('message') or unknown.get('impact'))}"
            )
    lines.append("")
    text = "\n".join(lines)
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return text


def _observations(
    *,
    normalized_event_count: int,
    findings: list[dict[str, Any]],
    validation: dict[str, Any],
    unknowns: dict[str, Any],
    tool_results: list[dict[str, Any]],
    parser_results: list[dict[str, Any]],
    guidance: dict[str, Any],
    maturity: dict[str, Any],
) -> list[dict[str, Any]]:
    failed_tools = [item for item in tool_results if _exit_code(item) not in (0, None)]
    warnings = sum(len(result.get("warnings", ()) or ()) for result in parser_results if isinstance(result, dict))
    observations = [
        {
            "type": "normalization",
            "message": f"Blitz normalized {normalized_event_count} event rows for downstream analysis.",
            "count": normalized_event_count,
        },
        {
            "type": "correlation",
            "message": f"Blitz produced {len(findings)} report findings with claim-to-tool trace metadata.",
            "count": len(findings),
        },
        {
            "type": "tool_execution",
            "message": f"{len(tool_results)} typed tool executions were recorded; {len(failed_tools)} had non-zero exits.",
            "tool_count": len(tool_results),
            "failed_tool_count": len(failed_tools),
        },
        {
            "type": "parser_coverage",
            "message": f"{len(parser_results)} parser results were recorded with {warnings} parser warnings.",
            "parser_result_count": len(parser_results),
            "warning_count": warnings,
        },
        {
            "type": "validation",
            "message": (
                f"Validation passed={validation.get('passed')} with "
                f"{len(validation.get('issues', ()) or ())} recorded issues."
            ),
            "passed": validation.get("passed"),
            "issue_count": len(validation.get("issues", ()) or ()),
        },
        {
            "type": "unknowns",
            "message": f"{unknowns.get('unknown_count', 0)} unknown or coverage-gap records were documented.",
            "unknown_count": unknowns.get("unknown_count", 0),
        },
    ]
    if guidance.get("recommended_tools"):
        observations.append(
            {
                "type": "investigation_guidance",
                "message": "Investigation guidance recommended follow-up tools from findings and attack stages.",
                "recommended_tools": guidance.get("recommended_tools", ()),
            }
        )
    maturity_summary = _dict(maturity.get("summary"))
    if maturity_summary:
        observations.append(
            {
                "type": "evidence_maturity",
                "message": (
                    f"{maturity_summary.get('traceable_finding_count', 0)} of "
                    f"{maturity_summary.get('finding_count', 0)} findings were traceable in evidence maturity."
                ),
                "summary": maturity_summary,
            }
        )
    return observations


def _deterministic_hypotheses(*, guidance: dict[str, Any], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    categories = guidance.get("finding_categories", ()) or ()
    stages = guidance.get("attack_stages", ()) or ()
    recommendations = guidance.get("recommendations", ()) or ()
    if not findings and not categories and not stages:
        return []
    top_findings = [str(finding.get("finding_id")) for finding in findings[:5]]
    statement_parts = []
    if categories:
        statement_parts.append("finding categories " + ", ".join(str(item) for item in categories[:5]))
    if stages:
        statement_parts.append("attack stages " + ", ".join(str(item) for item in stages[:5]))
    statement = "Blitz prioritized follow-up based on " + (" and ".join(statement_parts) or "correlated findings")
    return [
        {
            "hypothesis_id": "HYP-DETERMINISTIC-001",
            "source": "deterministic_investigation_guidance",
            "statement": statement,
            "status": "needs_validation" if recommendations else "supported",
            "confidence": 0.65 if recommendations else 0.50,
            "basis_findings": top_findings,
            "recommended_actions": recommendations,
            "evidence_type": "INFERRED",
        }
    ]


def _reasoning_hypotheses(reasoning: Any) -> list[dict[str, Any]]:
    dumped = _dump(reasoning)
    output = []
    for index, item in enumerate(_list(dumped.get("hypotheses")), 1):
        if not isinstance(item, dict):
            continue
        output.append(
            {
                "hypothesis_id": f"HYP-LLM-{index:03d}",
                "source": "bounded_llm_reasoning",
                "statement": item.get("hypothesis", ""),
                "status": item.get("status", "needs_validation"),
                "confidence": item.get("confidence", 0.0),
                "evidence_event_ids": item.get("evidence_event_ids", ()),
                "rationale": item.get("rationale", ""),
                "evidence_type": item.get("evidence_type", "INFERRED"),
            }
        )
    return output


def _tool_actions(*, tool_results: list[dict[str, Any]], audit_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    event_lookup = _tool_audit_lookup(audit_events)
    actions = []
    for index, result in enumerate(tool_results, 1):
        execution = _dict(result.get("execution"))
        outputs = _dict(result.get("outputs"))
        integrity = _dict(result.get("tool_integrity"))
        typed_tool = result.get("typed_tool") or result.get("tool_name")
        evidence_id = result.get("evidence_id")
        actions.append(
            {
                "action_id": f"ACT-{index:04d}",
                "typed_tool": typed_tool,
                "tool_name": result.get("tool_name"),
                "evidence_id": evidence_id,
                "exit_code": execution.get("exit_code"),
                "timed_out": execution.get("timed_out"),
                "duration_ms": execution.get("duration_ms"),
                "primary_output": outputs.get("primary_output"),
                "output_hash": outputs.get("output_hash"),
                "tool_verified": integrity.get("verified"),
                "raw_output_returned": result.get("raw_output_returned", False),
                "audit_events": event_lookup.get((str(typed_tool), str(evidence_id)), ()),
            }
        )
    return actions


def _parser_actions(parser_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    actions = []
    for index, result in enumerate(parser_results, 1):
        actions.append(
            {
                "parser_action_id": f"PARSE-{index:04d}",
                "parser": result.get("parser") or result.get("parser_name") or result.get("source_parser"),
                "source_tool": result.get("source_tool"),
                "evidence_id": result.get("evidence_id"),
                "processed_count": result.get("processed_count", result.get("record_count")),
                "malformed_count": result.get("malformed_count"),
                "truncated": result.get("truncated"),
                "warning_count": len(result.get("warnings", ()) or ()),
            }
        )
    return actions


def _plan_changes(
    *,
    audit_events: list[dict[str, Any]],
    guidance: dict[str, Any],
    validation: dict[str, Any],
) -> list[dict[str, Any]]:
    selected_types = {
        "plan_change",
        "hypothesis_formed",
        "disk_triage_fallback_started",
        "disk_triage_fallback_completed",
        "disk_triage_fallback_failed",
        "disk_triage_fallback_disabled",
        "analysis_tool_failed",
        "batch_task_skipped",
        "correction_attempt",
        "correction_history",
        "correction_outcome",
        "rerun_trigger",
        "analysis_scope_limited",
    }
    output = []
    for event in audit_events:
        event_type = str(event.get("event_type") or "")
        if event_type not in selected_types:
            continue
        data = _dict(event.get("data"))
        output.append(
            {
                "event_type": event_type,
                "timestamp_utc": event.get("timestamp_utc"),
                "sequence": event.get("sequence"),
                "reason": data.get("reason") or data.get("message") or data.get("impact") or event_type,
                "summary": _compact_data(data),
            }
        )
    if guidance.get("recommended_tools") or guidance.get("recommendations"):
        output.append(
            {
                "event_type": "investigation_guidance_resequencing",
                "timestamp_utc": None,
                "reason": "Blitz recommended follow-up lanes from finding distribution and attack stages.",
                "recommended_tools": guidance.get("recommended_tools", ()),
                "recommendations": guidance.get("recommendations", ()),
            }
        )
    if validation.get("passed") is False:
        output.append(
            {
                "event_type": "validation_driven_review",
                "timestamp_utc": None,
                "reason": "Validation issues require analyst review before treating findings as complete.",
                "issue_count": len(validation.get("issues", ()) or ()),
            }
        )
    return output


def _corrections(correction_history: dict[str, Any]) -> list[dict[str, Any]]:
    attempts = correction_history.get("attempts") if isinstance(correction_history.get("attempts"), list) else []
    return [attempt for attempt in attempts if isinstance(attempt, dict)]


def _contradictions(report: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(report.get("contradictions"), list):
        return [item for item in report["contradictions"] if isinstance(item, dict)]
    if isinstance(report.get("finding_impacts"), list):
        return [item for item in report["finding_impacts"] if isinstance(item, dict)]
    return []


def _unknowns(report: dict[str, Any]) -> list[dict[str, Any]]:
    items = report.get("unknowns") if isinstance(report.get("unknowns"), list) else []
    return [item for item in items if isinstance(item, dict)]


def _finding_trace(
    *,
    finding: dict[str, Any],
    tool_results: list[dict[str, Any]],
    audit_events: list[dict[str, Any]],
) -> dict[str, Any]:
    evidence_ids = set(str(item) for item in _list(finding.get("evidence_source")))
    source_tools = set(str(item) for item in _list(finding.get("source_tool")))
    tool_trace = [
        _tool_trace_item(result)
        for result in tool_results
        if _tool_matches(result, evidence_ids=evidence_ids, source_tools=source_tools)
    ]
    audit_refs = _finding_audit_refs(finding=finding, audit_events=audit_events)
    return {
        "finding_id": finding.get("finding_id"),
        "title": finding.get("finding") or finding.get("title"),
        "summary": finding.get("summary", ""),
        "category": finding.get("category"),
        "confidence": finding.get("confidence"),
        "triage_score": finding.get("triage_score"),
        "evidence_type": finding.get("evidence_type"),
        "evidence_source": _list(finding.get("evidence_source")),
        "source_tool": _list(finding.get("source_tool")),
        "parser": _list(finding.get("parser")),
        "supporting_event_ids": _list(finding.get("supporting_event_ids") or finding.get("event_ids")),
        "attack_stages": _list(finding.get("attack_stages")),
        "suspicion_reasons": _list(finding.get("suspicion_reasons")),
        "tool_trace": tool_trace,
        "audit_references": audit_refs,
        "trace_status": "tool_execution_linked" if tool_trace else "needs_manual_tool_trace_review",
    }


def _tool_matches(result: dict[str, Any], *, evidence_ids: set[str], source_tools: set[str]) -> bool:
    evidence_match = not evidence_ids or str(result.get("evidence_id")) in evidence_ids
    tool_names = {
        str(result.get("typed_tool") or ""),
        str(result.get("tool_name") or ""),
        str(_dict(result.get("tool_integrity")).get("executable") or ""),
    }
    normalized_tool_names = {item.lower() for item in tool_names if item}
    normalized_sources = {item.lower() for item in source_tools if item}
    tool_match = not normalized_sources or bool(
        normalized_tool_names & normalized_sources
        or any(source in tool for source in normalized_sources for tool in normalized_tool_names)
        or any(tool in source for source in normalized_sources for tool in normalized_tool_names)
    )
    return evidence_match and tool_match


def _tool_trace_item(result: dict[str, Any]) -> dict[str, Any]:
    execution = _dict(result.get("execution"))
    outputs = _dict(result.get("outputs"))
    integrity = _dict(result.get("tool_integrity"))
    return {
        "typed_tool": result.get("typed_tool"),
        "tool_name": result.get("tool_name"),
        "evidence_id": result.get("evidence_id"),
        "exit_code": execution.get("exit_code"),
        "timed_out": execution.get("timed_out"),
        "duration_ms": execution.get("duration_ms"),
        "primary_output": outputs.get("primary_output"),
        "output_hash": outputs.get("output_hash"),
        "tool_verified": integrity.get("verified"),
        "raw_output_returned": result.get("raw_output_returned", False),
    }


def _finding_audit_refs(*, finding: dict[str, Any], audit_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    evidence_ids = set(str(item) for item in _list(finding.get("evidence_source")))
    refs = []
    for event in audit_events:
        data = _dict(event.get("data"))
        if str(data.get("evidence_id") or "") not in evidence_ids:
            continue
        if str(event.get("event_type")) not in {"tool_request_validated", "tool_request_completed", "analysis_tool_result", "parser_completed"}:
            continue
        refs.append(
            {
                "sequence": event.get("sequence"),
                "timestamp_utc": event.get("timestamp_utc"),
                "event_type": event.get("event_type"),
                "tool": data.get("tool") or data.get("typed_tool") or data.get("tool_name"),
                "parser": data.get("parser"),
            }
        )
        if len(refs) >= 12:
            break
    return refs


def _tool_audit_lookup(audit_events: list[dict[str, Any]]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    lookup: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for event in audit_events:
        data = _dict(event.get("data"))
        tool = str(data.get("tool") or data.get("typed_tool") or data.get("tool_name") or "")
        evidence_id = str(data.get("evidence_id") or "")
        if not tool or not evidence_id:
            continue
        lookup.setdefault((tool, evidence_id), []).append(
            {
                "sequence": event.get("sequence"),
                "timestamp_utc": event.get("timestamp_utc"),
                "event_type": event.get("event_type"),
            }
        )
    return lookup


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


def _exit_code(result: dict[str, Any]) -> int | None:
    value = _dict(result.get("execution")).get("exit_code")
    if value is None:
        value = result.get("exit_code")
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _compact_data(data: dict[str, Any]) -> dict[str, Any]:
    allowed = (
        "tool",
        "typed_tool",
        "tool_name",
        "evidence_id",
        "reason",
        "exit_code",
        "timed_out",
        "parsed_records",
        "recommendation_count",
        "trigger_count",
        "correction_status",
    )
    return {key: data[key] for key in allowed if key in data}


def _dump(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if hasattr(value, "model_dump"):
        dumped = value.model_dump(mode="json")
        return dumped if isinstance(dumped, dict) else {}
    if isinstance(value, dict):
        return value
    return {}


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _text(value: object) -> str:
    text = "" if value is None else str(value)
    return text.replace("\n", " ").strip()


def _md(value: object) -> str:
    return _text(value).replace("\\", "\\\\").replace("`", "\\`").replace("|", "\\|")


def _iter_dicts(values: Iterable[Any]) -> Iterable[dict[str, Any]]:
    for value in values:
        if isinstance(value, dict):
            yield value
