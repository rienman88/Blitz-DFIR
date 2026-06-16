from __future__ import annotations

import re
from pathlib import Path

from blitz_dfir.reporting.evidence_maturity import EvidenceChainLink, EvidenceMaturityReport, FindingTrace
from blitz_dfir.reporting.findings import scrub_report_text


def render_finding_provenance_markdown(
    report: EvidenceMaturityReport,
    path: Path | None = None,
    *,
    finding_limit: int = 10,
) -> str:
    """Render judge-facing finding provenance diagrams from evidence maturity traces."""

    shown = report.finding_traces[: max(finding_limit, 0)]
    lines = [
        "# Finding Provenance Visualization",
        "",
        f"- Case: `{report.case_id}`",
        f"- Session: `{report.session_id}`",
        f"- Traceable findings: `{report.summary.get('traceable_finding_count')}/{report.summary.get('finding_count')}`",
        f"- Evidence hashes preserved: `{report.summary.get('evidence_hashes_preserved')}`",
        f"- Displayed findings: `{len(shown)}`",
        "",
        "This file is generated from `findings/evidence_maturity.json`. It is a visualization of existing provenance, not a separate source of truth.",
        "",
    ]
    if not shown:
        lines.extend(["No findings available for visualization.", ""])
    for index, trace in enumerate(shown, 1):
        lines.extend(_finding_section(trace, index=index))
    text = "\n".join(lines).rstrip() + "\n"
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return text


def _finding_section(trace: FindingTrace, *, index: int) -> list[str]:
    modifiers = ", ".join(trace.confidence_modifiers) if trace.confidence_modifiers else "none"
    stages = ", ".join(trace.attack_stages) if trace.attack_stages else "none"
    gaps = "; ".join(trace.gaps) if trace.gaps else "none"
    lines = [
        f"## Finding {index}: `{trace.finding_id}`",
        "",
        f"- Title: {scrub_report_text(trace.title)}",
        f"- Confidence: `{trace.confidence:.2f}`",
        f"- Triage score: `{trace.triage_score:.2f}`",
        f"- Confidence modifiers: `{modifiers}`",
        f"- Attack stages: `{stages}`",
        f"- Trace complete: `{trace.complete}`",
        f"- Gaps: {scrub_report_text(gaps)}",
        "",
        "```mermaid",
        "flowchart LR",
    ]
    finding_node = _node_id(f"finding_{index}")
    lines.append(f'  {finding_node}["Finding<br/>{_label(trace.finding_id)}<br/>confidence {_label(f"{trace.confidence:.2f}")}"]')
    if not trace.evidence_chain:
        lines.append(f'  {finding_node} --> gap_{index}["No evidence links"]')
    for link_index, link in enumerate(trace.evidence_chain, 1):
        lines.extend(_chain_lines(finding_node, link, index=index, link_index=link_index))
    lines.extend(["```", ""])
    if trace.why_flagged:
        lines.extend(["Why flagged:", ""])
        for reason in trace.why_flagged[:5]:
            lines.append(f"- {scrub_report_text(reason)}")
        lines.append("")
    return lines


def _chain_lines(finding_node: str, link: EvidenceChainLink, *, index: int, link_index: int) -> list[str]:
    prefix = f"f{index}_{link_index}"
    event_node = _node_id(f"{prefix}_event")
    parser_node = _node_id(f"{prefix}_parser")
    tool_node = _node_id(f"{prefix}_tool")
    evidence_node = _node_id(f"{prefix}_evidence")
    audit_node = _node_id(f"{prefix}_audit")

    event_label = f"Normalized Event<br/>{link.event_id}<br/>{link.normalized_record.category if link.normalized_record else link.traceability_status}"
    parser_label = "Parser<br/>missing"
    if link.parser_result:
        parser_label = (
            f"Parser<br/>{link.parser_result.parser}<br/>"
            f"processed {link.parser_result.processed_count}, malformed {link.parser_result.malformed_count}"
        )
    tool_label = "Tool<br/>direct/unknown"
    if link.tool_execution:
        timed_out = "timeout" if link.tool_execution.timed_out else "exit"
        tool_label = f"Tool<br/>{link.tool_execution.typed_tool}<br/>{timed_out} {link.tool_execution.exit_code}"
    audit_count = len(link.audit_entries)
    link_gaps = "; ".join(link.gaps) if link.gaps else "none"
    return [
        f'  {event_node}["{_label(event_label)}"]',
        f'  {parser_node}["{_label(parser_label)}"]',
        f'  {tool_node}["{_label(tool_label)}"]',
        f'  {evidence_node}["Evidence<br/>{_label(link.evidence_id)}<br/>status {_label(link.traceability_status)}"]',
        f'  {audit_node}["Audit refs<br/>{audit_count}<br/>gaps {_label(link_gaps)}"]',
        f"  {finding_node} --> {event_node}",
        f"  {event_node} --> {parser_node}",
        f"  {parser_node} --> {tool_node}",
        f"  {tool_node} --> {evidence_node}",
        f"  {event_node} --> {audit_node}",
    ]


def _node_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", value)


def _label(value: object) -> str:
    text = scrub_report_text(value)
    text = text.replace('"', "'")
    text = text.replace("[", "(").replace("]", ")")
    text = " ".join(text.split())
    return text[:120]
