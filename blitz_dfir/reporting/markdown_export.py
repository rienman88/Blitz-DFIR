from __future__ import annotations

from html import escape
from pathlib import Path

from blitz_dfir.reporting.report_builder import ReportDocument


def render_markdown_report(report: ReportDocument, path: Path | None = None) -> str:
    lines: list[str] = [
        "# Blitz DFIR Report",
        "",
        f"- Case: {_md(report.case_id)}",
        f"- Generated: `{report.generated_at_utc}`",
        f"- Audit trail: `{_md(report.audit_trail_reference)}`",
        f"- Global case trust: `{report.global_case_trust_score:.2f}`",
        f"- Parser consensus: `{report.parser_consensus_score:.2f}`",
        f"- Tool integrity: `{_md(report.tool_integrity_status)}`",
        "",
        "Coverage X percent; analysis gaps documented. Tool output is evidence candidate.",
        "",
        "## Case Objective And Evidence Triage",
        "",
        f"- Objective: {_md(report.case_objective.get('objective', 'Evidence-first DFIR investigation'))}",
        f"- Objective source: `{_md(report.case_objective.get('source', 'default_evidence_first'))}`",
        f"- Planning mode: `{_md(report.investigation_plan.get('mode', 'evidence_first'))}`",
        f"- Prioritized families: `{', '.join(report.investigation_plan.get('prioritized_artifact_families', []))}`",
        f"- Prioritized evidence: `{', '.join(report.evidence_triage.get('prioritized_evidence_ids', []))}`",
        "",
        "The objective and triage plan guide work order only. Blitz findings still require manifest-verified evidence and typed tool output.",
        "",
        "## Investigation Guidance",
        "",
        f"- Recommended tools: `{', '.join(report.investigation_guidance.get('recommended_tools', []))}`",
        f"- Attack stages: `{', '.join(report.investigation_guidance.get('attack_stages', []))}`",
        f"- Finding categories: `{', '.join(report.investigation_guidance.get('finding_categories', []))}`",
        "",
    ]
    recommendations = report.investigation_guidance.get("recommendations", [])
    if recommendations:
        for recommendation in recommendations:
            lines.append(f"- {_md(recommendation)}")
        lines.append("")
    else:
        lines.extend(
            [
                "No follow-up recommendation was generated because no finding or attack stage crossed the deterministic guidance rules.",
                "",
            ]
        )
    lines.extend(
        [
        "## Temporal Gap Analysis",
        "",
        f"- Events evaluated: `{report.temporal_gap_analysis.get('event_count', 0)}`",
        f"- Valid timestamps: `{report.temporal_gap_analysis.get('valid_timestamp_count', 0)}`",
        f"- Invalid or placeholder timestamps: `{report.temporal_gap_analysis.get('invalid_or_placeholder_timestamp_count', 0)}`",
        f"- First seen UTC: `{_md(report.temporal_gap_analysis.get('first_seen_utc') or 'none')}`",
        f"- Last seen UTC: `{_md(report.temporal_gap_analysis.get('last_seen_utc') or 'none')}`",
        f"- Largest gap seconds: `{report.temporal_gap_analysis.get('largest_gap_seconds', 0)}`",
        f"- Timestamp quality: `{_md(report.temporal_gap_analysis.get('timestamp_quality', 'unknown'))}`",
        "",
        _md(report.temporal_gap_analysis.get("interpretation", "Temporal gap analysis was not generated.")),
        "",
        "## Attack-Stage Timeline",
        "",
        f"- Stage count: `{report.attack_stage_timeline.get('stage_count', 0)}`",
        f"- Finding count: `{report.attack_stage_timeline.get('finding_count', 0)}`",
        f"- Limitation: {_md(report.attack_stage_timeline.get('limitation', 'Attack-stage timeline was not generated.'))}",
        "",
        ]
    )
    stages = report.attack_stage_timeline.get("stages", [])
    if isinstance(stages, list):
        for stage in stages[:25]:
            if not isinstance(stage, dict):
                continue
            lines.append(
                f"- `{_md(stage.get('stage', 'unknown'))}` "
                f"first `{_md(stage.get('first_seen_utc') or 'none')}` "
                f"last `{_md(stage.get('last_seen_utc') or 'none')}` "
                f"confidence `{float(stage.get('confidence', 0.0)):.2f}` "
                f"findings `{len(stage.get('finding_ids', [])) if isinstance(stage.get('finding_ids'), list) else 0}` "
                f"events `{len(stage.get('event_ids', [])) if isinstance(stage.get('event_ids'), list) else 0}`"
            )
        lines.append("")
    lines.extend(
        [
        "## Correlation Scope",
        "",
        f"- Input evidence: `{report.correlation_scope.get('input_evidence_count', 0)}` of limit `{report.correlation_scope.get('input_evidence_limit', 0)}`",
        f"- Correlatable evidence: `{report.correlation_scope.get('correlatable_evidence_count', 0)}`",
        f"- Source mix: `{_md(report.correlation_scope.get('source_mix', 'unknown'))}`",
        f"- Correlation mode: `{_md(report.correlation_scope.get('correlation_mode', 'unknown'))}`",
        f"- Normalized events: `{report.correlation_scope.get('normalized_event_count', 0)}`",
        f"- Analysis events: `{report.correlation_scope.get('analysis_event_count', 0)}`",
        f"- Participating evidence: `{', '.join(report.correlation_scope.get('participating_evidence_ids', []))}`",
        f"- Evidence without normalized events: `{', '.join(report.correlation_scope.get('evidence_without_normalized_events', []))}`",
        f"- Unsupported or unchecked evidence: `{', '.join(report.correlation_scope.get('unchecked_or_unsupported_evidence', []))}`",
        "",
        ]
    )
    memory_scope = report.correlation_scope.get("memory_plugin_scope", {})
    if isinstance(memory_scope, dict) and memory_scope:
        lines.extend(
            [
                "### Memory Plugin Scope",
                "",
                f"- Expected plugins: `{', '.join(memory_scope.get('expected_plugins', []))}`",
                f"- Successful plugins: `{', '.join(memory_scope.get('successful_plugins', []))}`",
                f"- Missing expected plugins: `{', '.join(memory_scope.get('missing_expected_plugins', []))}`",
                f"- Scope note: {_md(memory_scope.get('scope_note', ''))}",
                "",
            ]
        )
    lines.extend(["## Evidence-Supported Findings", ""])
    for finding in report.findings:
        lines.extend(
            [
                f"### {_md(finding.finding)}",
                "",
                f"- Finding ID: `{_md(finding.finding_id)}`",
                f"- Traceability: `{_md(finding.traceability_status)}`",
                f"- Confidence: `{finding.confidence:.2f}`",
                f"- Triage score: `{finding.triage_score:.2f}`",
                f"- Why suspicious: {_md('; '.join(finding.suspicion_reasons) or 'low-priority context')}",
                f"- Why flagged: {_md('; '.join(finding.explainability.why_flagged))}",
                f"- Confidence basis: `{', '.join(finding.explainability.confidence_basis)}`",
                f"- Limitations: {_md('; '.join(finding.explainability.limitations) or 'none recorded')}",
                f"- Evidence source: `{', '.join(finding.evidence_source)}`",
                f"- Source tool/parser: `{', '.join(finding.source_tool)} / {', '.join(finding.parser)}`",
                f"- Correlation path: `{', '.join(finding.correlation_path)}`",
                f"- Confidence modifiers: `{', '.join(finding.confidence_modifiers)}`",
                f"- Recovery notes: {_md('; '.join(finding.recovery_notes) or 'none')}",
                "",
                _md(finding.summary),
                "",
            ]
        )
    if not report.findings:
        lines.extend(
            [
                "No evidence-supported finding met the deterministic threshold in this report context.",
                "",
                "This is not a clean-memory conclusion. Review Coverage and Unknown Zones for missing plugins, failed tools, partial extraction, and unsupported sources before making an analyst verdict.",
                "",
            ]
        )

    lines.extend(["## Timeline", ""])
    for event in report.timeline:
        lines.append(
            f"- `{event.timestamp_utc}` `{event.event_id}` {_md(event.category)} "
            f"from `{_md(event.source_tool)}/{_md(event.parser)}` evidence `{_md(event.evidence_id)}`"
        )

    lines.extend(["", "## Coverage", ""])
    lines.append(f"- Overall case coverage: `{report.coverage.get('overall_case_coverage', 0.0):.2f}`")
    per_artifact = report.coverage.get("per_artifact", {})
    if isinstance(per_artifact, dict):
        for artifact, coverage in per_artifact.items():
            if isinstance(coverage, dict):
                lines.append(
                    f"- {_md(artifact)}: `{coverage.get('coverage', 0.0):.2f}` "
                    f"observed `{coverage.get('observed')}` expected `{coverage.get('expected')}`"
                )

    lines.extend(["", "## Unknown Zones", ""])
    for gap in report.unknown_zones:
        lines.append(f"- `{gap['severity']}` {_md(gap['source'])}: {_md(gap['impact'])}")

    lines.extend(["", "## Contradictions", ""])
    for contradiction in report.contradictions:
        lines.append(
            f"- `{contradiction['severity']}` {_md(contradiction['field'])}: "
            f"{_md(contradiction['reason'])}"
        )

    truth = report.truth_validation
    lines.extend(
        [
            "",
            "## Truth Validation",
            "",
            f"- Status: `{_md(truth.get('status', 'not_run'))}`",
            f"- Dataset: `{_md(truth.get('dataset_name') or 'none')}`",
            f"- Precision / recall / F1: `{float(truth.get('precision', 0.0)):.2f}` / `{float(truth.get('recall', 0.0)):.2f}` / `{float(truth.get('f1', 0.0)):.2f}`",
            f"- Matched / missed / unexpected findings: `{truth.get('matched_findings', 0)}` / `{truth.get('missed_findings', 0)}` / `{truth.get('unexpected_findings', 0)}`",
        ]
    )

    lines.extend(["", "## Self-Correction", "", f"```json\n{report.self_correction}\n```"])
    lines.extend(["", "## Evidence Credibility", ""])
    for item in report.evidence_credibility:
        lines.append(
            f"- `{item['evidence_id']}` `{item['evidence_type']}` `{item['trust_level']}` "
            f"events `{item['event_count']}`"
        )

    llm_verification = report.llm_report_verification
    lines.extend(
        [
            "",
            "## LLM Report Verification",
            "",
            f"- Status: `{_md(llm_verification.get('status', 'not_run'))}`",
            f"- Raw evidence sent: `{llm_verification.get('raw_evidence_sent', False)}`",
            f"- Raw tool output sent: `{llm_verification.get('raw_tool_output_sent', False)}`",
            f"- Invalid evidence references: `{llm_verification.get('invalid_evidence_reference_count', 0)}`",
            f"- Supported hypotheses without evidence: `{llm_verification.get('supported_hypotheses_without_evidence', 0)}`",
            "",
            _md(llm_verification.get("interpretation", "LLM report verification was not generated.")),
        ]
    )

    lines.extend(["", "## INFERRED Analyst Reasoning", "", f"```json\n{report.inferred_analyst_reasoning}\n```"])
    text = "\n".join(lines).rstrip() + "\n"
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return text


def _md(value: object) -> str:
    text = "" if value is None else str(value)
    text = escape(text, quote=False)
    return text.replace("\\", "\\\\").replace("`", "\\`").replace("|", "\\|")
