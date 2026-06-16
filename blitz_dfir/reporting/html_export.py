from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, select_autoescape

from blitz_dfir.reporting.report_builder import ReportDocument

HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Blitz DFIR Report - {{ report.case_id }}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 2rem; line-height: 1.45; color: #172026; }
    h1, h2 { color: #102030; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 1.25rem; }
    th, td { border: 1px solid #c8d0d8; padding: 0.45rem; text-align: left; vertical-align: top; }
    th { background: #eef2f5; }
    code { background: #eef2f5; padding: 0.1rem 0.2rem; }
    .section { margin-bottom: 1.5rem; }
  </style>
</head>
<body>
  <h1>Blitz DFIR Report</h1>
  <p><strong>Case:</strong> {{ report.case_id }}<br>
  <strong>Generated:</strong> {{ report.generated_at_utc }}<br>
  <strong>Audit trail:</strong> {{ report.audit_trail_reference }}</p>

  <div class="section">
    <h2>Trust Summary</h2>
    <p>Coverage {{ "%.0f"|format(report.coverage.overall_case_coverage * 100) }} percent; analysis gaps documented. Tool output is evidence candidate.</p>
    <p><strong>Global case trust:</strong> {{ "%.2f"|format(report.global_case_trust_score) }} |
    <strong>Parser consensus:</strong> {{ "%.2f"|format(report.parser_consensus_score) }} |
    <strong>Tool integrity:</strong> {{ report.tool_integrity_status }}</p>
  </div>

  <div class="section">
    <h2>Case Objective And Evidence Triage</h2>
    <p><strong>Objective:</strong> {{ report.case_objective.get("objective", "Evidence-first DFIR investigation") }}<br>
    <strong>Objective source:</strong> {{ report.case_objective.get("source", "default_evidence_first") }} |
    <strong>Planning mode:</strong> {{ report.investigation_plan.get("mode", "evidence_first") }} |
    <strong>Prioritized families:</strong> {{ report.investigation_plan.get("prioritized_artifact_families", [])|join(", ") }}</p>
    <p><strong>Prioritized evidence:</strong> {{ report.evidence_triage.get("prioritized_evidence_ids", [])|join(", ") }}</p>
    <p>The objective and triage plan guide work order only. Blitz findings still require manifest-verified evidence and typed tool output.</p>
  </div>

  <div class="section">
    <h2>Investigation Guidance</h2>
    <p><strong>Recommended tools:</strong> {{ report.investigation_guidance.get("recommended_tools", [])|join(", ") }}<br>
    <strong>Attack stages:</strong> {{ report.investigation_guidance.get("attack_stages", [])|join(", ") }}<br>
    <strong>Finding categories:</strong> {{ report.investigation_guidance.get("finding_categories", [])|join(", ") }}</p>
    <ul>
    {% for recommendation in report.investigation_guidance.get("recommendations", []) %}
      <li>{{ recommendation }}</li>
    {% else %}
      <li>No follow-up recommendation was generated because no finding or attack stage crossed the deterministic guidance rules.</li>
    {% endfor %}
    </ul>
  </div>

  <div class="section">
    <h2>Temporal Gap Analysis</h2>
    <table>
      <tbody>
        <tr><th>Events evaluated</th><td>{{ report.temporal_gap_analysis.get("event_count", 0) }}</td></tr>
        <tr><th>Valid timestamps</th><td>{{ report.temporal_gap_analysis.get("valid_timestamp_count", 0) }}</td></tr>
        <tr><th>Invalid or placeholder timestamps</th><td>{{ report.temporal_gap_analysis.get("invalid_or_placeholder_timestamp_count", 0) }}</td></tr>
        <tr><th>First seen UTC</th><td>{{ report.temporal_gap_analysis.get("first_seen_utc") or "none" }}</td></tr>
        <tr><th>Last seen UTC</th><td>{{ report.temporal_gap_analysis.get("last_seen_utc") or "none" }}</td></tr>
        <tr><th>Largest gap seconds</th><td>{{ report.temporal_gap_analysis.get("largest_gap_seconds", 0) }}</td></tr>
        <tr><th>Timestamp quality</th><td>{{ report.temporal_gap_analysis.get("timestamp_quality", "unknown") }}</td></tr>
      </tbody>
    </table>
    <p>{{ report.temporal_gap_analysis.get("interpretation", "Temporal gap analysis was not generated.") }}</p>
  </div>

  <div class="section">
    <h2>Attack-Stage Timeline</h2>
    <p>{{ report.attack_stage_timeline.get("limitation", "Attack-stage timeline was not generated.") }}</p>
    <table>
      <thead><tr><th>Stage</th><th>First Seen</th><th>Last Seen</th><th>Confidence</th><th>Findings</th><th>Events</th></tr></thead>
      <tbody>
      {% for stage in report.attack_stage_timeline.get("stages", [])[:25] %}
        <tr>
          <td>{{ stage.get("stage", "unknown") }}</td>
          <td>{{ stage.get("first_seen_utc") or "none" }}</td>
          <td>{{ stage.get("last_seen_utc") or "none" }}</td>
          <td>{{ "%.2f"|format(stage.get("confidence", 0.0)) }}</td>
          <td>{{ stage.get("finding_ids", [])|join(", ") }}</td>
          <td>{{ stage.get("event_ids", [])|length }}</td>
        </tr>
      {% else %}
        <tr><td colspan="6">No deterministic attack stage was inferred from the current evidence set.</td></tr>
      {% endfor %}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>Correlation Scope</h2>
    <table>
      <tbody>
        <tr><th>Input evidence</th><td>{{ report.correlation_scope.get("input_evidence_count", 0) }} of limit {{ report.correlation_scope.get("input_evidence_limit", 0) }}</td></tr>
        <tr><th>Correlatable evidence</th><td>{{ report.correlation_scope.get("correlatable_evidence_count", 0) }}</td></tr>
        <tr><th>Source mix</th><td>{{ report.correlation_scope.get("source_mix", "unknown") }}</td></tr>
        <tr><th>Correlation mode</th><td>{{ report.correlation_scope.get("correlation_mode", "unknown") }}</td></tr>
        <tr><th>Normalized / analysis events</th><td>{{ report.correlation_scope.get("normalized_event_count", 0) }} / {{ report.correlation_scope.get("analysis_event_count", 0) }}</td></tr>
        <tr><th>Participating evidence</th><td>{{ report.correlation_scope.get("participating_evidence_ids", [])|join(", ") }}</td></tr>
        <tr><th>Evidence without normalized events</th><td>{{ report.correlation_scope.get("evidence_without_normalized_events", [])|join(", ") }}</td></tr>
        <tr><th>Unsupported or unchecked evidence</th><td>{{ report.correlation_scope.get("unchecked_or_unsupported_evidence", [])|join(", ") }}</td></tr>
      </tbody>
    </table>
    {% set memory_scope = report.correlation_scope.get("memory_plugin_scope", {}) %}
    {% if memory_scope %}
    <h3>Memory Plugin Scope</h3>
    <table>
      <tbody>
        <tr><th>Expected plugins</th><td>{{ memory_scope.get("expected_plugins", [])|join(", ") }}</td></tr>
        <tr><th>Attempted plugins</th><td>{{ memory_scope.get("attempted_plugins", [])|join(", ") }}</td></tr>
        <tr><th>Successful plugins</th><td>{{ memory_scope.get("successful_plugins", [])|join(", ") }}</td></tr>
        <tr><th>Missing expected plugins</th><td>{{ memory_scope.get("missing_expected_plugins", [])|join(", ") }}</td></tr>
        <tr><th>Scope note</th><td>{{ memory_scope.get("scope_note", "") }}</td></tr>
      </tbody>
    </table>
    {% endif %}
  </div>

  <div class="section">
    <h2>Evidence-Supported Findings</h2>
    <table>
      <thead><tr><th>Finding</th><th>Priority</th><th>Explainability</th><th>Evidence</th><th>References</th><th>Recovery Notes</th></tr></thead>
      <tbody>
      {% for finding in report.findings %}
        <tr>
          <td><code>{{ finding.finding_id }}</code><br>{{ finding.finding }}<br>{{ finding.summary }}</td>
          <td>Confidence {{ "%.2f"|format(finding.confidence) }}<br>Triage {{ "%.2f"|format(finding.triage_score) }}<br>Traceability {{ finding.traceability_status }}<br>{{ finding.confidence_modifiers|join(", ") }}</td>
          <td>
            <strong>Why flagged</strong><br>
            {% for reason in finding.explainability.why_flagged %}{{ reason }}<br>{% else %}low-priority context{% endfor %}
            <strong>Confidence basis</strong><br>
            {% for basis in finding.explainability.confidence_basis %}{{ basis }}<br>{% endfor %}
            <strong>Limitations</strong><br>
            {% for limit in finding.explainability.limitations %}{{ limit }}<br>{% else %}none recorded{% endfor %}
          </td>
          <td>{{ finding.evidence_source|join(", ") }}<br>{{ finding.source_tool|join(", ") }} / {{ finding.parser|join(", ") }}</td>
          <td>{% for ref in finding.evidence_references %}<code>{{ ref.event_id }}</code> {{ ref.raw_reference }}<br>{% endfor %}</td>
          <td>{{ finding.recovery_notes|join("; ") }}</td>
        </tr>
      {% else %}
        <tr>
          <td colspan="6">No evidence-supported finding met the deterministic threshold in this report context. This is not a clean-memory conclusion; review Coverage and Unknown Zones for missing plugins, failed tools, partial extraction, and unsupported sources before making an analyst verdict.</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>Timeline</h2>
    <table>
      <thead><tr><th>Timestamp</th><th>Category</th><th>Event</th><th>Source</th><th>Trust</th></tr></thead>
      <tbody>
      {% for event in report.timeline %}
        <tr><td>{{ event.timestamp_utc }}</td><td>{{ event.category }}</td><td><code>{{ event.event_id }}</code></td><td>{{ event.source_tool }}/{{ event.parser }} {{ event.evidence_id }}</td><td>{{ event.trust_level }}</td></tr>
      {% endfor %}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>Coverage And Unknown Zones</h2>
    <table>
      <thead><tr><th>Artifact</th><th>Coverage</th><th>Observed</th><th>Expected</th><th>Missing</th></tr></thead>
      <tbody>
      {% for artifact, coverage in report.coverage.per_artifact.items() %}
        <tr><td>{{ artifact }}</td><td>{{ "%.2f"|format(coverage.coverage) }}</td><td>{{ coverage.observed }}</td><td>{{ coverage.expected }}</td><td>{{ coverage.missing_sources|join(", ") }}</td></tr>
      {% endfor %}
      </tbody>
    </table>
    <ul>{% for gap in report.unknown_zones %}<li>{{ gap.severity }}: {{ gap.source }} - {{ gap.impact }}</li>{% endfor %}</ul>
  </div>

  <div class="section">
    <h2>Cross-Validation And Corrections</h2>
    <p>{{ report.cross_validation }}</p>
    <p>{{ report.self_correction }}</p>
  </div>

  <div class="section">
    <h2>Truth Validation</h2>
    <table>
      <tbody>
        <tr><th>Status</th><td>{{ report.truth_validation.get("status", "not_run") }}</td></tr>
        <tr><th>Dataset</th><td>{{ report.truth_validation.get("dataset_name") or "none" }}</td></tr>
        <tr><th>Precision / recall / F1</th><td>{{ "%.2f"|format(report.truth_validation.get("precision", 0.0)) }} / {{ "%.2f"|format(report.truth_validation.get("recall", 0.0)) }} / {{ "%.2f"|format(report.truth_validation.get("f1", 0.0)) }}</td></tr>
        <tr><th>Matched / missed / unexpected findings</th><td>{{ report.truth_validation.get("matched_findings", 0) }} / {{ report.truth_validation.get("missed_findings", 0) }} / {{ report.truth_validation.get("unexpected_findings", 0) }}</td></tr>
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>LLM Report Verification</h2>
    <table>
      <tbody>
        <tr><th>Status</th><td>{{ report.llm_report_verification.get("status", "not_run") }}</td></tr>
        <tr><th>Raw evidence sent</th><td>{{ report.llm_report_verification.get("raw_evidence_sent", false) }}</td></tr>
        <tr><th>Raw tool output sent</th><td>{{ report.llm_report_verification.get("raw_tool_output_sent", false) }}</td></tr>
        <tr><th>Invalid evidence references</th><td>{{ report.llm_report_verification.get("invalid_evidence_reference_count", 0) }}</td></tr>
        <tr><th>Supported hypotheses without evidence</th><td>{{ report.llm_report_verification.get("supported_hypotheses_without_evidence", 0) }}</td></tr>
      </tbody>
    </table>
    <p>{{ report.llm_report_verification.get("interpretation", "LLM report verification was not generated.") }}</p>
  </div>

  <div class="section">
    <h2>INFERRED Analyst Reasoning</h2>
    <p>{{ report.inferred_analyst_reasoning }}</p>
  </div>
</body>
</html>
"""


def render_html_report(report: ReportDocument, path: Path | None = None) -> str:
    env = Environment(autoescape=select_autoescape(default=True, default_for_string=True))
    template = env.from_string(HTML_TEMPLATE)
    html = template.render(report=report)
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html, encoding="utf-8")
    return html
