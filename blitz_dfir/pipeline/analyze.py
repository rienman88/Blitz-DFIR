from __future__ import annotations

import csv
import json
import os
import sqlite3
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from blitz_dfir.accounting.event_store import build_full_accounting
from blitz_dfir.accounting.models import FullAccountingSummary
from blitz_dfir.artifacts.windows_profiles import (
    log2timeline_parsers_for_profile,
    normalize_windows_artifact_profile,
    psort_filter_for_profile,
)
from blitz_dfir.audit.audit_log import AuditLogger
from blitz_dfir.audit.progress import progress_heartbeat, write_progress_state
from blitz_dfir.audit.session_integrity import write_artifact_manifest, write_session_state
from blitz_dfir.batching.models import BatchTask as PlannedBatchTask
from blitz_dfir.batching.planner import DEFAULT_MEMORY_TRIAGE_PLUGINS, build_batch_plan
from blitz_dfir.core.integrity import sha256_file
from blitz_dfir.core.manifest import dump_manifest_summary, load_manifest
from blitz_dfir.core.models import (
    EvidenceCategory,
    EvidenceManifest,
    EvidenceRecord,
    EvidenceType,
    MAX_MANIFEST_EVIDENCE_INPUTS,
    NormalizedEvent,
    Pipeline,
    SignalWarning,
    TrustTier,
)
from blitz_dfir.core.normalization import normalize_parsed_record, normalize_parser_results, sort_normalized_events
from blitz_dfir.core.session import CaseSession, create_session, load_existing_session
from blitz_dfir.correction.bounded_retry import execute_bounded_corrections
from blitz_dfir.correction.triggers import triggers_from_validation
from blitz_dfir.correction.validator import downgrade_unverified_findings, validate_case_outputs
from blitz_dfir.correlation.attack_chain import infer_attack_stages
from blitz_dfir.correlation.confidence import assess_confidence, detect_contradictions
from blitz_dfir.correlation.contradiction_analysis import (
    apply_contradiction_penalties,
    build_contradiction_analysis_report,
    export_contradiction_analysis_report,
    render_contradiction_analysis_markdown,
)
from blitz_dfir.correlation.evidentiary_weighting import (
    build_evidentiary_weighting_report,
    export_evidentiary_weighting_report,
    render_evidentiary_weighting_markdown,
)
from blitz_dfir.correlation.lineage import build_process_lineage
from blitz_dfir.correlation.models import (
    Contradiction,
    CorrelatedFinding,
    ProcessLineageLink,
    stable_correlation_id,
)
from blitz_dfir.correlation.persistence import detect_persistence
from blitz_dfir.correlation.sqlite_backend import correlate_normalized_events_sqlite
from blitz_dfir.correlation.timeline import stitch_events
from blitz_dfir.correlation.triage import assess_group_suspicion
from blitz_dfir.exceptions import BlitzError
from blitz_dfir.inventory.object_inventory import build_object_inventory_report
from blitz_dfir.inventory.report import build_inventory_report
from blitz_dfir.inventory.tool_discovery import discover_tools
from blitz_dfir.mcp.default_tools import build_default_tool_registry
from blitz_dfir.mcp.dispatcher import ToolDispatcher
from blitz_dfir.parsers.common import make_record
from blitz_dfir.parsers.disk_triage_parser import (
    disk_triage_payload_warnings,
    iter_disk_triage_records,
    load_disk_triage_payload,
    parse_disk_triage_file,
    parse_disk_triage_json,
)
from blitz_dfir.parsers.evtx_parser import parse_evtx_json
from blitz_dfir.parsers.models import ParserResult
from blitz_dfir.parsers.pcap_parser import parse_pcap_json
from blitz_dfir.parsers.plaso_parser import parse_plaso_csv_file
from blitz_dfir.parsers.strings_parser import parse_strings_output
from blitz_dfir.parsers.volatility_parser import parse_volatility_json
from blitz_dfir.parsers.yara_parser import parse_yara_output
from blitz_dfir.planning.evidence_first import (
    build_case_objective,
    build_evidence_triage,
    build_investigation_plan,
    export_case_objective,
    export_evidence_triage,
    export_investigation_plan,
    render_case_objective_markdown,
    render_evidence_triage_markdown,
    render_investigation_plan_markdown,
)
from blitz_dfir.investigation.findings_guidance import build_investigation_guidance
from blitz_dfir.reasoning.analyst import build_reasoning_context, run_analyst_reasoning
from blitz_dfir.reasoning.models import ReasoningResult
from blitz_dfir.reasoning.provider import OpenAICompatibleProvider, ReasoningProviderError, provider_config_from_env
from blitz_dfir.reasoning.verification import (
    build_llm_report_verification,
    export_llm_report_verification,
    render_llm_report_verification_markdown,
)
from blitz_dfir.recovery.planner import build_recovery_plan
from blitz_dfir.reporting.evidence_maturity import (
    build_evidence_maturity_report,
    export_evidence_maturity_report,
    render_evidence_maturity_markdown,
)
from blitz_dfir.reporting.agent_trace import build_agent_trace, export_agent_trace, render_agent_journal
from blitz_dfir.reporting.collated_outputs import render_collated_audit, write_collated_outputs
from blitz_dfir.reporting.html_export import render_html_report
from blitz_dfir.reporting.markdown_export import render_markdown_report
from blitz_dfir.reporting.provenance_visualization import render_finding_provenance_markdown
from blitz_dfir.reporting.report_builder import build_report_document, export_json_report
from blitz_dfir.sanitization.sanitizer import event_cap_warning, get_max_events
from blitz_dfir.signal.coverage import coverage_report_from_expected_artifacts, expected_artifact_key
from blitz_dfir.signal.integrity import (
    SignalIntegrityReport,
    confidence_penalty_from_warnings,
    decode_with_signal,
    summarize_signal_integrity,
)
from blitz_dfir.signal.warnings import make_warning, parser_crash_warning
from blitz_dfir.stress.report import build_stress_report
from blitz_dfir.temporal.analysis import (
    build_attack_stage_timeline,
    build_temporal_gap_analysis,
    export_attack_stage_timeline,
    export_temporal_gap_analysis,
    render_attack_stage_timeline_markdown,
    render_temporal_gap_markdown,
)
from blitz_dfir.tools.config import load_tool_config
from blitz_dfir.unknowns.engine import build_unknowns_report


DEFAULT_NORMALIZED_EXPORT_LIMIT = 10_000
DEFAULT_PARSER_RECORD_EXPORT_LIMIT = 1_000


@dataclass(frozen=True)
class AnalyzeResult:
    case_id: str
    session_id: str
    session_root: Path
    audit_log_path: Path
    session_state_path: Path
    progress_state_path: Path
    artifact_manifest_path: Path
    report_json_path: Path
    report_markdown_path: Path
    report_html_path: Path
    normalized_events_path: Path
    tool_results_path: Path
    parser_results_path: Path
    case_objective_path: Path
    investigation_plan_path: Path
    evidence_triage_path: Path
    case_objective_markdown_path: Path
    investigation_plan_markdown_path: Path
    evidence_triage_markdown_path: Path
    batch_plan_path: Path
    tool_discovery_path: Path
    evidence_inventory_path: Path
    recovery_plan_path: Path
    object_inventory_path: Path
    full_accounting_path: Path
    event_store_path: Path
    unknowns_path: Path
    stress_report_path: Path
    evidentiary_weighting_path: Path
    contradiction_analysis_path: Path
    temporal_gap_analysis_path: Path
    attack_stage_timeline_path: Path
    llm_report_verification_path: Path
    validation_path: Path
    evidence_maturity_path: Path
    evidentiary_weighting_markdown_path: Path
    contradiction_analysis_markdown_path: Path
    temporal_gap_analysis_markdown_path: Path
    attack_stage_timeline_markdown_path: Path
    llm_report_verification_markdown_path: Path
    investigation_guidance_path: Path
    evidence_maturity_markdown_path: Path
    finding_provenance_markdown_path: Path
    agent_trace_path: Path
    agent_journal_path: Path
    overall_findings_path: Path
    overall_reports_path: Path
    collated_audit_path: Path
    event_count: int
    finding_count: int
    warning_count: int
    validation_passed: bool
    reasoning_enabled: bool


@dataclass(frozen=True)
class ToolTask:
    tool: str
    evidence_id: str
    params: dict[str, Any]


@dataclass(frozen=True)
class SQLiteNormalizationResult:
    events: tuple[NormalizedEvent, ...]
    warnings: tuple[SignalWarning, ...]
    processed_count: int
    truncated: bool
    store_path: Path
    table_name: str = "normalized_events"
    analysis_event_memory_limit: int | None = None


@dataclass(frozen=True)
class BoundedReasoningOutcome:
    reasoning: ReasoningResult | None
    enabled: bool
    status: Literal["completed", "skipped", "provider_failed"]
    reason: str
    details: dict[str, Any]


def run_analysis(
    *,
    manifest_path: Path,
    mode: str = "timeline",
    tool_config_path: Path = Path("config/tools.yaml"),
    enable_reasoning: bool = False,
    psort_profile: str = "triage",
    tool_timeout_seconds: int | None = None,
    psort_filter: str | None = None,
    psort_slice: str | None = None,
    psort_slice_size: int | None = None,
    resume_session_path: Path | None = None,
    full_sql_correlation: bool = False,
    case_objective: str | None = None,
    progress: Callable[[str, dict[str, Any] | None], None] | None = None,
) -> AnalyzeResult:
    if mode != "timeline":
        raise ValueError(f"unsupported analysis mode: {mode}")
    if psort_profile not in {"triage", "full"}:
        raise ValueError(f"unsupported psort profile: {psort_profile}")
    if tool_timeout_seconds is not None and (tool_timeout_seconds < 1 or tool_timeout_seconds > 7200):
        raise ValueError("tool_timeout_seconds must be between 1 and 7200")
    if psort_slice_size is not None and (psort_slice_size < 1 or psort_slice_size > 1440):
        raise ValueError("psort_slice_size must be between 1 and 1440")
    findings_before_contradiction_penalty: tuple[CorrelatedFinding, ...]
    if full_sql_correlation:
        os.environ["BLITZ_SQLITE_NORMALIZATION"] = "1"

    manifest = load_manifest(manifest_path)
    resuming = resume_session_path is not None
    session = load_existing_session(manifest, resume_session_path) if resume_session_path else create_session(manifest)
    _write_run_bundle_session_pointer(session)
    tool_results_path = session.findings_dir / "tool_results.json"
    parser_results_path = session.findings_dir / "parser_results.json"
    case_objective_path = session.findings_dir / "case_objective.json"
    investigation_plan_path = session.findings_dir / "investigation_plan.json"
    evidence_triage_path = session.findings_dir / "evidence_triage.json"
    batch_plan_path = session.findings_dir / "batch_plan.json"
    tool_discovery_path = session.findings_dir / "tool_discovery.json"
    evidence_inventory_path = session.findings_dir / "evidence_inventory.json"
    recovery_plan_path = session.findings_dir / "recovery_plan.json"
    object_inventory_path = session.findings_dir / "object_inventory.json"
    artifact_manifest_path = session.findings_dir / "artifact_manifest.json"
    full_accounting_path = session.findings_dir / "full_accounting.json"
    event_store_path = session.findings_dir / "event_store.sqlite"
    unknowns_path = session.findings_dir / "unknowns.json"
    stress_report_path = session.findings_dir / "stress_report.json"
    evidentiary_weighting_path = session.findings_dir / "evidentiary_weighting.json"
    investigation_guidance_path = session.findings_dir / "investigation_guidance.json"
    contradiction_analysis_path = session.findings_dir / "contradiction_analysis.json"
    temporal_gap_analysis_path = session.findings_dir / "temporal_gap_analysis.json"
    attack_stage_timeline_path = session.findings_dir / "attack_stage_timeline.json"
    llm_report_verification_path = session.findings_dir / "llm_report_verification.json"
    evidence_maturity_path = session.findings_dir / "evidence_maturity.json"
    agent_trace_path = session.findings_dir / "agent_trace.json"
    normalized_events_path = session.findings_dir / "normalized_events.json"
    validation_path = session.findings_dir / "validation.json"
    coverage_path = session.findings_dir / "coverage.json"
    signal_path = session.findings_dir / "signal_integrity.json"
    correction_path = session.findings_dir / "correction_history.json"
    report_json_path = session.reports_dir / "report.json"
    report_markdown_path = session.reports_dir / "report.md"
    report_html_path = session.reports_dir / "report.html"
    case_objective_markdown_path = session.reports_dir / "case_objective.md"
    investigation_plan_markdown_path = session.reports_dir / "investigation_plan.md"
    evidence_triage_markdown_path = session.reports_dir / "evidence_triage.md"
    evidentiary_weighting_markdown_path = session.reports_dir / "evidentiary_weighting.md"
    contradiction_analysis_markdown_path = session.reports_dir / "contradiction_analysis.md"
    temporal_gap_analysis_markdown_path = session.reports_dir / "temporal_gap_analysis.md"
    attack_stage_timeline_markdown_path = session.reports_dir / "attack_stage_timeline.md"
    llm_report_verification_markdown_path = session.reports_dir / "llm_report_verification.md"
    evidence_maturity_markdown_path = session.reports_dir / "evidence_maturity.md"
    finding_provenance_markdown_path = session.reports_dir / "finding_provenance.md"
    agent_journal_path = session.reports_dir / "agent_journal.md"
    overall_findings_path = session.findings_dir / "overall_findings.md"
    overall_reports_path = session.reports_dir / "overall_reports.md"
    collated_audit_path = session.audit_dir / "collated_audit.md"
    _progress(
        progress,
        "Manifest loaded" if not resuming else "Manifest loaded for resume",
        {
            "case_id": manifest.case_id,
            "evidence_count": len(manifest.evidence),
            "session_id": session.session_id,
        },
    )
    audit = AuditLogger(
        session.audit_log_path,
        session_id=session.session_id,
        case_id=manifest.case_id,
    )
    session_state_path = write_session_state(
        session=session,
        status="RUNNING",
        phase="manifest_integrity_completed" if not resuming else "resume_started",
        details={
            "manifest": str(manifest.source_path),
            "resume": resuming,
            "evidence_count": len(manifest.evidence),
        },
    )
    if resuming:
        audit.append(
            "analysis_resumed",
            {
                "manifest": str(manifest.source_path),
                "resume_session": str(session.session_root),
                "max_normalized_events": _configured_max_events(),
            },
        )
    else:
        _audit_foundation(audit, manifest, session, mode)

    progress_state_path = write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="manifest_integrity",
        layer_status="COMPLETED",
        details={
            "manifest": str(manifest.source_path),
            "evidence_count": len(manifest.evidence),
            "resume": resuming,
        },
    )

    protocol_sift_context = _protocol_sift_context()
    audit.append("protocol_sift_workflow_recorded", protocol_sift_context)
    windows_artifact_profile = normalize_windows_artifact_profile(None)
    audit.append(
        "windows_artifact_profile_configured",
        {
            "profile": windows_artifact_profile,
            "log2timeline_parsers": log2timeline_parsers_for_profile(windows_artifact_profile) or "default",
            "psort_filter": psort_filter or psort_filter_for_profile(windows_artifact_profile) or "default",
        },
    )
    write_session_state(
        session=session,
        status="RUNNING",
        phase="protocol_sift_workflow_recorded",
        details=protocol_sift_context,
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="protocol_sift_workflow",
        layer_status="COMPLETED",
        details=protocol_sift_context,
    )
    _progress(progress, "Protocol SIFT workflow context recorded", protocol_sift_context)

    case_objective_report = build_case_objective(manifest=manifest, objective_text=case_objective)
    export_case_objective(case_objective_report, case_objective_path)
    render_case_objective_markdown(case_objective_report, case_objective_markdown_path)
    audit.append(
        "case_objective_defined",
        {
            "objective_source": case_objective_report.source,
            "evidence_count": len(case_objective_report.evidence_ids_in_scope),
            "success_criteria_count": len(case_objective_report.success_criteria),
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="case_objective",
        layer_status="COMPLETED",
        details={
            "source": case_objective_report.source,
            "evidence_count": len(case_objective_report.evidence_ids_in_scope),
            "artifact": str(case_objective_path),
        },
    )
    _progress(
        progress,
        "Case objective defined",
        {
            "source": case_objective_report.source,
            "evidence_count": len(case_objective_report.evidence_ids_in_scope),
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="tool_discovery",
        layer_status="RUNNING",
        details={"tool_config": str(tool_config_path)},
    )
    write_session_state(
        session=session,
        status="RUNNING",
        phase="tool_discovery_started",
        details={"tool_config": str(tool_config_path)},
    )
    tool_config = load_tool_config(tool_config_path)
    tool_discovery = discover_tools(tool_config)
    _write_json(tool_discovery_path, tool_discovery.model_dump(mode="json"))
    audit.append(
        "tool_discovery_completed",
        {
            "tool_count": tool_discovery.tool_count,
            "available_count": tool_discovery.available_count,
            "missing_count": tool_discovery.missing_count,
            "hash_mismatch_count": tool_discovery.hash_mismatch_count,
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="tool_discovery",
        layer_status="COMPLETED",
        details={
            "tool_count": tool_discovery.tool_count,
            "available_tools": tool_discovery.available_count,
            "missing_tools": tool_discovery.missing_count,
            "hash_mismatch_count": tool_discovery.hash_mismatch_count,
        },
    )
    write_session_state(
        session=session,
        status="RUNNING",
        phase="tool_discovery_completed",
        details={
            "tool_count": tool_discovery.tool_count,
            "available_tools": tool_discovery.available_count,
            "missing_tools": tool_discovery.missing_count,
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="investigation_planning",
        layer_status="RUNNING",
        details={
            "evidence_count": len(manifest.evidence),
            "objective_source": case_objective_report.source,
        },
    )
    write_session_state(
        session=session,
        status="RUNNING",
        phase="investigation_planning_started",
        details={"evidence_count": len(manifest.evidence)},
    )
    investigation_plan = build_investigation_plan(
        manifest=manifest,
        objective=case_objective_report,
        tool_discovery=tool_discovery,
    )
    export_investigation_plan(investigation_plan, investigation_plan_path)
    render_investigation_plan_markdown(investigation_plan, investigation_plan_markdown_path)
    audit.append(
        "investigation_plan_completed",
        {
            "mode": investigation_plan.mode,
            "prioritized_artifact_families": investigation_plan.prioritized_artifact_families,
            "phase_count": len(investigation_plan.phases),
            "evidence_ids_in_scope": investigation_plan.evidence_ids_in_scope,
            "limitation_count": len(investigation_plan.limitations),
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="investigation_planning",
        layer_status="COMPLETED",
        details={
            "mode": investigation_plan.mode,
            "prioritized_artifact_families": investigation_plan.prioritized_artifact_families,
            "phase_count": len(investigation_plan.phases),
            "limitation_count": len(investigation_plan.limitations),
            "artifact": str(investigation_plan_path),
        },
    )
    write_session_state(
        session=session,
        status="RUNNING",
        phase="investigation_planning_completed",
        details={
            "phase_count": len(investigation_plan.phases),
            "prioritized_artifact_families": investigation_plan.prioritized_artifact_families,
        },
    )
    _progress(
        progress,
        "Investigation plan completed",
        {
            "families": ",".join(investigation_plan.prioritized_artifact_families),
            "phases": len(investigation_plan.phases),
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="batch_planning",
        layer_status="RUNNING",
        details={"mode": mode, "evidence_count": len(manifest.evidence)},
    )
    write_session_state(
        session=session,
        status="RUNNING",
        phase="batch_planning_started",
        details={"mode": mode, "evidence_count": len(manifest.evidence)},
    )
    batch_plan = build_batch_plan(
        manifest=manifest,
        mode=mode,
        psort_profile=psort_profile,
        tool_timeout_seconds=tool_timeout_seconds,
        psort_filter=psort_filter,
        psort_slice=psort_slice,
        psort_slice_size=psort_slice_size,
        prioritized_artifact_families=investigation_plan.prioritized_artifact_families,
        triage_context=investigation_plan.mode,
    )
    _write_json(batch_plan_path, batch_plan.model_dump(mode="json"))
    audit.append(
        "batch_plan_created",
        {
            "batch_count": batch_plan.batch_count,
            "task_count": batch_plan.task_count,
            "batches": [batch.batch_id for batch in batch_plan.batches],
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="batch_planning",
        layer_status="COMPLETED",
        details={
            "batch_count": batch_plan.batch_count,
            "task_count": batch_plan.task_count,
            "batches": [batch.batch_id for batch in batch_plan.batches],
        },
    )
    write_session_state(
        session=session,
        status="RUNNING",
        phase="batch_planning_completed",
        details={"batch_count": batch_plan.batch_count, "task_count": batch_plan.task_count},
    )
    _progress(
        progress,
        "Batch plan created",
        {"batches": batch_plan.batch_count, "tasks": batch_plan.task_count},
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="evidence_inventory",
        layer_status="RUNNING",
        details={"evidence_count": len(manifest.evidence)},
    )
    write_session_state(
        session=session,
        status="RUNNING",
        phase="evidence_inventory_started",
        details={"evidence_count": len(manifest.evidence)},
    )
    inventory_report = build_inventory_report(
        manifest=manifest,
        batch_plan=batch_plan,
        tool_discovery=tool_discovery,
    )
    _write_json(evidence_inventory_path, inventory_report.model_dump(mode="json"))
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="evidence_inventory",
        layer_status="COMPLETED",
        details={
            "evidence_count": inventory_report.evidence_count,
            "high_or_critical_risk_count": inventory_report.high_or_critical_risk_count,
            "unavailable_tool_count": inventory_report.unavailable_tool_count,
        },
    )
    write_session_state(
        session=session,
        status="RUNNING",
        phase="evidence_inventory_completed",
        details={
            "evidence_count": inventory_report.evidence_count,
            "high_or_critical_risk_count": inventory_report.high_or_critical_risk_count,
            "unavailable_tool_count": inventory_report.unavailable_tool_count,
        },
    )
    audit.append(
        "evidence_inventory_completed",
        {
            "evidence_count": inventory_report.evidence_count,
            "high_or_critical_risk_count": inventory_report.high_or_critical_risk_count,
            "unavailable_tool_count": inventory_report.unavailable_tool_count,
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="recovery_planning",
        layer_status="RUNNING",
        details={"evidence_count": inventory_report.evidence_count},
    )
    write_session_state(
        session=session,
        status="RUNNING",
        phase="recovery_planning_started",
        details={"evidence_count": inventory_report.evidence_count},
    )
    recovery_plan = build_recovery_plan(
        manifest=manifest,
        batch_plan=batch_plan,
        tool_discovery=tool_discovery,
    )
    _write_json(recovery_plan_path, recovery_plan.model_dump(mode="json"))
    audit.append(
        "recovery_plan_created",
        {
            "evidence_count": recovery_plan.evidence_count,
            "candidate_count": recovery_plan.candidate_count,
            "auto_runnable_candidate_count": recovery_plan.auto_runnable_candidate_count,
            "blocked_candidate_count": recovery_plan.blocked_candidate_count,
            "sequential_execution_required": recovery_plan.sequential_execution_required,
        },
    )
    write_session_state(
        session=session,
        status="RUNNING",
        phase="recovery_plan_created",
        details={
            "batch_count": batch_plan.batch_count,
            "task_count": batch_plan.task_count,
            "recovery_candidates": recovery_plan.candidate_count,
            "blocked_recovery_candidates": recovery_plan.blocked_candidate_count,
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="recovery_planning",
        layer_status="COMPLETED",
        details={
            "recovery_candidates": recovery_plan.candidate_count,
            "auto_runnable_candidate_count": recovery_plan.auto_runnable_candidate_count,
            "blocked_recovery_candidates": recovery_plan.blocked_candidate_count,
            "sequential_execution_required": recovery_plan.sequential_execution_required,
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="evidence_triage",
        layer_status="RUNNING",
        details={
            "evidence_count": inventory_report.evidence_count,
            "blocked_recovery_candidates": recovery_plan.blocked_candidate_count,
        },
    )
    evidence_triage = build_evidence_triage(
        manifest=manifest,
        objective=case_objective_report,
        inventory=inventory_report,
        recovery=recovery_plan,
        investigation_plan=investigation_plan,
    )
    export_evidence_triage(evidence_triage, evidence_triage_path)
    render_evidence_triage_markdown(evidence_triage, evidence_triage_markdown_path)
    audit.append(
        "evidence_triage_completed",
        {
            "evidence_count": evidence_triage.evidence_count,
            "critical_count": evidence_triage.critical_count,
            "high_count": evidence_triage.high_count,
            "medium_count": evidence_triage.medium_count,
            "low_count": evidence_triage.low_count,
            "prioritized_evidence_ids": evidence_triage.prioritized_evidence_ids,
        },
    )
    write_session_state(
        session=session,
        status="RUNNING",
        phase="evidence_triage_completed",
        details={
            "evidence_count": evidence_triage.evidence_count,
            "critical_count": evidence_triage.critical_count,
            "high_count": evidence_triage.high_count,
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="evidence_triage",
        layer_status="COMPLETED",
        details={
            "evidence_count": evidence_triage.evidence_count,
            "critical_count": evidence_triage.critical_count,
            "high_count": evidence_triage.high_count,
            "artifact": str(evidence_triage_path),
        },
    )
    _progress(
        progress,
        "Evidence triage completed",
        {
            "evidence": evidence_triage.evidence_count,
            "critical": evidence_triage.critical_count,
            "high": evidence_triage.high_count,
        },
    )
    all_evidence: list[EvidenceRecord] = list(manifest.evidence)
    parser_results: list[ParserResult] = []
    tool_results: list[dict[str, Any]] = []
    extra_warnings: list[SignalWarning] = []
    completed_tool_tasks = 0

    if resuming:
        write_progress_state(
            session=session,
            status="RUNNING",
            current_layer="typed_tool_execution",
            layer_status="RUNNING",
            details={"mode": "resume", "action": "loading prior typed tool results"},
        )
        tool_results = _load_tool_results_checkpoint(session)
        if not tool_results:
            raise ValueError(
                "resume requires findings/tool_results.json or recoverable analysis_tool_result audit entries"
            )
        audit.append(
            "resume_tool_results_loaded",
            {
                "tool_result_count": len(tool_results),
                "source": str(tool_results_path if tool_results_path.exists() else session.audit_log_path),
            },
        )
        _progress(progress, "Resume tool results loaded", {"tool_results": len(tool_results)})
        for checkpoint_result in tool_results:
            evidence_id = str(checkpoint_result.get("evidence_id") or "")
            evidence = _evidence_by_id(all_evidence, evidence_id)
            if evidence is None:
                audit.append(
                    "resume_tool_result_skipped",
                    {"evidence_id": evidence_id, "reason": "evidence_not_registered"},
                )
                continue
            parsed = _parse_tool_result(checkpoint_result, evidence, session, extra_warnings=extra_warnings)
            if parsed is not None:
                parser_results.append(parsed)
                audit.append("parser_completed", _parser_summary(parsed))
        _write_json(parser_results_path, _serializable_parser_results(parser_results))
        write_progress_state(
            session=session,
            status="RUNNING",
            current_layer="typed_tool_execution",
            layer_status="COMPLETED",
            details={"mode": "resume", "tool_results_reused": len(tool_results)},
        )

    if not resuming:
        write_progress_state(
            session=session,
            status="RUNNING",
            current_layer="typed_tool_execution",
            layer_status="RUNNING",
            details={"batch_count": batch_plan.batch_count, "task_count": batch_plan.task_count},
            processed_items=0,
            total_items=max(batch_plan.task_count, 1),
        )
    for batch in (() if resuming else batch_plan.batches):
        audit.append(
            "batch_started",
            {
                "batch_id": batch.batch_id,
                "artifact_family": batch.artifact_family,
                "task_count": len(batch.tasks),
                "max_parallel_tools": batch.resource_policy.max_parallel_tools,
            },
        )
        _progress(
            progress,
            "Batch started",
            {"batch_id": batch.batch_id, "family": batch.artifact_family, "tasks": len(batch.tasks)},
        )
        batch_tool_count = 0
        batch_parser_count = 0
        for planned_task in batch.tasks:
            evidence = _evidence_by_id(all_evidence, planned_task.evidence_id)
            if evidence is None:
                completed_tool_tasks += 1
                audit.append(
                    "batch_task_skipped",
                    {
                        "batch_id": batch.batch_id,
                        "task_id": planned_task.task_id,
                        "reason": "evidence_not_registered",
                    },
                )
                continue
            _progress(
                progress,
                "Evidence queued",
                {"evidence_id": evidence.evidence_id, "type": evidence.evidence_type.value},
            )
            if planned_task.status == "SKIPPED" or planned_task.tool == "unsupported":
                completed_tool_tasks += 1
                audit.append(
                    "batch_task_skipped",
                    {
                        "batch_id": batch.batch_id,
                        "task_id": planned_task.task_id,
                        "reason": planned_task.rationale,
                    },
                )
                continue
            if planned_task.tool == "direct_parse":
                direct = _parse_direct_processed_evidence(evidence, extra_warnings=extra_warnings)
                if direct is not None:
                    parser_results.append(direct)
                    batch_parser_count += 1
                    audit.append("parser_completed", _parser_summary(direct))
                completed_tool_tasks += 1
                write_progress_state(
                    session=session,
                    status="RUNNING",
                    current_layer="typed_tool_execution",
                    layer_status="RUNNING",
                    details={
                        "batch_id": batch.batch_id,
                        "last_task": planned_task.task_id,
                        "last_tool": planned_task.tool,
                    },
                    processed_items=completed_tool_tasks,
                    total_items=max(batch_plan.task_count, 1),
                )
                continue
            task = _planned_to_tool_task(planned_task)
            write_progress_state(
                session=session,
                status="RUNNING",
                current_layer="typed_tool_execution",
                layer_status="RUNNING",
                details={
                    "batch_id": batch.batch_id,
                    "active_task": planned_task.task_id,
                    "active_tool": task.tool,
                    "evidence_id": evidence.evidence_id,
                },
                processed_items=completed_tool_tasks,
                total_items=max(batch_plan.task_count, 1),
            )
            maybe_tool_result = _dispatch_tool_task(
                manifest=manifest,
                session=session,
                audit=audit,
                tool_config=tool_config,
                task=task,
                extra_warnings=extra_warnings,
                progress=progress,
            )
            if maybe_tool_result is None:
                completed_tool_tasks += 1
                continue
            tool_result = maybe_tool_result
            tool_results.append(tool_result)
            batch_tool_count += 1
            audit.append("analysis_tool_result", _tool_result_summary(tool_result))
            parsed = _parse_tool_result(tool_result, evidence, session, extra_warnings=extra_warnings)
            if parsed is not None:
                parser_results.append(parsed)
                batch_parser_count += 1
                audit.append("parser_completed", _parser_summary(parsed))

            if task.tool == "timeline":
                derived = _derived_plaso_evidence(tool_result, evidence, session)
                if derived is not None:
                    all_evidence.append(derived)
                    maybe_psort_result = _dispatch_tool_task(
                        manifest=manifest.model_copy(update={"evidence": tuple(all_evidence)}),
                        session=session,
                        audit=audit,
                        tool_config=tool_config,
                        task=ToolTask(
                            tool="psort",
                            evidence_id=derived.evidence_id,
                            params=_tool_params(
                                "psort",
                                psort_profile=psort_profile,
                                tool_timeout_seconds=tool_timeout_seconds,
                                psort_filter=psort_filter,
                                psort_slice=psort_slice,
                                psort_slice_size=psort_slice_size,
                            ),
                        ),
                        extra_warnings=extra_warnings,
                        progress=progress,
                    )
                    if maybe_psort_result is None:
                        continue
                    psort_result = maybe_psort_result
                    tool_results.append(psort_result)
                    batch_tool_count += 1
                    audit.append("analysis_tool_result", _tool_result_summary(psort_result))
                    parsed_psort = _parse_tool_result(
                        psort_result,
                        derived,
                        session,
                        extra_warnings=extra_warnings,
                    )
                    if parsed_psort is not None:
                        parser_results.append(parsed_psort)
                        batch_parser_count += 1
                        audit.append("parser_completed", _parser_summary(parsed_psort))
                elif evidence.evidence_type in {EvidenceType.E01, EvidenceType.DD}:
                    if _disk_triage_fallback_enabled():
                        reason = _timeline_failure_reason(tool_result)
                        fallback_warning = make_warning(
                            "DISK_TRIAGE_FALLBACK",
                            artifact=evidence.evidence_id,
                            impact=(
                                "Full log2timeline did not produce a usable PLASO timeline; "
                                "running bounded Sleuth Kit filesystem triage so accessible disk "
                                f"metadata is still checked. Reason: {reason}"
                            ),
                            severity="HIGH",
                            tool="disk_triage",
                            metadata={"primary_tool": "timeline", "fallback_tool": "disk_triage"},
                        )
                        extra_warnings.append(fallback_warning)
                        audit.append(
                            "disk_triage_fallback_started",
                            {
                                "evidence_id": evidence.evidence_id,
                                "reason": reason,
                                "coverage_note": (
                                    "Fallback checks accessible filesystem metadata and configured high-value paths; "
                                    "it does not claim full Plaso/VSS coverage."
                                ),
                            },
                        )
                        audit.append(
                            "plan_change",
                            {
                                "evidence_id": evidence.evidence_id,
                                "reason": (
                                    "Full E01/DD timeline extraction did not produce a usable PLASO output; "
                                    "Blitz switched to bounded disk triage so accessible filesystem metadata "
                                    "is still checked and the limitation remains auditable."
                                ),
                                "from": "full_disk_log2timeline",
                                "to": "bounded_disk_triage_fallback",
                                "coverage_note": (
                                    "Fallback is streamed and bounded. It preserves partial disk coverage but "
                                    "does not claim full Plaso or VSS coverage."
                                ),
                            },
                        )
                        _progress(
                            progress,
                            "Disk triage fallback started",
                            {"evidence_id": evidence.evidence_id, "reason": reason},
                        )
                        maybe_disk_result = _dispatch_tool_task(
                            manifest=manifest,
                            session=session,
                            audit=audit,
                            tool_config=tool_config,
                            task=ToolTask(
                                tool="disk_triage",
                                evidence_id=evidence.evidence_id,
                                params=_tool_params(
                                    "disk_triage",
                                    tool_timeout_seconds=tool_timeout_seconds,
                                ),
                            ),
                            extra_warnings=extra_warnings,
                            progress=progress,
                        )
                        if maybe_disk_result is None:
                            extra_warnings.append(
                                make_warning(
                                    "DISK_TRIAGE_FALLBACK_FAILED",
                                    artifact=evidence.evidence_id,
                                    impact=(
                                        "Disk triage fallback did not produce bounded output. "
                                        "Treat disk-image coverage as incomplete until manual review."
                                    ),
                                    severity="CRITICAL",
                                    tool="disk_triage",
                                )
                            )
                            audit.append(
                                "disk_triage_fallback_failed",
                                {"evidence_id": evidence.evidence_id, "reason": "dispatch returned no result"},
                            )
                        else:
                            disk_result = maybe_disk_result
                            tool_results.append(disk_result)
                            batch_tool_count += 1
                            audit.append("analysis_tool_result", _tool_result_summary(disk_result))
                            parsed_disk = _parse_tool_result(
                                disk_result,
                                evidence,
                                session,
                                extra_warnings=extra_warnings,
                            )
                            if parsed_disk is not None:
                                parser_results.append(parsed_disk)
                                batch_parser_count += 1
                                audit.append("parser_completed", _parser_summary(parsed_disk))
                            audit.append(
                                "disk_triage_fallback_completed",
                                {
                                    "evidence_id": evidence.evidence_id,
                                    "tool_result": _tool_result_summary(disk_result),
                                    "parsed_records": parsed_disk.processed_count if parsed_disk is not None else 0,
                                },
                            )
                    else:
                        extra_warnings.append(
                            make_warning(
                                "DISK_TRIAGE_FALLBACK_DISABLED",
                                artifact=evidence.evidence_id,
                                impact=(
                                    "Full log2timeline did not produce a usable PLASO timeline and "
                                    "BLITZ_E01_DISK_TRIAGE_FALLBACK disabled the bounded disk fallback."
                                ),
                                severity="CRITICAL",
                                tool="timeline",
                            )
                        )
                        audit.append(
                            "disk_triage_fallback_disabled",
                            {"evidence_id": evidence.evidence_id, "reason": _timeline_failure_reason(tool_result)},
                        )
            completed_tool_tasks += 1
            write_progress_state(
                session=session,
                status="RUNNING",
                current_layer="typed_tool_execution",
                layer_status="RUNNING",
                details={
                    "batch_id": batch.batch_id,
                    "last_task": planned_task.task_id,
                    "last_tool": task.tool,
                },
                processed_items=completed_tool_tasks,
                total_items=max(batch_plan.task_count, 1),
            )
        audit.append(
            "batch_completed",
            {
                "batch_id": batch.batch_id,
                "tool_result_count": batch_tool_count,
                "parser_result_count": batch_parser_count,
            },
        )
        _progress(
            progress,
            "Batch completed",
            {"batch_id": batch.batch_id, "tool_results": batch_tool_count, "parser_results": batch_parser_count},
        )
        _write_json(tool_results_path, tool_results)
        _write_json(parser_results_path, _serializable_parser_results(parser_results))
        write_session_state(
            session=session,
            status="RUNNING",
            phase="batch_completed",
            details={
                "batch_id": batch.batch_id,
                "tool_results": batch_tool_count,
                "parser_results": batch_parser_count,
            },
        )
    if not resuming:
        write_progress_state(
            session=session,
            status="RUNNING",
            current_layer="typed_tool_execution",
            layer_status="COMPLETED",
            details={"tool_results": len(tool_results), "parser_results": len(parser_results)},
        )

    evidence_by_id = {evidence.evidence_id: evidence for evidence in all_evidence}
    parser_record_count = sum(result.processed_count for result in parser_results)
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="parsing",
        layer_status="RUNNING",
        details={
            "parser_result_count": len(parser_results),
            "parser_processed_count": parser_record_count,
        },
        processed_items=0,
        total_items=max(len(parser_results), 1),
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="parsing",
        layer_status="COMPLETED",
        details={
            "parser_result_count": len(parser_results),
            "parser_processed_count": parser_record_count,
        },
        processed_items=len(parser_results),
        total_items=max(len(parser_results), 1),
    )
    write_session_state(
        session=session,
        status="RUNNING",
        phase="normalization_started",
        details={
            "parser_result_count": len(parser_results),
            "parser_processed_count": parser_record_count,
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="normalization",
        layer_status="RUNNING",
        details={
            "parser_result_count": len(parser_results),
            "parser_processed_count": parser_record_count,
            "max_normalized_events": _configured_max_events(),
            "progress_denominator": "configured_normalized_event_cap",
        },
        processed_items=0,
        total_items=max(_configured_max_events(), 1),
    )
    sqlite_normalized = _try_sqlite_backed_normalization(
        session=session,
        tool_results=tool_results,
        parser_results=parser_results,
        evidence_by_id=evidence_by_id,
        full_sql_correlation=full_sql_correlation,
    )
    normalized_store_path: Path | None = None
    if sqlite_normalized is not None:
        events = sqlite_normalized.events
        normalized_event_count = sqlite_normalized.processed_count
        normalized_warning_count = len(sqlite_normalized.warnings)
        normalized_truncated = sqlite_normalized.truncated
        all_warnings = _deduplicate_warnings((*extra_warnings, *sqlite_normalized.warnings))
        normalized_store_path = sqlite_normalized.store_path
        audit.append(
            "sqlite_normalization_completed",
            {
                "event_count": sqlite_normalized.processed_count,
                "analysis_event_count": len(events),
                "analysis_event_memory_limit": sqlite_normalized.analysis_event_memory_limit,
                "store_path": _relative_session_path(sqlite_normalized.store_path, session),
                "table_name": sqlite_normalized.table_name,
            },
        )
    else:
        normalized = normalize_parser_results(parser_results, evidence_by_id=evidence_by_id)
        events = normalized.events
        normalized_event_count = len(events)
        normalized_warning_count = len(normalized.warnings)
        normalized_truncated = normalized.truncated
        all_warnings = _deduplicate_warnings((*extra_warnings, *normalized.warnings))
        if full_sql_correlation:
            normalized_store_path = _write_in_memory_normalized_events_to_sqlite(session=session, events=events)
            audit.append(
                "sqlite_normalization_completed",
                {
                    "event_count": normalized_event_count,
                    "analysis_event_count": len(events),
                    "store_path": _relative_session_path(normalized_store_path, session),
                    "table_name": "normalized_events",
                    "strategy": "in_memory_materialization",
                },
            )
    audit.append(
        "normalization_completed",
        {
            "event_count": normalized_event_count,
            "processed_count": normalized_event_count,
            "truncated": normalized_truncated,
            "warning_count": normalized_warning_count,
        },
    )
    write_session_state(
        session=session,
        status="RUNNING",
        phase="normalization_completed",
        details={"event_count": normalized_event_count, "warning_count": normalized_warning_count},
    )
    _progress(
        progress,
        "Normalization completed",
        {
            "events": normalized_event_count,
            "warnings": len(all_warnings),
            "analysis_events_loaded": len(events),
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="normalization",
        layer_status="COMPLETED",
        details={
            "event_count": normalized_event_count,
            "warning_count": normalized_warning_count,
            "analysis_events_loaded": len(events),
            "analysis_event_memory_limit": sqlite_normalized.analysis_event_memory_limit
            if sqlite_normalized is not None
            else len(events),
            "truncated": normalized_truncated,
        },
        processed_items=normalized_event_count,
        total_items=max(normalized_event_count, 1),
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="object_inventory",
        layer_status="RUNNING",
        details={"source": "normalized_events"},
    )
    with progress_heartbeat(
        session=session,
        status="RUNNING",
        current_layer="object_inventory",
        details={"source": "normalized_events", "state": "building_object_inventory"},
        interval_seconds=30,
    ):
        object_inventory = build_object_inventory_report(
            case_id=manifest.case_id,
            manifest=manifest,
            events=events,
            store_path=normalized_store_path,
            evidence_inventory=inventory_report,
        )
    _write_json(object_inventory_path, object_inventory.model_dump(mode="json"))
    audit.append(
        "object_inventory_completed",
        {
            "source": object_inventory.source,
            "normalized_event_count": object_inventory.normalized_event_count,
            "object_count": object_inventory.object_count,
            "object_mention_count": object_inventory.object_mention_count,
            "object_type_counts": object_inventory.object_type_counts,
            "evidence_without_normalized_events": object_inventory.evidence_without_normalized_events,
            "unchecked_or_unsupported_evidence": object_inventory.unchecked_or_unsupported_evidence,
        },
    )
    write_session_state(
        session=session,
        status="RUNNING",
        phase="object_inventory_completed",
        details={
            "source": object_inventory.source,
            "object_count": object_inventory.object_count,
            "normalized_event_count": object_inventory.normalized_event_count,
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="object_inventory",
        layer_status="COMPLETED",
        details={
            "source": object_inventory.source,
            "object_count": object_inventory.object_count,
            "object_mention_count": object_inventory.object_mention_count,
            "normalized_event_count": object_inventory.normalized_event_count,
        },
    )
    _progress(
        progress,
        "Object inventory completed",
        {
            "source": object_inventory.source,
            "objects": object_inventory.object_count,
            "normalized_events": object_inventory.normalized_event_count,
        },
    )
    analysis_events, scope_warning = _bounded_analysis_events(events)
    if full_sql_correlation:
        scope_warning = None
    elif scope_warning is None and normalized_event_count > len(analysis_events):
        scope_warning = _analysis_scope_warning(
            normalized_event_count=normalized_event_count,
            analysis_event_count=len(analysis_events),
        )
    if scope_warning is not None:
        all_warnings.append(scope_warning)
        audit.append(
            "analysis_scope_limited",
            {
                "normalized_event_count": normalized_event_count,
                "analysis_event_count": len(analysis_events),
                "reason": scope_warning.impact,
            },
        )
        _progress(
            progress,
            "Analysis scope limited",
            {"normalized_events": normalized_event_count, "analysis_events": len(analysis_events)},
        )

    correlation_scope = _build_correlation_scope(
        manifest=manifest,
        tool_results=tool_results,
        normalized_event_count=normalized_event_count,
        analysis_event_count=len(analysis_events),
        evidence_event_counts=object_inventory.evidence_event_counts,
        event_category_counts=object_inventory.event_category_counts,
        evidence_without_normalized_events=object_inventory.evidence_without_normalized_events,
        unchecked_or_unsupported_evidence=object_inventory.unchecked_or_unsupported_evidence,
        full_sql_correlation=full_sql_correlation,
    )
    audit.append("correlation_scope_recorded", correlation_scope)

    observed_counts, expected_counts = _coverage_counts(
        manifest,
        events,
        tool_results=tool_results,
        psort_filter=psort_filter,
    )
    coverage_report = coverage_report_from_expected_artifacts(
        observed_counts=observed_counts,
        expected_counts=expected_counts,
        artifact_types=_coverage_artifact_types(observed_counts, expected_counts),
    )
    signal_report = summarize_signal_integrity(
        parser_results=parser_results,
        coverage_report=coverage_report,
        extra_warnings=all_warnings,
    )
    signal_report = _deduplicate_signal_report(signal_report)
    full_accounting = _load_full_accounting_checkpoint(full_accounting_path) if resuming else None
    if full_accounting is None and resuming:
        full_accounting = _recover_full_accounting_from_store(session, tool_results)
    if full_accounting is None:
        write_progress_state(
            session=session,
            status="RUNNING",
            current_layer="full_accounting",
            layer_status="RUNNING",
            details={"tool_results": len(tool_results), "event_store": str(event_store_path)},
        )
        with progress_heartbeat(
            session=session,
            status="RUNNING",
            current_layer="full_accounting",
            details={"tool_results": len(tool_results), "event_store": str(event_store_path), "state": "building_full_accounting"},
            interval_seconds=30,
        ):
            full_accounting = build_full_accounting(session=session, tool_results=tool_results)
        _write_json(full_accounting_path, full_accounting.model_dump(mode="json"))
    elif resuming and not full_accounting_path.exists():
        write_progress_state(
            session=session,
            status="RUNNING",
            current_layer="full_accounting",
            layer_status="RUNNING",
            details={"source": "recovered_checkpoint", "event_store": str(event_store_path)},
        )
        _write_json(full_accounting_path, full_accounting.model_dump(mode="json"))
    audit.append(
        "full_accounting_completed",
        {
            "artifact_count": full_accounting.artifact_count,
            "total_rows": full_accounting.total_rows,
            "event_store_path": full_accounting.event_store_path,
        },
    )
    write_session_state(
        session=session,
        status="RUNNING",
        phase="full_accounting_completed",
        details={"artifact_count": full_accounting.artifact_count, "total_rows": full_accounting.total_rows},
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="full_accounting",
        layer_status="COMPLETED",
        details={
            "artifact_count": full_accounting.artifact_count,
            "total_rows": full_accounting.total_rows,
            "event_store_path": full_accounting.event_store_path,
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="sqlite_event_store",
        layer_status="COMPLETED",
        details={
            "event_store_path": full_accounting.event_store_path,
            "total_rows": full_accounting.total_rows,
        },
    )
    contradictions: tuple[Contradiction, ...]
    lineage: tuple[ProcessLineageLink, ...]
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="correlation",
        layer_status="RUNNING",
        details={
            "backend": "sqlite" if full_sql_correlation else "python",
            "normalized_event_count": normalized_event_count,
            "analysis_event_count": len(analysis_events),
        },
    )
    if full_sql_correlation:
        with progress_heartbeat(
            session=session,
            status="RUNNING",
            current_layer="correlation",
            details={
                "backend": "sqlite",
                "event_store": str(event_store_path),
                "state": "scanning_normalized_events",
            },
            interval_seconds=30,
        ):
            sql_correlation = correlate_normalized_events_sqlite(
                event_store_path,
                finding_limit=_sql_correlation_finding_limit(),
                support_event_limit=_sql_correlation_support_event_limit(),
            )
        findings = downgrade_unverified_findings(sql_correlation.findings, signal_report.warnings)
        sql_report_events = sql_correlation.support_events
        if not sql_report_events:
            sql_report_events = tuple(analysis_events[:_sql_no_finding_context_event_limit()])
        analysis_events = sql_report_events
        contradictions = ()
        lineage = ()
        stages = sql_correlation.stages
        findings_before_contradiction_penalty = findings
        audit.append(
            "sql_correlation_completed",
            {
                "backend": sql_correlation.backend,
                "rows_scanned": sql_correlation.rows_scanned,
                "candidate_count": sql_correlation.candidate_count,
                "finding_count": len(findings),
                "support_event_count": len(sql_correlation.support_events),
                "selected_report_context_event_count": len(analysis_events),
                "candidate_store": "findings/event_store.sqlite:sql_correlation_candidates",
            },
        )
        _progress(
            progress,
            "Full SQL correlation completed",
            {
                "rows_scanned": sql_correlation.rows_scanned,
                "candidates": sql_correlation.candidate_count,
                "findings": len(findings),
            },
        )
    else:
        findings = _derive_findings(analysis_events)
        findings = downgrade_unverified_findings(findings, signal_report.warnings)
        contradictions = detect_contradictions(analysis_events)
        findings_before_contradiction_penalty = findings
        findings = apply_contradiction_penalties(findings, contradictions)
        lineage = build_process_lineage(analysis_events)
        stages = infer_attack_stages(analysis_events, findings=findings)
    audit.append(
        "correlation_completed",
        {
            "backend": "sqlite" if full_sql_correlation else "python",
            "finding_count": len(findings),
            "contradiction_count": len(contradictions),
            "lineage_link_count": len(lineage),
            "attack_stage_count": len(stages),
        },
    )
    _progress(progress, "Correlation completed", {"findings": len(findings), "stages": len(stages)})
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="correlation",
        layer_status="COMPLETED",
        details={
            "backend": "sqlite" if full_sql_correlation else "python",
            "finding_count": len(findings),
            "contradiction_count": len(contradictions),
            "lineage_link_count": len(lineage),
            "attack_stage_count": len(stages),
        },
    )

    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="investigation_guidance",
        layer_status="RUNNING",
        details={"finding_count": len(findings), "attack_stage_count": len(stages)},
    )
    investigation_guidance = build_investigation_guidance(findings=findings, stages=stages)
    _write_json(investigation_guidance_path, investigation_guidance.model_dump(mode="json"))

    audit.append(
        "investigation_guidance_generated",
        {
            "recommendation_count": investigation_guidance.recommendation_count,
            "recommended_tools": investigation_guidance.recommended_tools,
            "attack_stages": investigation_guidance.attack_stages,
        },
    )
    audit.append(
        "investigation_guidance_completed",
        {
            "finding_count": investigation_guidance.finding_count,
            "recommendation_count": investigation_guidance.recommendation_count,
            "recommended_tools": investigation_guidance.recommended_tools,
            "attack_stages": investigation_guidance.attack_stages,
            "finding_categories": investigation_guidance.finding_categories,
        },
    )
    if investigation_guidance.finding_count or investigation_guidance.attack_stage_count:
        audit.append(
            "hypothesis_formed",
            {
                "source": "deterministic_investigation_guidance",
                "hypothesis": (
                    "Observed finding categories and attack-stage grouping require targeted validation before "
                    "any conclusion is treated as complete."
                ),
                "finding_count": investigation_guidance.finding_count,
                "attack_stage_count": investigation_guidance.attack_stage_count,
                "recommended_tools": investigation_guidance.recommended_tools,
                "status": "needs_validation",
            },
        )
    write_session_state(
        session=session,
        status="RUNNING",
        phase="investigation_guidance_generated",
        details={
            "recommendation_count": investigation_guidance.recommendation_count,
            "recommended_tools": investigation_guidance.recommended_tools,
            "attack_stages": investigation_guidance.attack_stages,
        },
    )
    _progress(
        progress,
        "Investigation guidance generated",
        {
            "recommendations": investigation_guidance.recommendation_count,
            "recommended_tools": investigation_guidance.recommended_tools,
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="investigation_guidance",
        layer_status="COMPLETED",
        details={
            "recommendation_count": investigation_guidance.recommendation_count,
            "recommended_tools": investigation_guidance.recommended_tools,
            "attack_stages": investigation_guidance.attack_stages,
            "investigation_guidance": str(investigation_guidance_path),
        },
    )

    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="temporal_analysis",
        layer_status="RUNNING",
        details={
            "normalized_event_count": normalized_event_count,
            "analysis_event_count": len(analysis_events),
            "finding_count": len(findings),
            "attack_stage_count": len(stages),
        },
    )
    temporal_gap_analysis = build_temporal_gap_analysis(events)
    attack_stage_timeline = build_attack_stage_timeline(
        events=analysis_events,
        findings=findings,
        stages=stages,
    )
    export_temporal_gap_analysis(temporal_gap_analysis, temporal_gap_analysis_path)
    export_attack_stage_timeline(attack_stage_timeline, attack_stage_timeline_path)
    render_temporal_gap_markdown(temporal_gap_analysis, temporal_gap_analysis_markdown_path)
    render_attack_stage_timeline_markdown(attack_stage_timeline, attack_stage_timeline_markdown_path)
    audit.append(
        "temporal_analysis_completed",
        {
            "temporal_gap_analysis": str(temporal_gap_analysis_path),
            "attack_stage_timeline": str(attack_stage_timeline_path),
            "temporal_gap_count": len(temporal_gap_analysis.gaps),
            "attack_stage_count": attack_stage_timeline.stage_count,
            "valid_timestamp_count": temporal_gap_analysis.valid_timestamp_count,
            "invalid_or_placeholder_timestamp_count": temporal_gap_analysis.invalid_or_placeholder_timestamp_count,
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="temporal_analysis",
        layer_status="COMPLETED",
        details={
            "temporal_gap_analysis": str(temporal_gap_analysis_path),
            "attack_stage_timeline": str(attack_stage_timeline_path),
            "temporal_gap_count": len(temporal_gap_analysis.gaps),
            "attack_stage_count": attack_stage_timeline.stage_count,
            "timestamp_quality": temporal_gap_analysis.timestamp_quality,
        },
    )

    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="evidentiary_weighting",
        layer_status="RUNNING",
        details={"finding_count": len(findings), "source": "correlated_findings"},
    )
    evidentiary_weighting_report = build_evidentiary_weighting_report(
        findings=findings,
        events=analysis_events,
        contradictions=contradictions,
    )
    export_evidentiary_weighting_report(evidentiary_weighting_report, evidentiary_weighting_path)
    render_evidentiary_weighting_markdown(evidentiary_weighting_report, evidentiary_weighting_markdown_path)
    audit.append(
        "evidentiary_weighting_completed",
        {
            "finding_count": evidentiary_weighting_report.finding_count,
            "average_evidence_weight": evidentiary_weighting_report.average_evidence_weight,
            "evidentiary_weighting": str(evidentiary_weighting_path),
            "evidentiary_weighting_markdown": str(evidentiary_weighting_markdown_path),
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="evidentiary_weighting",
        layer_status="COMPLETED",
        details={
            "finding_count": evidentiary_weighting_report.finding_count,
            "average_evidence_weight": evidentiary_weighting_report.average_evidence_weight,
            "evidentiary_weighting": str(evidentiary_weighting_path),
        },
    )

    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="contradiction_analysis",
        layer_status="RUNNING",
        details={"contradiction_count": len(contradictions), "finding_count": len(findings)},
    )
    contradiction_analysis_report = build_contradiction_analysis_report(
        findings_before=findings_before_contradiction_penalty,
        findings_after=findings,
        contradictions=contradictions,
    )
    export_contradiction_analysis_report(contradiction_analysis_report, contradiction_analysis_path)
    render_contradiction_analysis_markdown(contradiction_analysis_report, contradiction_analysis_markdown_path)
    audit.append(
        "contradiction_analysis_completed",
        {
            "contradiction_count": contradiction_analysis_report.contradiction_count,
            "contradiction_score": contradiction_analysis_report.contradiction_score,
            "impacted_finding_count": len(contradiction_analysis_report.finding_impacts),
            "contradiction_analysis": str(contradiction_analysis_path),
            "contradiction_analysis_markdown": str(contradiction_analysis_markdown_path),
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="contradiction_analysis",
        layer_status="COMPLETED",
        details={
            "contradiction_count": contradiction_analysis_report.contradiction_count,
            "contradiction_score": contradiction_analysis_report.contradiction_score,
            "impacted_finding_count": len(contradiction_analysis_report.finding_impacts),
            "contradiction_analysis": str(contradiction_analysis_path),
        },
    )

    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="validation",
        layer_status="RUNNING",
        details={"finding_count": len(findings), "warning_count": len(signal_report.warnings)},
    )
    validation_report = validate_case_outputs(
        findings=findings,
        contradictions=contradictions,
        signal_report=signal_report,
        lineage_links=lineage,
    )
    triggers = triggers_from_validation(validation_report)
    correction_history = execute_bounded_corrections(
        triggers,
        confidence_before=_average_confidence(findings),
        audit_logger=audit,
    )
    audit.append(
        "validation_completed",
        {
            "passed": validation_report.passed,
            "issue_count": len(validation_report.issues),
            "trigger_count": len(triggers),
            "correction_status": correction_history.status,
        },
    )
    if triggers:
        audit.append(
            "plan_change",
            {
                "reason": "Validation produced correction triggers, so Blitz recorded bounded correction review.",
                "from": "initial_correlation_findings",
                "to": "bounded_validation_correction_review",
                "trigger_count": len(triggers),
                "correction_status": correction_history.status,
                "validation_passed": validation_report.passed,
            },
        )
    _progress(
        progress,
        "Validation completed",
        {"passed": validation_report.passed, "issues": len(validation_report.issues)},
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="validation",
        layer_status="COMPLETED",
        details={
            "validation_passed": validation_report.passed,
            "issue_count": len(validation_report.issues),
            "trigger_count": len(triggers),
            "correction_status": correction_history.status,
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="unknowns",
        layer_status="RUNNING",
        details={"validation_passed": validation_report.passed},
    )
    unknowns_report = build_unknowns_report(
        coverage_report=coverage_report,
        signal_report=signal_report,
        validation_report=validation_report,
        full_accounting=full_accounting,
    )
    audit.append(
        "unknowns_completed",
        {
            "unknown_count": unknowns_report.unknown_count,
            "critical_count": unknowns_report.critical_count,
            "high_count": unknowns_report.high_count,
        },
    )
    _write_json(unknowns_path, unknowns_report.model_dump(mode="json"))
    _write_json(validation_path, validation_report.model_dump(mode="json"))
    _write_json(coverage_path, coverage_report.model_dump(mode="json"))
    _write_json(signal_path, signal_report.model_dump(mode="json"))
    _write_json(correction_path, correction_history.model_dump(mode="json"))
    write_session_state(
        session=session,
        status="RUNNING",
        phase="validation_unknowns_completed",
        details={
            "validation_passed": validation_report.passed,
            "unknown_count": unknowns_report.unknown_count,
        },
    )
    _progress(
        progress,
        "Validation artifacts written",
        {"validation": str(validation_path), "unknowns": str(unknowns_path)},
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="unknowns",
        layer_status="COMPLETED",
        details={
            "validation_passed": validation_report.passed,
            "issue_count": len(validation_report.issues),
            "unknown_count": unknowns_report.unknown_count,
        },
    )

    write_session_state(
        session=session,
        status="RUNNING",
        phase="reasoning_started" if enable_reasoning else "reasoning_skipped",
        details={
            "enabled": enable_reasoning,
            "analysis_event_count": len(analysis_events),
            "finding_count": len(findings),
            "raw_evidence_allowed": False,
            "raw_tool_output_allowed": False,
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="bounded_llm_reasoning",
        layer_status="RUNNING" if enable_reasoning else "SKIPPED",
        details={
            "enabled": enable_reasoning,
            "provider": os.getenv("LLM_PROVIDER", "openai-compatible") if enable_reasoning else None,
            "model": os.getenv("LLM_MODEL") if enable_reasoning else None,
            "raw_evidence_sent": False,
            "raw_tool_output_sent": False,
        },
    )
    reasoning_outcome = _run_bounded_reasoning(
        enable_reasoning=enable_reasoning,
        events=analysis_events,
        findings=findings,
        contradictions=contradictions,
        warnings=signal_report.warnings,
        coverage=coverage_report.model_dump(mode="json"),
        confidence={
            "average_finding_confidence": _average_confidence(findings),
            "validation_passed": validation_report.passed,
            "signal_confidence_penalty": signal_report.confidence_penalty,
        },
        audit=audit,
    )
    reasoning = reasoning_outcome.reasoning
    if reasoning is None:
        phase = "reasoning_failed_closed" if reasoning_outcome.status == "provider_failed" else "reasoning_skipped"
        write_session_state(
            session=session,
            status="RUNNING",
            phase=phase,
            details={
                "enabled": reasoning_outcome.enabled,
                "status": reasoning_outcome.status,
                "reason": reasoning_outcome.reason,
                "raw_evidence_sent": False,
                "raw_tool_output_sent": False,
                **reasoning_outcome.details,
            },
        )
        write_progress_state(
            session=session,
            status="RUNNING",
            current_layer="bounded_llm_reasoning",
            layer_status="SKIPPED",
            details={
                "enabled": reasoning_outcome.enabled,
                "status": reasoning_outcome.status,
                "reason": reasoning_outcome.reason,
                "raw_evidence_sent": False,
                "raw_tool_output_sent": False,
                **reasoning_outcome.details,
            },
        )
    else:
        reasoning_metadata = reasoning.provider_metadata.model_dump() if reasoning.provider_metadata else {}
        token_usage = reasoning.token_usage.model_dump() if reasoning.token_usage else {}
        write_session_state(
            session=session,
            status="RUNNING",
            phase="reasoning_completed",
            details={
                "provider": reasoning_metadata.get("provider"),
                "model": reasoning_metadata.get("model"),
                "prompt_hash": reasoning.prompt_hash,
                "hypothesis_count": len(reasoning.hypotheses),
                "raw_evidence_sent": False,
                "raw_tool_output_sent": False,
            },
        )
        write_progress_state(
            session=session,
            status="RUNNING",
            current_layer="bounded_llm_reasoning",
            layer_status="COMPLETED",
            details={
                "provider": reasoning_metadata.get("provider"),
                "model": reasoning_metadata.get("model"),
                "prompt_hash": reasoning.prompt_hash,
                "hypothesis_count": len(reasoning.hypotheses),
                "total_tokens": token_usage.get("total_tokens"),
                "raw_evidence_sent": False,
                "raw_tool_output_sent": False,
            },
        )

    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="llm_report_verification",
        layer_status="RUNNING",
        details={
            "reasoning_enabled": reasoning is not None,
            "finding_count": len(findings),
            "analysis_event_count": len(analysis_events),
        },
    )
    llm_report_verification = build_llm_report_verification(
        reasoning=reasoning,
        events=analysis_events,
        findings=findings,
        reasoning_error=reasoning_outcome.reason if reasoning_outcome.status == "provider_failed" else None,
    )
    export_llm_report_verification(llm_report_verification, llm_report_verification_path)
    render_llm_report_verification_markdown(llm_report_verification, llm_report_verification_markdown_path)
    audit.append(
        "llm_report_verification_completed",
        {
            "status": llm_report_verification.status,
            "reasoning_enabled": llm_report_verification.reasoning_enabled,
            "invalid_evidence_reference_count": llm_report_verification.invalid_evidence_reference_count,
            "supported_hypotheses_without_evidence": llm_report_verification.supported_hypotheses_without_evidence,
            "llm_report_verification": str(llm_report_verification_path),
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="llm_report_verification",
        layer_status="COMPLETED",
        details={
            "status": llm_report_verification.status,
            "reasoning_enabled": llm_report_verification.reasoning_enabled,
            "invalid_evidence_reference_count": llm_report_verification.invalid_evidence_reference_count,
            "supported_hypotheses_without_evidence": llm_report_verification.supported_hypotheses_without_evidence,
            "llm_report_verification": str(llm_report_verification_path),
        },
    )

    write_session_state(
        session=session,
        status="RUNNING",
        phase="report_build_started",
        details={
            "analysis_event_count": len(analysis_events),
            "finding_count": len(findings),
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="report_generation",
        layer_status="RUNNING",
        details={
            "phase": "report_build_started",
            "analysis_event_count": len(analysis_events),
            "finding_count": len(findings),
        },
        processed_items=0,
        total_items=4,
    )
    report = build_report_document(
        case_id=manifest.case_id,
        events=analysis_events,
        findings=findings,
        contradictions=contradictions,
        coverage_report=coverage_report,
        signal_report=signal_report,
        validation_report=validation_report,
        correction_history=correction_history,
        reasoning=reasoning,
        audit_trail_path=str(session.audit_log_path),
        case_objective=case_objective_report.model_dump(mode="json"),
        investigation_plan=investigation_plan.model_dump(mode="json"),
        investigation_guidance=investigation_guidance.model_dump(mode="json"),
        temporal_gap_analysis=temporal_gap_analysis.model_dump(mode="json"),
        attack_stage_timeline=attack_stage_timeline.model_dump(mode="json"),
        evidence_triage=evidence_triage.model_dump(mode="json"),
        correlation_scope=correlation_scope,
        llm_report_verification=llm_report_verification.model_dump(mode="json"),
    )
    write_session_state(
        session=session,
        status="RUNNING",
        phase="report_built",
        details={
            "normalized_export_limit": _export_limit("BLITZ_NORMALIZED_EXPORT_LIMIT"),
            "parser_record_export_limit": _export_limit("BLITZ_PARSER_RECORD_EXPORT_LIMIT"),
            "report_timeline_count": len(report.timeline),
            "report_finding_count": len(report.findings),
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="report_generation",
        layer_status="RUNNING",
        details={
            "phase": "report_built",
            "report_timeline_count": len(report.timeline),
            "report_finding_count": len(report.findings),
        },
        processed_items=1,
        total_items=4,
    )

    write_session_state(
        session=session,
        status="RUNNING",
        phase="normalized_export_started",
        details={"normalized_export_limit": _export_limit("BLITZ_NORMALIZED_EXPORT_LIMIT")},
    )
    _write_json(normalized_events_path, _serializable_normalized_events(events, total_events=normalized_event_count))
    write_session_state(
        session=session,
        status="RUNNING",
        phase="normalized_export_written",
        details={"normalized_events": str(normalized_events_path)},
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="report_generation",
        layer_status="RUNNING",
        details={
            "phase": "normalized_export_written",
            "normalized_events": str(normalized_events_path),
            "normalized_event_count": normalized_event_count,
        },
        processed_items=2,
        total_items=4,
    )
    stress_report = build_stress_report(
        session=session,
        tool_results=tool_results,
        full_accounting=full_accounting,
        normalized_event_count=normalized_event_count,
        validation_report=validation_report,
        signal_report=signal_report,
    )
    _write_json(stress_report_path, stress_report)
    write_session_state(
        session=session,
        status="RUNNING",
        phase="stress_report_written",
        details={"stress_report": str(stress_report_path)},
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="report_generation",
        layer_status="RUNNING",
        details={"phase": "stress_report_written", "stress_report": str(stress_report_path)},
        processed_items=3,
        total_items=4,
    )
    write_session_state(
        session=session,
        status="RUNNING",
        phase="report_export_started",
        details={"report_json": str(report_json_path), "report_markdown": str(report_markdown_path)},
    )
    export_json_report(report, report_json_path)
    render_markdown_report(report, report_markdown_path)
    render_html_report(report, report_html_path)
    audit.append(
        "report_generation_completed",
        {
            "report_json": str(report_json_path),
            "report_markdown": str(report_markdown_path),
            "report_html": str(report_html_path),
            "report_timeline_count": len(report.timeline),
            "report_finding_count": len(report.findings),
        },
    )
    write_session_state(
        session=session,
        status="RUNNING",
        phase="report_exported",
        details={
            "report_json": str(report_json_path),
            "report_markdown": str(report_markdown_path),
            "report_html": str(report_html_path),
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="report_generation",
        layer_status="COMPLETED",
        details={
            "report_json": str(report_json_path),
            "report_markdown": str(report_markdown_path),
            "report_html": str(report_html_path),
            "report_timeline_count": len(report.timeline),
            "report_finding_count": len(report.findings),
        },
        processed_items=4,
        total_items=4,
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="evidence_maturity",
        layer_status="RUNNING",
        details={
            "finding_count": len(findings),
            "analysis_event_count": len(analysis_events),
            "phase": "evidence_maturity_started",
        },
    )
    write_session_state(
        session=session,
        status="RUNNING",
        phase="evidence_maturity_started",
        details={
            "finding_count": len(findings),
            "analysis_event_count": len(analysis_events),
        },
    )
    with progress_heartbeat(
        session=session,
        status="RUNNING",
        current_layer="evidence_maturity",
        details={"finding_count": len(findings), "state": "building_traceability_index"},
        interval_seconds=30,
    ):
        evidence_maturity_report = build_evidence_maturity_report(
            case_id=manifest.case_id,
            session_id=session.session_id,
            manifest=manifest,
            events=analysis_events,
            findings=findings,
            parser_results=parser_results,
            tool_results=tool_results,
            coverage_report=coverage_report,
            signal_report=signal_report,
            validation_report=validation_report,
            unknowns_report=unknowns_report,
            full_accounting=full_accounting,
            audit_log_path=session.audit_log_path,
        )
        export_evidence_maturity_report(evidence_maturity_report, evidence_maturity_path)
        render_evidence_maturity_markdown(evidence_maturity_report, evidence_maturity_markdown_path)
        render_finding_provenance_markdown(evidence_maturity_report, finding_provenance_markdown_path)
    audit.append(
        "evidence_maturity_written",
        {
            "evidence_maturity_json": str(evidence_maturity_path),
            "evidence_maturity_markdown": str(evidence_maturity_markdown_path),
            "finding_provenance_markdown": str(finding_provenance_markdown_path),
            "traceable_finding_count": evidence_maturity_report.summary["traceable_finding_count"],
            "finding_count": evidence_maturity_report.summary["finding_count"],
            "evidence_hashes_preserved": evidence_maturity_report.summary["evidence_hashes_preserved"],
        },
    )
    write_session_state(
        session=session,
        status="RUNNING",
        phase="evidence_maturity_written",
        details={
            "evidence_maturity": str(evidence_maturity_path),
            "finding_provenance_markdown": str(finding_provenance_markdown_path),
            "traceable_finding_count": evidence_maturity_report.summary["traceable_finding_count"],
            "finding_count": evidence_maturity_report.summary["finding_count"],
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="evidence_maturity",
        layer_status="COMPLETED",
        details={
            "evidence_maturity_json": str(evidence_maturity_path),
            "evidence_maturity_markdown": str(evidence_maturity_markdown_path),
            "finding_provenance_markdown": str(finding_provenance_markdown_path),
            "traceable_finding_count": evidence_maturity_report.summary["traceable_finding_count"],
            "finding_count": evidence_maturity_report.summary["finding_count"],
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="agent_trace",
        layer_status="RUNNING",
        details={
            "finding_count": len(findings),
            "tool_result_count": len(tool_results),
            "phase": "agent_trace_started",
        },
    )
    serializable_parser_results = _serializable_parser_results(parser_results)
    agent_trace = build_agent_trace(
        session=session,
        manifest=manifest,
        case_objective=case_objective_report,
        investigation_plan=investigation_plan,
        investigation_guidance=investigation_guidance,
        report_document=report,
        validation_report=validation_report,
        unknowns_report=unknowns_report,
        correction_history=correction_history,
        contradiction_analysis=contradiction_analysis_report,
        llm_report_verification=llm_report_verification,
        reasoning=reasoning,
        tool_results=tool_results,
        parser_results=serializable_parser_results,
        normalized_event_count=normalized_event_count,
        evidence_maturity_report=evidence_maturity_report,
    )
    export_agent_trace(agent_trace, agent_trace_path)
    render_agent_journal(agent_trace, agent_journal_path)
    audit.append(
        "agent_trace_written",
        {
            "agent_trace": str(agent_trace_path),
            "agent_journal": str(agent_journal_path),
            "finding_count": agent_trace["summary"]["finding_count"],
            "hypothesis_count": agent_trace["summary"]["hypothesis_count"],
            "plan_change_count": agent_trace["summary"]["plan_change_count"],
            "raw_evidence_included": agent_trace["raw_evidence_included"],
            "raw_tool_output_included": agent_trace["raw_tool_output_included"],
        },
    )
    write_session_state(
        session=session,
        status="RUNNING",
        phase="agent_trace_written",
        details={
            "agent_trace": str(agent_trace_path),
            "agent_journal": str(agent_journal_path),
            "finding_count": agent_trace["summary"]["finding_count"],
            "hypothesis_count": agent_trace["summary"]["hypothesis_count"],
            "plan_change_count": agent_trace["summary"]["plan_change_count"],
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="agent_trace",
        layer_status="COMPLETED",
        details={
            "agent_trace": str(agent_trace_path),
            "agent_journal": str(agent_journal_path),
            "finding_count": agent_trace["summary"]["finding_count"],
            "hypothesis_count": agent_trace["summary"]["hypothesis_count"],
            "plan_change_count": agent_trace["summary"]["plan_change_count"],
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="collated_outputs",
        layer_status="RUNNING",
        details={"phase": "collated_outputs_started"},
    )
    collated_artifact_paths = {
        "report_json": report_json_path,
        "report_markdown": report_markdown_path,
        "report_html": report_html_path,
        "case_objective_markdown": case_objective_markdown_path,
        "investigation_plan_markdown": investigation_plan_markdown_path,
        "evidence_triage_markdown": evidence_triage_markdown_path,
        "temporal_gap_analysis_markdown": temporal_gap_analysis_markdown_path,
        "attack_stage_timeline_markdown": attack_stage_timeline_markdown_path,
        "llm_report_verification_markdown": llm_report_verification_markdown_path,
        "evidentiary_weighting_markdown": evidentiary_weighting_markdown_path,
        "contradiction_analysis_markdown": contradiction_analysis_markdown_path,
        "evidence_maturity_markdown": evidence_maturity_markdown_path,
        "finding_provenance_markdown": finding_provenance_markdown_path,
        "agent_trace": agent_trace_path,
        "agent_journal_markdown": agent_journal_path,
        "tool_results": tool_results_path,
        "parser_results": parser_results_path,
        "normalized_events": normalized_events_path,
        "full_accounting": full_accounting_path,
        "event_store": event_store_path,
        "unknowns": unknowns_path,
        "validation": validation_path,
        "coverage": coverage_path,
        "signal_integrity": signal_path,
        "stress_report": stress_report_path,
        "artifact_manifest": artifact_manifest_path,
    }
    collated_outputs = write_collated_outputs(
        session=session,
        manifest=manifest,
        report_document=report,
        validation_report=validation_report,
        unknowns_report=unknowns_report,
        signal_report=signal_report,
        tool_results=tool_results,
        parser_results=serializable_parser_results,
        normalized_event_count=normalized_event_count,
        artifact_paths=collated_artifact_paths,
    )
    audit.append(
        "collated_outputs_written",
        {
            "overall_findings": str(collated_outputs.overall_findings_path),
            "overall_reports": str(collated_outputs.overall_reports_path),
            "collated_audit": str(collated_outputs.collated_audit_path),
        },
    )
    write_session_state(
        session=session,
        status="RUNNING",
        phase="collated_outputs_written",
        details={
            "overall_findings": str(collated_outputs.overall_findings_path),
            "overall_reports": str(collated_outputs.overall_reports_path),
            "collated_audit": str(collated_outputs.collated_audit_path),
        },
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="collated_outputs",
        layer_status="COMPLETED",
        details={
            "overall_findings": str(collated_outputs.overall_findings_path),
            "overall_reports": str(collated_outputs.overall_reports_path),
            "collated_audit": str(collated_outputs.collated_audit_path),
        },
    )
    collated_outputs.collated_audit_path.write_text(
        render_collated_audit(session=session, artifact_paths=collated_artifact_paths),
        encoding="utf-8",
    )
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="audit_finalization",
        layer_status="RUNNING",
        details={"phase": "artifact_manifest_started"},
    )
    event_store_checkpoint = _checkpoint_sqlite_event_store(event_store_path)
    audit.append("event_store_checkpointed", event_store_checkpoint)
    artifact_manifest_path = write_artifact_manifest(session=session, status="COMPLETED")
    audit.append(
        "artifact_manifest_written",
        {
            "artifact_manifest": str(artifact_manifest_path),
            "artifact_manifest_sha256": sha256_file(artifact_manifest_path),
        },
    )

    audit.append(
        "reports_written",
        {
            "artifact_manifest": str(artifact_manifest_path),
            "report_json": str(report_json_path),
            "report_markdown": str(report_markdown_path),
            "report_html": str(report_html_path),
            "normalized_events": str(normalized_events_path),
            "tool_results": str(tool_results_path),
            "parser_results": str(parser_results_path),
            "case_objective": str(case_objective_path),
            "case_objective_markdown": str(case_objective_markdown_path),
            "investigation_plan": str(investigation_plan_path),
            "investigation_plan_markdown": str(investigation_plan_markdown_path),
            "evidence_triage": str(evidence_triage_path),
            "evidence_triage_markdown": str(evidence_triage_markdown_path),
            "batch_plan": str(batch_plan_path),
            "tool_discovery": str(tool_discovery_path),
            "evidence_inventory": str(evidence_inventory_path),
            "recovery_plan": str(recovery_plan_path),
            "object_inventory": str(object_inventory_path),
            "full_accounting": str(full_accounting_path),
            "event_store": str(event_store_path),
            "unknowns": str(unknowns_path),
            "stress_report": str(stress_report_path),
            "evidentiary_weighting": str(evidentiary_weighting_path),
            "investigation_guidance": str(investigation_guidance_path),
            "temporal_gap_analysis": str(temporal_gap_analysis_path),
            "temporal_gap_analysis_markdown": str(temporal_gap_analysis_markdown_path),
            "attack_stage_timeline": str(attack_stage_timeline_path),
            "attack_stage_timeline_markdown": str(attack_stage_timeline_markdown_path),
            "llm_report_verification": str(llm_report_verification_path),
            "llm_report_verification_markdown": str(llm_report_verification_markdown_path),
            "evidentiary_weighting_markdown": str(evidentiary_weighting_markdown_path),
            "contradiction_analysis": str(contradiction_analysis_path),
            "contradiction_analysis_markdown": str(contradiction_analysis_markdown_path),
            "validation": str(validation_path),
            "evidence_maturity": str(evidence_maturity_path),
            "evidence_maturity_markdown": str(evidence_maturity_markdown_path),
            "finding_provenance_markdown": str(finding_provenance_markdown_path),
            "agent_trace": str(agent_trace_path),
            "agent_journal": str(agent_journal_path),
            "overall_findings": str(collated_outputs.overall_findings_path),
            "overall_reports": str(collated_outputs.overall_reports_path),
            "collated_audit": str(collated_outputs.collated_audit_path),
        },
    )
    _progress(progress, "Reports written", {"report_html": report_html_path})
    write_progress_state(
        session=session,
        status="RUNNING",
        current_layer="audit_finalization",
        layer_status="COMPLETED",
        details={
            "report_json": str(report_json_path),
            "report_markdown": str(report_markdown_path),
            "report_html": str(report_html_path),
            "evidentiary_weighting": str(evidentiary_weighting_path),
            "investigation_guidance": str(investigation_guidance_path),
            "temporal_gap_analysis": str(temporal_gap_analysis_path),
            "attack_stage_timeline": str(attack_stage_timeline_path),
            "llm_report_verification": str(llm_report_verification_path),
            "contradiction_analysis": str(contradiction_analysis_path),
            "evidence_maturity": str(evidence_maturity_path),
            "finding_provenance_markdown": str(finding_provenance_markdown_path),
            "agent_trace": str(agent_trace_path),
            "agent_journal": str(agent_journal_path),
            "overall_findings": str(collated_outputs.overall_findings_path),
            "overall_reports": str(collated_outputs.overall_reports_path),
            "collated_audit": str(collated_outputs.collated_audit_path),
            "artifact_manifest": str(artifact_manifest_path),
        },
    )
    audit.append(
        "analysis_completed",
        {
            "event_count": normalized_event_count,
            "finding_count": len(findings),
            "warning_count": len(signal_report.warnings),
            "validation_passed": validation_report.passed,
            "reasoning_enabled": reasoning is not None,
        },
    )
    write_session_state(
        session=session,
        status="COMPLETED",
        phase="analysis_completed",
        details={
            "artifact_manifest": str(artifact_manifest_path),
            "audit_log": str(session.audit_log_path),
            "agent_trace": str(agent_trace_path),
            "agent_journal": str(agent_journal_path),
            "overall_findings": str(collated_outputs.overall_findings_path),
            "overall_reports": str(collated_outputs.overall_reports_path),
            "collated_audit": str(collated_outputs.collated_audit_path),
            "validation_passed": validation_report.passed,
        },
    )
    write_progress_state(
        session=session,
        status="COMPLETED",
        current_layer="audit_finalization",
        layer_status="COMPLETED",
        details={
            "status": "analysis_completed",
            "event_count": normalized_event_count,
            "finding_count": len(findings),
            "validation_passed": validation_report.passed,
        },
    )

    return AnalyzeResult(
        case_id=manifest.case_id,
        session_id=session.session_id,
        session_root=session.session_root,
        audit_log_path=session.audit_log_path,
        session_state_path=session_state_path,
        progress_state_path=progress_state_path,
        artifact_manifest_path=artifact_manifest_path,
        report_json_path=report_json_path,
        report_markdown_path=report_markdown_path,
        report_html_path=report_html_path,
        normalized_events_path=normalized_events_path,
        tool_results_path=tool_results_path,
        parser_results_path=parser_results_path,
        case_objective_path=case_objective_path,
        investigation_plan_path=investigation_plan_path,
        evidence_triage_path=evidence_triage_path,
        case_objective_markdown_path=case_objective_markdown_path,
        investigation_plan_markdown_path=investigation_plan_markdown_path,
        evidence_triage_markdown_path=evidence_triage_markdown_path,
        batch_plan_path=batch_plan_path,
        tool_discovery_path=tool_discovery_path,
        evidence_inventory_path=evidence_inventory_path,
        recovery_plan_path=recovery_plan_path,
        object_inventory_path=object_inventory_path,
        full_accounting_path=full_accounting_path,
        event_store_path=event_store_path,
        unknowns_path=unknowns_path,
        stress_report_path=stress_report_path,
        evidentiary_weighting_path=evidentiary_weighting_path,
        contradiction_analysis_path=contradiction_analysis_path,
        temporal_gap_analysis_path=temporal_gap_analysis_path,
        attack_stage_timeline_path=attack_stage_timeline_path,
        llm_report_verification_path=llm_report_verification_path,
        validation_path=validation_path,
        evidence_maturity_path=evidence_maturity_path,
        evidentiary_weighting_markdown_path=evidentiary_weighting_markdown_path,
        contradiction_analysis_markdown_path=contradiction_analysis_markdown_path,
        temporal_gap_analysis_markdown_path=temporal_gap_analysis_markdown_path,
        attack_stage_timeline_markdown_path=attack_stage_timeline_markdown_path,
        llm_report_verification_markdown_path=llm_report_verification_markdown_path,
        investigation_guidance_path=investigation_guidance_path,
        evidence_maturity_markdown_path=evidence_maturity_markdown_path,
        finding_provenance_markdown_path=finding_provenance_markdown_path,
        agent_trace_path=agent_trace_path,
        agent_journal_path=agent_journal_path,
        overall_findings_path=collated_outputs.overall_findings_path,
        overall_reports_path=collated_outputs.overall_reports_path,
        collated_audit_path=collated_outputs.collated_audit_path,
        event_count=normalized_event_count,
        finding_count=len(findings),
        warning_count=len(signal_report.warnings),
        validation_passed=validation_report.passed,
        reasoning_enabled=reasoning is not None,
    )


def _audit_foundation(
    audit: AuditLogger,
    manifest: EvidenceManifest,
    session: CaseSession,
    mode: str,
) -> None:
    audit.append("manifest_loaded", dump_manifest_summary(manifest))
    for record in manifest.evidence:
        audit.append(
            "evidence_verified",
            {
                "case_id": manifest.case_id,
                "session_id": session.session_id,
                "evidence_id": record.evidence_id,
                "evidence_type": record.evidence_type.value,
                "pipeline": record.pipeline.value,
                "sha256": record.sha256,
                "size_bytes": record.size_bytes,
            },
        )
    audit.append(
        "analysis_started",
        {
            "case_id": manifest.case_id,
            "mode": mode,
            "evidence_count": len(manifest.evidence),
            "session_id": session.session_id,
        },
    )


def _write_run_bundle_session_pointer(session: CaseSession) -> None:
    run_root = os.environ.get("BLITZ_RUN_ROOT") or os.environ.get("RUN_ROOT")
    if not run_root:
        return
    root = Path(run_root)
    try:
        root.mkdir(parents=True, exist_ok=True)
        (root / "session_path.txt").write_text(str(session.session_root) + "\n", encoding="utf-8")
        link = root / "session"
        if link.exists() or link.is_symlink():
            link.unlink()
        try:
            link.symlink_to(session.session_root, target_is_directory=True)
        except OSError:
            pass
    except OSError:
        return


def _tasks_for_evidence(
    evidence: EvidenceRecord,
    *,
    psort_profile: str,
    tool_timeout_seconds: int | None,
    psort_filter: str | None,
    psort_slice: str | None,
    psort_slice_size: int | None,
) -> tuple[ToolTask, ...]:
    if evidence.evidence_type is EvidenceType.EVTX:
        return (ToolTask("events", evidence.evidence_id, _tool_params("events", tool_timeout_seconds=tool_timeout_seconds)),)
    if evidence.evidence_type is EvidenceType.PCAP:
        return (ToolTask("pcap", evidence.evidence_id, _tool_params("pcap", tool_timeout_seconds=tool_timeout_seconds)),)
    if evidence.evidence_type is EvidenceType.MEMORY:
        params = _tool_params("memory", tool_timeout_seconds=tool_timeout_seconds)
        params["plugin"] = "windows.pslist"
        return (ToolTask("memory", evidence.evidence_id, params),)
    if evidence.evidence_type is EvidenceType.PLASO:
        return (
            ToolTask(
                "psort",
                evidence.evidence_id,
                _tool_params(
                    "psort",
                    psort_profile=psort_profile,
                    tool_timeout_seconds=tool_timeout_seconds,
                    psort_filter=psort_filter,
                    psort_slice=psort_slice,
                    psort_slice_size=psort_slice_size,
                ),
            ),
        )
    if evidence.evidence_type in {
        EvidenceType.E01,
        EvidenceType.DD,
        EvidenceType.REGISTRY_HIVE,
        EvidenceType.FILESYSTEM_ARTIFACT,
    }:
        return (ToolTask("timeline", evidence.evidence_id, _tool_params("timeline", tool_timeout_seconds=tool_timeout_seconds)),)
    return ()


def _tool_params(
    tool: str,
    *,
    psort_profile: str = "triage",
    tool_timeout_seconds: int | None,
    psort_filter: str | None = None,
    psort_slice: str | None = None,
    psort_slice_size: int | None = None,
) -> dict[str, Any]:
    params: dict[str, Any] = {}
    if tool_timeout_seconds is not None:
        params["timeout_seconds"] = tool_timeout_seconds
    if tool == "timeline":
        params["partitions"] = os.environ.get("BLITZ_LOG2TIMELINE_PARTITIONS", "all")
        params["vss_stores"] = os.environ.get("BLITZ_LOG2TIMELINE_VSS_STORES", "none")
        parsers = log2timeline_parsers_for_profile()
        if parsers:
            params["parsers"] = parsers
    if tool == "psort":
        params["profile"] = psort_profile
        selected_filter = psort_filter or psort_filter_for_profile()
        if selected_filter:
            params["filter"] = selected_filter
        if psort_slice:
            params["slice"] = psort_slice
        if psort_slice_size is not None:
            params["slice_size"] = psort_slice_size
    return params


def _planned_to_tool_task(task: PlannedBatchTask) -> ToolTask:
    return ToolTask(
        tool=task.tool,
        evidence_id=task.evidence_id,
        params=dict(task.params),
    )


def _evidence_by_id(records: list[EvidenceRecord], evidence_id: str) -> EvidenceRecord | None:
    for record in records:
        if record.evidence_id == evidence_id:
            return record
    return None


def _dispatch_tool_task(
    *,
    manifest: EvidenceManifest,
    session: CaseSession,
    audit: AuditLogger,
    tool_config: Any,
    task: ToolTask,
    extra_warnings: list[SignalWarning],
    progress: Callable[[str, dict[str, Any] | None], None] | None = None,
) -> dict[str, Any] | None:
    registry = build_default_tool_registry(manifest=manifest, session=session, tool_config=tool_config)
    dispatcher = ToolDispatcher(manifest=manifest, session=session, registry=registry, audit=audit)
    try:
        _progress(progress, "Typed tool started", {"tool": task.tool, "evidence_id": task.evidence_id})
        write_progress_state(
            session=session,
            status="RUNNING",
            current_layer="typed_tool_execution",
            layer_status="RUNNING",
            details={"tool": task.tool, "evidence_id": task.evidence_id, "state": "dispatching"},
        )
        with progress_heartbeat(
            session=session,
            status="RUNNING",
            current_layer="typed_tool_execution",
            details={"tool": task.tool, "evidence_id": task.evidence_id, "state": "tool_running"},
        ):
            result = dispatcher.dispatch({"tool": task.tool, "evidence_id": task.evidence_id, "params": task.params})
        extra_warnings.extend(_safe_tool_warnings(result))
        execution = _dict_value(result, "execution")
        _progress(
            progress,
            "Typed tool completed",
            {
                "tool": task.tool,
                "exit_code": execution.get("exit_code"),
                "duration_ms": execution.get("duration_ms"),
                "timed_out": execution.get("timed_out"),
            },
        )
        return result
    except Exception as exc:
        warning = make_warning(
            "PARSER_CRASH",
            artifact=task.evidence_id,
            impact="typed tool execution failed before producing bounded output",
            severity="CRITICAL",
            tool=task.tool,
            metadata={"exception_type": type(exc).__name__},
        )
        extra_warnings.append(warning)
        audit.append(
            "analysis_tool_failed",
            {
                "tool": task.tool,
                "evidence_id": task.evidence_id,
                "exception_type": type(exc).__name__,
                "blitz_error": isinstance(exc, BlitzError),
            },
        )
        return None


def _progress(
    callback: Callable[[str, dict[str, Any] | None], None] | None,
    message: str,
    data: dict[str, Any] | None = None,
) -> None:
    if callback is not None:
        callback(message, data)


def _safe_tool_warnings(result: dict[str, Any]) -> list[SignalWarning]:
    warnings: list[SignalWarning] = []
    evidence_id = str(result.get("evidence_id") or "unknown")
    tool = str(result.get("typed_tool") or result.get("tool_name") or "unknown")
    for item in result.get("warnings", []):
        if not isinstance(item, dict):
            continue
        warnings.append(
            make_warning(
                str(item.get("warning_type") or "TOOL_WARNING"),
                artifact=evidence_id,
                impact=str(item.get("message") or "typed tool warning"),
                severity=_coerce_warning_severity(item.get("severity")),
                tool=tool,
            )
        )
    return warnings


def _coerce_warning_severity(value: object) -> Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
    if value == "LOW":
        return "LOW"
    if value == "MEDIUM":
        return "MEDIUM"
    if value == "HIGH":
        return "HIGH"
    if value == "CRITICAL":
        return "CRITICAL"
    return "MEDIUM"


def _parse_direct_processed_evidence(
    evidence: EvidenceRecord,
    *,
    extra_warnings: list[SignalWarning],
) -> ParserResult | None:
    if evidence.evidence_type is EvidenceType.CSV_TIMELINE:
        return parse_plaso_csv_file(evidence.path, evidence)
    if evidence.evidence_type is EvidenceType.PREPROCESSED_EVTX:
        return parse_evtx_json(_read_text_with_signal(evidence.path, evidence, "evtx", extra_warnings), evidence)
    if evidence.evidence_type is EvidenceType.JSON_EXPORT:
        return parse_volatility_json(
            _read_text_with_signal(evidence.path, evidence, "volatility", extra_warnings),
            evidence,
            plugin="json_export",
        )
    if evidence.evidence_type is EvidenceType.VOLATILITY_JSON:
        return parse_volatility_json(
            _read_text_with_signal(evidence.path, evidence, "volatility", extra_warnings),
            evidence,
            plugin="volatility_json",
        )
    if evidence.evidence_type is EvidenceType.YARA_MATCHES:
        return parse_yara_output(_read_text_with_signal(evidence.path, evidence, "yara", extra_warnings), evidence)
    if evidence.evidence_type is EvidenceType.STRINGS_OUTPUT:
        return parse_strings_output(_read_text_with_signal(evidence.path, evidence, "strings", extra_warnings), evidence)
    return None


def _parse_tool_result(
    result: dict[str, Any],
    evidence: EvidenceRecord,
    session: CaseSession,
    *,
    extra_warnings: list[SignalWarning],
) -> ParserResult | None:
    tool = str(result.get("typed_tool") or result.get("tool_name") or "")
    execution = _dict_value(result, "execution")
    exit_code = _int_value(execution.get("exit_code"))
    parser_name = _parser_name_for_tool(tool)
    if parser_name is None:
        return None
    if exit_code != 0:
        extra_warnings.append(parser_crash_warning(artifact=evidence.evidence_id, parser=parser_name, exit_code=exit_code))

    output_path = _primary_output_path(result, session)
    if output_path is None or not output_path.exists():
        extra_warnings.append(
            parser_crash_warning(artifact=evidence.evidence_id, parser=parser_name, exit_code=exit_code or 1)
        )
        text = ""
    else:
        if tool == "psort":
            record_limit = _parser_record_memory_limit() if _sqlite_backed_normalization_requested() else None
            return parse_plaso_csv_file(output_path, evidence, record_limit=record_limit)
        if tool == "disk_triage":
            return parse_disk_triage_file(output_path, evidence, record_limit=_parser_record_memory_limit())
        text = _read_text_with_signal(output_path, evidence, parser_name, extra_warnings)

    if tool == "events":
        return parse_evtx_json(text, evidence)
    if tool == "pcap":
        return parse_pcap_json(text, evidence)
    if tool == "memory":
        return parse_volatility_json(text, evidence, plugin=_memory_plugin_from_output(output_path, evidence))
    if tool == "disk_triage":
        return parse_disk_triage_json(text, evidence)
    if tool == "strings":
        return parse_strings_output(text, evidence)
    if tool == "yara":
        return parse_yara_output(text, evidence)
    return None


def _parser_name_for_tool(tool: str) -> str | None:
    return {
        "events": "evtx",
        "pcap": "pcap",
        "memory": "volatility",
        "psort": "plaso",
        "disk_triage": "disk_triage",
        "strings": "strings",
        "yara": "yara",
    }.get(tool)


def _primary_output_path(result: dict[str, Any], session: CaseSession) -> Path | None:
    outputs = _dict_value(result, "outputs")
    relative = outputs.get("primary_output")
    if not isinstance(relative, str) or relative.startswith("["):
        return None
    return session.session_root / relative


def _memory_plugin_from_output(output_path: Path | None, evidence: EvidenceRecord) -> str:
    if output_path is None:
        return "windows.pslist"
    name = output_path.name
    prefix = f"{evidence.evidence_id}."
    suffix = ".json"
    if not name.startswith(prefix) or not name.endswith(suffix):
        return "windows.pslist"
    plugin_token = name[len(prefix) : -len(suffix)]
    if not plugin_token:
        return "windows.pslist"
    return plugin_token.replace("_", ".")


def _derived_plaso_evidence(
    result: dict[str, Any],
    source: EvidenceRecord,
    session: CaseSession,
) -> EvidenceRecord | None:
    execution = _dict_value(result, "execution")
    if _int_value(execution.get("exit_code")) != 0:
        return None
    path = _primary_output_path(result, session)
    if path is None or not path.exists():
        return None
    return EvidenceRecord(
        evidence_id=f"{source.evidence_id}-plaso",
        path=path.resolve(),
        evidence_type=EvidenceType.PLASO,
        category=EvidenceCategory.DERIVED,
        pipeline=Pipeline.PROCESSED,
        trust_tier=TrustTier.TIER_2_MEDIUM_HIGH,
        sha256=sha256_file(path),
        verified=True,
        size_bytes=path.stat().st_size,
        internally_generated=True,
        description=f"Derived PLASO timeline from {source.evidence_id}",
    )


def _disk_triage_fallback_enabled() -> bool:
    value = os.environ.get("BLITZ_E01_DISK_TRIAGE_FALLBACK", "1").strip().lower()
    return value not in {"0", "false", "no", "off"}


def _timeline_failure_reason(result: dict[str, Any]) -> str:
    execution = _dict_value(result, "execution")
    outputs = _dict_value(result, "outputs")
    exit_code = _int_value(execution.get("exit_code"))
    primary = outputs.get("primary_output")
    stderr = outputs.get("stderr")
    return (
        f"exit_code={exit_code}; primary_output={primary or 'missing'}; "
        f"stderr={stderr or 'missing'}"
    )


def _read_text_with_signal(
    path: Path,
    evidence: EvidenceRecord,
    source: str,
    warnings: list[SignalWarning],
) -> str:
    try:
        text, decoded_warnings = decode_with_signal(
            path.read_bytes(),
            artifact=evidence.evidence_id,
            source=source,
        )
    except OSError:
        warnings.append(parser_crash_warning(artifact=evidence.evidence_id, parser=source, exit_code=1))
        return ""
    warnings.extend(decoded_warnings)
    return text


def _build_correlation_scope(
    *,
    manifest: EvidenceManifest,
    tool_results: list[dict[str, Any]],
    normalized_event_count: int,
    analysis_event_count: int,
    evidence_event_counts: dict[str, int],
    event_category_counts: dict[str, int],
    evidence_without_normalized_events: tuple[str, ...],
    unchecked_or_unsupported_evidence: tuple[str, ...],
    full_sql_correlation: bool,
) -> dict[str, object]:
    evidence_type_counts = Counter(evidence.evidence_type.value for evidence in manifest.evidence)
    evidence_category_counts = Counter(evidence.category.value for evidence in manifest.evidence)
    participating_evidence_ids = tuple(sorted(evidence_event_counts))
    memory_scope = _memory_plugin_scope(manifest=manifest, tool_results=tool_results)
    return {
        "schema_version": "correlation-scope.v1",
        "input_evidence_count": len(manifest.evidence),
        "input_evidence_limit": MAX_MANIFEST_EVIDENCE_INPUTS,
        "correlatable_evidence_count": len(participating_evidence_ids),
        "source_mix": "multi_source" if len(participating_evidence_ids) > 1 else "single_source_or_none",
        "correlation_mode": "sqlite_full_store" if full_sql_correlation else "bounded_analysis_events",
        "normalized_event_count": normalized_event_count,
        "analysis_event_count": analysis_event_count,
        "participating_evidence_ids": participating_evidence_ids,
        "evidence_without_normalized_events": tuple(sorted(evidence_without_normalized_events)),
        "unchecked_or_unsupported_evidence": tuple(sorted(unchecked_or_unsupported_evidence)),
        "event_counts_by_evidence": dict(sorted(evidence_event_counts.items())),
        "event_counts_by_category": dict(sorted(event_category_counts.items())),
        "input_evidence_type_counts": dict(sorted(evidence_type_counts.items())),
        "input_evidence_category_counts": dict(sorted(evidence_category_counts.items())),
        "memory_plugin_scope": memory_scope,
        "policy": (
            "All manifest-registered evidence records that produce normalized events enter the same correlation "
            "surface; missing or unsupported sources remain explicit instead of silently increasing confidence."
        ),
    }


def _coverage_counts(
    manifest: EvidenceManifest,
    events: tuple[NormalizedEvent, ...],
    *,
    tool_results: list[dict[str, Any]],
    psort_filter: str | None = None,
) -> tuple[dict[str, int], dict[str, int | None]]:
    expected: dict[str, int | None] = {}
    for evidence in manifest.evidence:
        key = expected_artifact_key(evidence.evidence_type)
        expected[key] = int(expected.get(key, 0) or 0) + 1
    for key in _artifact_keys_from_filter(psort_filter):
        expected[key] = max(int(expected.get(key, 0) or 0), 1)

    observed: dict[str, int] = {}
    event_evidence_ids = {event.evidence_id for event in events}
    for evidence in manifest.evidence:
        if evidence.evidence_id in event_evidence_ids:
            key = expected_artifact_key(evidence.evidence_type)
            observed[key] = observed.get(key, 0) + 1
    for event in events:
        event_key = _artifact_key_from_event(event)
        if event_key is not None:
            observed[event_key] = observed.get(event_key, 0) + 1

    if any(evidence.evidence_type is EvidenceType.MEMORY for evidence in manifest.evidence):
        successful_plugins = _successful_memory_plugins(tool_results)
        observed["Memory Plugin Coverage"] = len(successful_plugins)
        expected["Memory Plugin Coverage"] = len(DEFAULT_MEMORY_TRIAGE_PLUGINS)
    return observed, expected


def _coverage_artifact_types(observed_counts: dict[str, int], expected_counts: dict[str, int | None]) -> tuple[str, ...]:
    preferred_order = (
        "EVTX",
        "Registry",
        "Memory",
        "Memory Plugin Coverage",
        "SRUM",
        "Windows Timeline",
        "USB Artifacts",
        "Browser Artifacts",
        "Timeline",
        "PCAP",
        "Disk Image",
        "Filesystem",
    )
    present = set(observed_counts) | set(expected_counts)
    ordered = [artifact for artifact in preferred_order if artifact in present]
    ordered.extend(sorted(present - set(ordered)))
    return tuple(ordered)


def _artifact_keys_from_filter(psort_filter: str | None) -> set[str]:
    if not psort_filter:
        return set()
    lowered = psort_filter.lower()
    keys: set[str] = set()
    if "windows:evtx" in lowered or "winevtx" in lowered:
        keys.add("EVTX")
    if any(token in lowered for token in ("windows:registry", "winreg", "amcache", "bam")):
        keys.add("Registry")
    if "srum" in lowered:
        keys.add("SRUM")
    if "windows:timeline" in lowered or "windows_timeline" in lowered:
        keys.add("Windows Timeline")
    if "setupapi" in lowered or "usbstor" in lowered or "usb" in lowered:
        keys.add("USB Artifacts")
    if "chrome" in lowered or "firefox" in lowered or "msie" in lowered or "webcache" in lowered:
        keys.add("Browser Artifacts")
    if "pcap" in lowered or "network" in lowered:
        keys.add("PCAP")
    if "prefetch" in lowered or "lnk" in lowered or "tasks" in lowered or "powershell" in lowered:
        keys.add("Timeline")
    return keys


def _artifact_key_from_event(event: NormalizedEvent) -> str | None:
    data_type = event.normalized_fields.get("data_type", "").lower()
    parser = event.normalized_fields.get("parser", "").lower()
    category = event.category.lower()
    if event.source_parser == "volatility" or event.source_tool == "volatility":
        return "Memory"
    if "windows:evtx" in data_type or parser == "winevtx":
        return "EVTX"
    if "srum" in data_type or "srum" in parser:
        return "SRUM"
    if "windows:timeline" in data_type or "windows_timeline" in parser:
        return "Windows Timeline"
    if "setupapi" in data_type or "setupapi" in parser or "usbstor" in parser or "usb" in parser:
        return "USB Artifacts"
    if "windows:registry" in data_type or parser.startswith("winreg") or "amcache" in parser or "bam" in parser:
        return "Registry"
    if any(token in data_type or token in parser for token in ("chrome", "firefox", "msie", "webcache")):
        return "Browser Artifacts"
    if category.startswith("network_"):
        return "PCAP"
    if category.startswith("memory_"):
        return "Memory"
    return None


def _memory_plugin_scope(
    *,
    manifest: EvidenceManifest,
    tool_results: list[dict[str, Any]],
) -> dict[str, object]:
    if not any(evidence.evidence_type is EvidenceType.MEMORY for evidence in manifest.evidence):
        return {}
    expected = DEFAULT_MEMORY_TRIAGE_PLUGINS
    successful = _successful_memory_plugins(tool_results)
    attempted = _attempted_memory_plugins(tool_results)
    missing = tuple(plugin for plugin in expected if plugin not in successful)
    return {
        "schema_version": "memory-plugin-scope.v1",
        "expected_plugins": expected,
        "attempted_plugins": attempted,
        "successful_plugins": successful,
        "missing_expected_plugins": missing,
        "scope_note": (
            "A memory image is not cleared by process listing alone. Suspicious-process, command-line, network, "
            "process-scan, and malfind coverage must either succeed or remain explicit unknowns."
        ),
    }


def _attempted_memory_plugins(tool_results: list[dict[str, Any]]) -> tuple[str, ...]:
    plugins: list[str] = []
    seen: set[str] = set()
    for result in tool_results:
        if str(result.get("typed_tool") or result.get("tool_name") or "") != "memory":
            continue
        plugin = _memory_plugin_from_result(result)
        if plugin in seen:
            continue
        seen.add(plugin)
        plugins.append(plugin)
    return tuple(plugins)


def _successful_memory_plugins(tool_results: list[dict[str, Any]]) -> tuple[str, ...]:
    plugins: list[str] = []
    seen: set[str] = set()
    for result in tool_results:
        if str(result.get("typed_tool") or result.get("tool_name") or "") != "memory":
            continue
        execution = _dict_value(result, "execution")
        if _int_value(execution.get("exit_code")) != 0:
            continue
        plugin = _memory_plugin_from_result(result)
        if plugin in seen:
            continue
        seen.add(plugin)
        plugins.append(plugin)
    return tuple(plugins)


def _memory_plugin_from_result(result: dict[str, Any]) -> str:
    outputs = _dict_value(result, "outputs")
    primary = outputs.get("primary_output")
    if not isinstance(primary, str):
        return "windows.pslist"
    name = Path(primary).name
    suffix = ".json"
    if not name.endswith(suffix):
        return "windows.pslist"
    stem = name[: -len(suffix)]
    evidence_id = str(result.get("evidence_id") or "")
    prefix = f"{evidence_id}."
    if evidence_id and stem.startswith(prefix):
        plugin_token = stem[len(prefix) :]
    elif "." in stem:
        plugin_token = stem.split(".", 1)[1]
    else:
        return "windows.pslist"
    return plugin_token.replace("_", ".") or "windows.pslist"


def _derive_findings(events: tuple[NormalizedEvent, ...]) -> tuple[CorrelatedFinding, ...]:
    findings = list(detect_persistence(events))
    covered_event_ids = {event_id for finding in findings for event_id in finding.supporting_event_ids}
    for group in stitch_events(events):
        if any(event_id in covered_event_ids for event_id in group.event_ids):
            continue
        if group.category == "unknown":
            continue
        confidence = assess_confidence(group.evidence)
        group_events = tuple(event for event in events if event.event_id in group.event_ids)
        triage_score, suspicion_reasons = assess_group_suspicion(group_events)
        findings.append(
            CorrelatedFinding(
                finding_id=stable_correlation_id("FIND", "activity", group.group_id),
                finding_type="triage_activity",
                title=f"Activity cluster: {group.category}",
                summary=(
                    f"{len(group.event_ids)} normalized event(s) observed for "
                    f"{group.subject} from typed tool output."
                ),
                category=group.category,
                supporting_event_ids=group.event_ids,
                evidence=group.evidence,
                confidence=confidence.score,
                confidence_modifiers=confidence.modifiers,
                triage_score=triage_score,
                suspicion_reasons=suspicion_reasons,
            )
        )
        if len(findings) >= 25:
            break
    return tuple(findings)


def _run_bounded_reasoning(
    *,
    enable_reasoning: bool,
    events: tuple[NormalizedEvent, ...],
    findings: tuple[CorrelatedFinding, ...],
    contradictions: Any,
    warnings: tuple[SignalWarning, ...],
    coverage: dict[str, Any],
    confidence: dict[str, Any],
    audit: AuditLogger,
) -> BoundedReasoningOutcome:
    if not enable_reasoning:
        audit.append("reasoning_skipped", {"reason": "not_enabled"})
        return BoundedReasoningOutcome(
            reasoning=None,
            enabled=False,
            status="skipped",
            reason="not_enabled",
            details={},
        )
    try:
        config = provider_config_from_env()
        provider = OpenAICompatibleProvider(config)
        context = build_reasoning_context(
            events=events,
            findings=findings,
            contradictions=contradictions,
            warnings=warnings,
            coverage=coverage,
            confidence=confidence,
        )
        context_details = _bounded_reasoning_context_details(context)
        audit.append(
            "reasoning_provider_request_started",
            {
                "provider": config.provider,
                "model": config.model,
                "raw_evidence_sent": False,
                "raw_tool_output_sent": False,
                **context_details,
            },
        )
        result = run_analyst_reasoning(provider=provider, model=config.model, context=context)
    except ReasoningProviderError as exc:
        reason = str(exc)
        provider_name = os.getenv("LLM_PROVIDER", "openai-compatible")
        model = os.getenv("LLM_MODEL", "")
        context_details = locals().get("context_details", {})
        audit.append(
            "reasoning_skipped",
            {
                "reason": "provider_failed",
                "error": reason,
                "provider": provider_name,
                "model": model,
                "raw_evidence_sent": False,
                "raw_tool_output_sent": False,
                **context_details,
            },
        )
        audit.append(
            "plan_change",
            {
                "reason": (
                    "Bounded LLM reasoning provider failed; Blitz continued deterministic reporting "
                    "without treating missing LLM output as evidence."
                ),
                "from": "bounded_llm_reasoning",
                "to": "deterministic_reporting_without_llm_reasoning",
                "provider": provider_name,
                "model": model,
            },
        )
        return BoundedReasoningOutcome(
            reasoning=None,
            enabled=True,
            status="provider_failed",
            reason=reason,
            details={
                "provider": provider_name,
                "model": model,
                **context_details,
            },
        )
    audit.append(
        "reasoning_completed",
        {
            "provider": config.provider,
            "model": config.model,
            "prompt_hash": result.prompt_hash,
            "hypothesis_count": len(result.hypotheses),
            "raw_evidence_sent": False,
            "raw_tool_output_sent": False,
            **context_details,
        },
    )
    return BoundedReasoningOutcome(
        reasoning=result,
        enabled=True,
        status="completed",
        reason="completed",
        details={
            "provider": config.provider,
            "model": config.model,
            "prompt_hash": result.prompt_hash,
            "hypothesis_count": len(result.hypotheses),
            **context_details,
        },
    )


def _bounded_reasoning_context_details(context: Any) -> dict[str, Any]:
    payload = json.dumps(context.model_dump(), separators=(",", ":"), ensure_ascii=True)
    return {
        "prompt_context_event_count": len(context.events),
        "prompt_context_finding_count": len(context.findings),
        "prompt_context_contradiction_count": len(context.contradictions),
        "prompt_context_warning_count": len(context.warnings),
        "prompt_context_bytes": len(payload.encode("utf-8")),
        "llm_timeout_seconds": os.getenv("LLM_TIMEOUT_SECONDS", "120"),
        "llm_max_tokens": os.getenv("LLM_MAX_TOKENS", "request_default_1200"),
        "llm_response_format_json": os.getenv("LLM_RESPONSE_FORMAT_JSON", "0"),
    }


def _average_confidence(findings: tuple[CorrelatedFinding, ...]) -> float:
    if not findings:
        return 0.0
    return sum(finding.confidence for finding in findings) / len(findings)


def _parser_summary(result: ParserResult) -> dict[str, Any]:
    return {
        "parser": result.parser,
        "source_tool": result.source_tool,
        "evidence_id": result.evidence_id,
        "processed_count": result.processed_count,
        "malformed_count": result.malformed_count,
        "truncated": result.truncated,
        "warning_count": len(result.warnings),
    }


def _tool_result_summary(result: dict[str, Any]) -> dict[str, Any]:
    execution = _dict_value(result, "execution")
    outputs = _dict_value(result, "outputs")
    integrity = _dict_value(result, "tool_integrity")
    return {
        "typed_tool": result.get("typed_tool"),
        "tool_name": result.get("tool_name"),
        "evidence_id": result.get("evidence_id"),
        "exit_code": execution.get("exit_code"),
        "duration_ms": execution.get("duration_ms"),
        "timed_out": execution.get("timed_out"),
        "primary_output": outputs.get("primary_output"),
        "output_hash": outputs.get("output_hash"),
        "tool_verified": integrity.get("verified"),
        "raw_output_returned": result.get("raw_output_returned"),
    }


def _dict_value(value: dict[str, Any], key: str) -> dict[str, Any]:
    item = value.get(key)
    return item if isinstance(item, dict) else {}


def _int_value(value: object) -> int:
    return value if isinstance(value, int) else 0


def _configured_max_events() -> int:
    return get_max_events()


def _protocol_sift_context() -> dict[str, Any]:
    run_root = os.environ.get("BLITZ_RUN_ROOT")
    case_root = os.environ.get("CASE_ROOT")
    workflow = os.environ.get("BLITZ_PROTOCOL_SIFT_WORKFLOW", "protocol_sift_compatible_direct_analysis")
    agent_framework = os.environ.get("BLITZ_AGENT_FRAMEWORK", "supervised_sift_launcher")
    return {
        "workflow": workflow,
        "agent_framework": agent_framework,
        "case_root": case_root,
        "run_root": run_root,
        "control_path": "Protocol SIFT / SIFT launcher -> Blitz typed evidence pipeline -> SIFT forensic tools",
        "generic_shell_exposed": False,
        "raw_evidence_to_llm": False,
        "raw_tool_output_to_llm": False,
        "claim_boundary": (
            "This layer records Protocol SIFT-compatible workflow context. Findings still require "
            "manifest evidence, typed tool output, parser validation, normalization, correlation, and audit traceability."
        ),
    }


def _sqlite_backed_normalization_requested() -> bool:
    raw = os.environ.get("BLITZ_SQLITE_NORMALIZATION", "").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    analysis_limit = _analysis_event_limit()
    return analysis_limit is not None and get_max_events() > analysis_limit


def _parser_record_memory_limit() -> int:
    limit = _export_limit("BLITZ_PARSER_RECORD_EXPORT_LIMIT")
    return DEFAULT_PARSER_RECORD_EXPORT_LIMIT if limit is None else limit


def _try_sqlite_backed_normalization(
    *,
    session: CaseSession,
    tool_results: list[dict[str, Any]],
    parser_results: list[ParserResult] | None = None,
    evidence_by_id: dict[str, EvidenceRecord],
    full_sql_correlation: bool = False,
) -> SQLiteNormalizationResult | None:
    if not _sqlite_backed_normalization_requested():
        return None

    sources: list[tuple[str, Path, EvidenceRecord]] = []
    for result in tool_results:
        tool = str(result.get("typed_tool") or result.get("tool_name") or "")
        if tool not in {"psort", "disk_triage"}:
            continue
        evidence_id = str(result.get("evidence_id") or "")
        evidence = evidence_by_id.get(evidence_id)
        output_path = _primary_output_path(result, session)
        if evidence is None or output_path is None or not output_path.exists():
            continue
        sources.append((tool, output_path, evidence))

    if not sources:
        return None

    store_path = session.findings_dir / "event_store.sqlite"
    store_path.parent.mkdir(parents=True, exist_ok=True)
    max_events = get_max_events()
    analysis_limit = _sqlite_analysis_event_memory_limit(max_events=max_events, full_sql_correlation=full_sql_correlation)
    checkpoint_interval = _sqlite_normalization_checkpoint_interval()
    analysis_events: list[NormalizedEvent] = []
    warnings_by_key: dict[tuple[str, str, str, str | None, str], SignalWarning] = {}
    processed_count = 0
    total_rows = 0
    malformed_count = 0

    def update_normalization_progress(processed: int, total: int, source: str, source_rows_seen: int) -> None:
        details = {
            "strategy": "sqlite_streaming",
            "source": source,
            "live_processed_normalized_rows": processed,
            "live_source_rows_seen": source_rows_seen,
            "configured_normalized_event_cap": total,
            "analysis_event_memory_limit": analysis_limit,
            "analysis_events_retained": len(analysis_events),
            "sqlite_checkpoint_interval": checkpoint_interval,
            "progress_denominator": "configured_normalized_event_cap",
        }
        write_session_state(
            session=session,
            status="RUNNING",
            phase="normalization_running",
            details=details,
        )
        write_progress_state(
            session=session,
            status="RUNNING",
            current_layer="normalization",
            layer_status="RUNNING",
            details=details,
            processed_items=processed,
            total_items=max(total, 1),
        )

    connection = sqlite3.connect(store_path)
    try:
        _configure_sqlite_for_streaming(connection)
        normalized_table = "normalized_events"
        staging_table = "normalized_events_next"
        _initialize_normalized_event_store(connection, table_name=staging_table)
        connection.execute(f"DELETE FROM {staging_table}")
        connection.commit()

        streamed_sources = {(tool, evidence.evidence_id) for tool, _, evidence in sources}
        source_total, source_malformed, source_processed = _stream_parser_results_normalization_to_sqlite(
            connection=connection,
            table_name=staging_table,
            parser_results=parser_results or [],
            evidence_by_id=evidence_by_id,
            streamed_sources=streamed_sources,
            max_events=max_events,
            already_processed=processed_count,
            analysis_limit=analysis_limit,
            checkpoint_interval=checkpoint_interval,
            analysis_events=analysis_events,
            warnings_by_key=warnings_by_key,
            progress_callback=update_normalization_progress,
        )
        total_rows += source_total
        malformed_count += source_malformed
        processed_count += source_processed

        for source_tool, source_path, evidence in sources:
            if source_tool == "psort":
                source_total, source_malformed, source_processed = _stream_plaso_normalization_to_sqlite(
                    connection=connection,
                    table_name=staging_table,
                    source_path=source_path,
                    evidence=evidence,
                    max_events=max_events,
                    already_processed=processed_count,
                    analysis_limit=analysis_limit,
                    checkpoint_interval=checkpoint_interval,
                    analysis_events=analysis_events,
                    warnings_by_key=warnings_by_key,
                    progress_callback=update_normalization_progress,
                )
            else:
                source_total, source_malformed, source_processed = _stream_disk_triage_normalization_to_sqlite(
                    connection=connection,
                    table_name=staging_table,
                    source_path=source_path,
                    evidence=evidence,
                    max_events=max_events,
                    already_processed=processed_count,
                    analysis_limit=analysis_limit,
                    checkpoint_interval=checkpoint_interval,
                    analysis_events=analysis_events,
                    warnings_by_key=warnings_by_key,
                    progress_callback=update_normalization_progress,
                )
            total_rows += source_total
            malformed_count += source_malformed
            processed_count += source_processed

        if total_rows > max_events:
            warning = event_cap_warning(artifact="normalized_batch", processed=max_events, total=total_rows)
            warnings_by_key[_warning_key(warning)] = warning

        _replace_normalized_event_store(connection, staging_table=staging_table, target_table=normalized_table)
        _create_normalized_event_indexes(connection)
        connection.commit()
        _checkpoint_open_sqlite_connection(connection)
    finally:
        connection.close()

    warnings = tuple(warnings_by_key.values())
    if malformed_count:
        malformed = make_warning(
            "MALFORMED_RECORDS",
            artifact="normalized_batch",
            severity="MEDIUM",
            impact=f"{malformed_count} normalized source row(s) had missing timestamp values",
            metadata={"malformed_count": malformed_count},
        )
        warnings = (*warnings, malformed)

    return SQLiteNormalizationResult(
        events=sort_normalized_events(analysis_events),
        warnings=warnings,
        processed_count=min(processed_count, max_events),
        truncated=total_rows > max_events or any(
            warning.warning_type == "DISK_TRIAGE_TRUNCATED" for warning in warnings_by_key.values()
        ),
        store_path=store_path,
        analysis_event_memory_limit=analysis_limit,
    )


def _stream_parser_results_normalization_to_sqlite(
    *,
    connection: sqlite3.Connection,
    table_name: str,
    parser_results: list[ParserResult],
    evidence_by_id: dict[str, EvidenceRecord],
    streamed_sources: set[tuple[str, str]],
    max_events: int,
    already_processed: int,
    analysis_limit: int,
    checkpoint_interval: int,
    analysis_events: list[NormalizedEvent],
    warnings_by_key: dict[tuple[str, str, str, str | None, str], SignalWarning],
    progress_callback: Callable[[int, int, str, int], None] | None = None,
) -> tuple[int, int, int]:
    total_rows = 0
    malformed_count = 0
    processed_count = 0
    pending_rows: list[
        tuple[int, str, str, str, str, str, str, str, str, str, str, float, str, str, str, str]
    ] = []
    last_checkpoint_update = 0

    for result in parser_results:
        if (result.source_tool, result.evidence_id) in streamed_sources:
            continue
        evidence = evidence_by_id.get(result.evidence_id)
        if evidence is None:
            continue
        total_rows += result.processed_count
        malformed_count += result.malformed_count
        for warning in result.warnings:
            warnings_by_key.setdefault(_warning_key(warning), warning)
        if result.processed_count > len(result.records):
            warning = make_warning(
                "SQLITE_NORMALIZATION_SOURCE_SAMPLE_ONLY",
                artifact=result.evidence_id,
                severity="HIGH",
                impact=(
                    f"{result.source_tool} parser retained {len(result.records)} record(s) but reported "
                    f"{result.processed_count}; only retained records can be materialized unless a streaming "
                    "normalizer exists for that source."
                ),
                tool=result.source_tool,
            )
            warnings_by_key.setdefault(_warning_key(warning), warning)
        for record in result.records:
            if already_processed + processed_count >= max_events:
                break
            event = normalize_parsed_record(record, evidence=evidence)
            for warning in (*result.warnings, *record.warnings, *event.warnings):
                warnings_by_key.setdefault(_warning_key(warning), warning)
            global_row_number = already_processed + processed_count + 1
            pending_rows.append(_normalized_event_sqlite_row(event, global_row_number))
            if len(analysis_events) < analysis_limit:
                analysis_events.append(event)
            processed_count += 1
            if len(pending_rows) >= 5000:
                _insert_normalized_events(connection, pending_rows, table_name=table_name)
                connection.commit()
                global_processed = already_processed + processed_count
                last_checkpoint_update = _maybe_checkpoint_streaming_sqlite(
                    connection,
                    processed=global_processed,
                    last_checkpoint=last_checkpoint_update,
                    interval=checkpoint_interval,
                )
                pending_rows.clear()

    if pending_rows:
        _insert_normalized_events(connection, pending_rows, table_name=table_name)
        connection.commit()
        _maybe_checkpoint_streaming_sqlite(
            connection,
            processed=already_processed + processed_count,
            last_checkpoint=last_checkpoint_update,
            interval=checkpoint_interval,
        )
    if progress_callback is not None and processed_count:
        progress_callback(already_processed + processed_count, max_events, "parser_results", processed_count)
    return total_rows, malformed_count, processed_count


def _write_in_memory_normalized_events_to_sqlite(
    *,
    session: CaseSession,
    events: tuple[NormalizedEvent, ...],
) -> Path:
    store_path = session.findings_dir / "event_store.sqlite"
    store_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(store_path)
    try:
        _configure_sqlite_for_streaming(connection)
        normalized_table = "normalized_events"
        staging_table = "normalized_events_next"
        _initialize_normalized_event_store(connection, table_name=staging_table)
        connection.execute(f"DELETE FROM {staging_table}")
        pending_rows: list[tuple[int, str, str, str, str, str, str, str, str, str, str, float, str, str, str, str]] = []
        for row_number, event in enumerate(events, 1):
            pending_rows.append(_normalized_event_sqlite_row(event, row_number))
            if len(pending_rows) >= 5000:
                _insert_normalized_events(connection, pending_rows, table_name=staging_table)
                connection.commit()
                pending_rows.clear()
        if pending_rows:
            _insert_normalized_events(connection, pending_rows, table_name=staging_table)
        _replace_normalized_event_store(connection, staging_table=staging_table, target_table=normalized_table)
        _create_normalized_event_indexes(connection)
        connection.commit()
    finally:
        connection.close()
    return store_path


def _configure_sqlite_for_streaming(connection: sqlite3.Connection) -> None:
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.execute("PRAGMA temp_store=FILE")
    connection.execute("PRAGMA cache_size=-64000")


def _checkpoint_open_sqlite_connection(connection: sqlite3.Connection) -> bool:
    try:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except sqlite3.Error:
        return False
    return True


def _maybe_checkpoint_streaming_sqlite(
    connection: sqlite3.Connection,
    *,
    processed: int,
    last_checkpoint: int,
    interval: int,
) -> int:
    if interval <= 0 or processed - last_checkpoint < interval:
        return last_checkpoint
    if _checkpoint_open_sqlite_connection(connection):
        return processed
    return last_checkpoint


def _checkpoint_sqlite_event_store(store_path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "event_store": str(store_path),
        "exists": store_path.exists(),
        "wal_exists_before": store_path.with_name(store_path.name + "-wal").exists(),
        "shm_exists_before": store_path.with_name(store_path.name + "-shm").exists(),
    }
    if not store_path.exists():
        result["status"] = "skipped_missing_store"
        return result
    try:
        with sqlite3.connect(store_path) as connection:
            checkpoint_row = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            journal_row = connection.execute("PRAGMA journal_mode=DELETE").fetchone()
            connection.commit()
    except sqlite3.Error as exc:
        result["status"] = "failed"
        result["error"] = str(exc)
        return result
    result.update(
        {
            "status": "completed",
            "checkpoint_result": list(checkpoint_row) if checkpoint_row is not None else None,
            "journal_mode": journal_row[0] if journal_row else None,
            "wal_exists_after": store_path.with_name(store_path.name + "-wal").exists(),
            "shm_exists_after": store_path.with_name(store_path.name + "-shm").exists(),
            "size_bytes": store_path.stat().st_size,
        }
    )
    return result


def _initialize_normalized_event_store(connection: sqlite3.Connection, *, table_name: str = "normalized_events") -> None:
    table = _normalized_store_table_name(table_name)
    connection.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {table} (
            row_number INTEGER PRIMARY KEY,
            event_id TEXT NOT NULL,
            timestamp_utc TEXT NOT NULL,
            category TEXT NOT NULL,
            artifact TEXT NOT NULL,
            message TEXT NOT NULL,
            source_tool TEXT NOT NULL,
            source_parser TEXT NOT NULL,
            evidence_id TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            trust_level TEXT NOT NULL,
            confidence REAL NOT NULL,
            raw_reference_json TEXT NOT NULL,
            normalized_fields_json TEXT NOT NULL,
            provenance_json TEXT NOT NULL,
            warnings_json TEXT NOT NULL
        )
        """
    )


def _replace_normalized_event_store(
    connection: sqlite3.Connection,
    *,
    staging_table: str,
    target_table: str,
) -> None:
    staging = _normalized_store_table_name(staging_table)
    target = _normalized_store_table_name(target_table)
    previous = _normalized_store_table_name("normalized_events_previous")
    target_exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (target,),
    ).fetchone()
    connection.execute("DROP TABLE IF EXISTS normalized_events_previous")
    if target_exists:
        connection.execute(f"ALTER TABLE {target} RENAME TO {previous}")
    connection.execute(f"ALTER TABLE {staging} RENAME TO {target}")
    connection.execute("DROP TABLE IF EXISTS normalized_events_previous")


def _normalized_store_table_name(table_name: str) -> str:
    allowed = {"normalized_events", "normalized_events_next", "normalized_events_previous"}
    if table_name not in allowed:
        raise ValueError(f"unsupported normalized store table: {table_name}")
    return table_name


def _create_normalized_event_indexes(connection: sqlite3.Connection) -> None:
    connection.execute("CREATE INDEX IF NOT EXISTS idx_normalized_events_event_id ON normalized_events(event_id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_normalized_events_timestamp ON normalized_events(timestamp_utc)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_normalized_events_evidence ON normalized_events(evidence_id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_normalized_events_category ON normalized_events(category)")


def _stream_plaso_normalization_to_sqlite(
    *,
    connection: sqlite3.Connection,
    table_name: str,
    source_path: Path,
    evidence: EvidenceRecord,
    max_events: int,
    already_processed: int,
    analysis_limit: int,
    checkpoint_interval: int,
    analysis_events: list[NormalizedEvent],
    warnings_by_key: dict[tuple[str, str, str, str | None, str], SignalWarning],
    progress_callback: Callable[[int, int, str, int], None] | None = None,
) -> tuple[int, int, int]:
    total_rows = 0
    malformed_count = 0
    processed_count = 0
    pending_rows: list[
        tuple[int, str, str, str, str, str, str, str, str, str, str, float, str, str, str, str]
    ] = []
    last_progress_update = 0
    last_checkpoint_update = 0
    with source_path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            warning = make_warning(
                "PARSER_DEGRADATION",
                artifact=evidence.evidence_id,
                severity="HIGH",
                impact="psort CSV output had no header during SQLite-backed normalization",
                tool="psort",
            )
            warnings_by_key[_warning_key(warning)] = warning
            return 0, 1, 0
        for row_number, row in enumerate(reader, 1):
            total_rows = row_number
            if already_processed + processed_count >= max_events:
                continue
            if not (row.get("datetime") or row.get("timestamp") or row.get("date")):
                malformed_count += 1
            record_warnings: list[SignalWarning] = []
            record = make_record(
                parser="plaso",
                source_tool="psort",
                evidence=evidence,
                timestamp=row.get("datetime") or row.get("timestamp") or row.get("date"),
                event_type=row.get("source") or row.get("parser") or row.get("event_type") or "timeline_event",
                artifact=row.get("filename") or row.get("source_long") or row.get("source") or evidence.evidence_id,
                message=row.get("message") or row.get("description") or "",
                raw_reference=row.get("inode") or row.get("display_name"),
                fields=dict(row),
                warnings=record_warnings,
            )
            event = normalize_parsed_record(record, evidence=evidence)
            for warning in (*record_warnings, *event.warnings):
                warnings_by_key.setdefault(_warning_key(warning), warning)
            global_row_number = already_processed + processed_count + 1
            pending_rows.append(_normalized_event_sqlite_row(event, global_row_number))
            if len(analysis_events) < analysis_limit:
                analysis_events.append(event)
            processed_count += 1
            if len(pending_rows) >= 5000:
                _insert_normalized_events(connection, pending_rows, table_name=table_name)
                connection.commit()
                pending_rows.clear()
                global_processed = already_processed + processed_count
                last_checkpoint_update = _maybe_checkpoint_streaming_sqlite(
                    connection,
                    processed=global_processed,
                    last_checkpoint=last_checkpoint_update,
                    interval=checkpoint_interval,
                )
                if progress_callback is not None and global_processed - last_progress_update >= 50_000:
                    progress_callback(global_processed, max_events, source_path.name, processed_count)
                    last_progress_update = global_processed

    if pending_rows:
        _insert_normalized_events(connection, pending_rows, table_name=table_name)
        connection.commit()
        _maybe_checkpoint_streaming_sqlite(
            connection,
            processed=already_processed + processed_count,
            last_checkpoint=last_checkpoint_update,
            interval=checkpoint_interval,
        )
    if progress_callback is not None:
        progress_callback(already_processed + processed_count, max_events, source_path.name, processed_count)
    return total_rows, malformed_count, processed_count


def _stream_disk_triage_normalization_to_sqlite(
    *,
    connection: sqlite3.Connection,
    table_name: str,
    source_path: Path,
    evidence: EvidenceRecord,
    max_events: int,
    already_processed: int,
    analysis_limit: int,
    checkpoint_interval: int,
    analysis_events: list[NormalizedEvent],
    warnings_by_key: dict[tuple[str, str, str, str | None, str], SignalWarning],
    progress_callback: Callable[[int, int, str, int], None] | None = None,
) -> tuple[int, int, int]:
    try:
        payload = load_disk_triage_payload(source_path)
    except (OSError, json.JSONDecodeError):
        warning = make_warning(
            "PARSER_DEGRADATION",
            artifact=evidence.evidence_id,
            severity="HIGH",
            impact="disk triage JSON output could not be read during SQLite-backed normalization",
            tool="disk_triage",
        )
        warnings_by_key[_warning_key(warning)] = warning
        return 0, 1, 0

    for warning in disk_triage_payload_warnings(payload, evidence, summary_path=source_path):
        warnings_by_key.setdefault(_warning_key(warning), warning)

    try:
        reported_total = int(payload.get("entry_count") or 0)
    except (TypeError, ValueError):
        reported_total = 0
    if already_processed >= max_events:
        return reported_total, 0, 0

    total_rows = 0
    malformed_count = 0
    processed_count = 0
    pending_rows: list[
        tuple[int, str, str, str, str, str, str, str, str, str, str, float, str, str, str, str]
    ] = []
    last_progress_update = 0
    last_checkpoint_update = 0

    for row_number, record in enumerate(iter_disk_triage_records(payload, evidence, summary_path=source_path), 1):
        total_rows = row_number
        if already_processed + processed_count >= max_events:
            if reported_total:
                total_rows = reported_total
                break
            continue
        if not record.timestamp:
            malformed_count += 1
        event = normalize_parsed_record(record, evidence=evidence)
        for warning in (*record.warnings, *event.warnings):
            warnings_by_key.setdefault(_warning_key(warning), warning)
        global_row_number = already_processed + processed_count + 1
        pending_rows.append(_normalized_event_sqlite_row(event, global_row_number))
        if len(analysis_events) < analysis_limit:
            analysis_events.append(event)
        processed_count += 1
        if len(pending_rows) >= 5000:
            _insert_normalized_events(connection, pending_rows, table_name=table_name)
            connection.commit()
            pending_rows.clear()
            global_processed = already_processed + processed_count
            last_checkpoint_update = _maybe_checkpoint_streaming_sqlite(
                connection,
                processed=global_processed,
                last_checkpoint=last_checkpoint_update,
                interval=checkpoint_interval,
            )
            if progress_callback is not None and global_processed - last_progress_update >= 50_000:
                progress_callback(global_processed, max_events, source_path.name, processed_count)
                last_progress_update = global_processed

    total_rows = max(total_rows, reported_total)
    if pending_rows:
        _insert_normalized_events(connection, pending_rows, table_name=table_name)
        connection.commit()
        _maybe_checkpoint_streaming_sqlite(
            connection,
            processed=already_processed + processed_count,
            last_checkpoint=last_checkpoint_update,
            interval=checkpoint_interval,
        )
    if progress_callback is not None:
        progress_callback(already_processed + processed_count, max_events, source_path.name, processed_count)
    return total_rows, malformed_count, processed_count


def _normalized_event_sqlite_row(
    event: NormalizedEvent,
    row_number: int,
) -> tuple[int, str, str, str, str, str, str, str, str, str, str, float, str, str, str, str]:
    return (
        row_number,
        event.event_id,
        event.timestamp_utc,
        event.category,
        event.artifact,
        event.message,
        event.source_tool,
        event.source_parser,
        event.evidence_id,
        event.evidence_type.value,
        event.trust_level.value,
        event.confidence,
        _compact_json(event.raw_reference.model_dump(mode="json")),
        _compact_json(event.normalized_fields),
        _compact_json(event.provenance),
        _compact_json([warning.model_dump(mode="json") for warning in event.warnings]),
    )


def _insert_normalized_events(
    connection: sqlite3.Connection,
    rows: list[tuple[int, str, str, str, str, str, str, str, str, str, str, float, str, str, str, str]],
    *,
    table_name: str = "normalized_events",
) -> None:
    table = _normalized_store_table_name(table_name)
    connection.executemany(
        f"""
        INSERT OR REPLACE INTO {table} (
            row_number,
            event_id,
            timestamp_utc,
            category,
            artifact,
            message,
            source_tool,
            source_parser,
            evidence_id,
            evidence_type,
            trust_level,
            confidence,
            raw_reference_json,
            normalized_fields_json,
            provenance_json,
            warnings_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )


def _compact_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _bounded_analysis_events(
    events: tuple[NormalizedEvent, ...],
) -> tuple[tuple[NormalizedEvent, ...], SignalWarning | None]:
    limit = _analysis_event_limit()
    if limit is None or len(events) <= limit:
        return events, None
    bounded = events[:limit]
    return bounded, _analysis_scope_warning(normalized_event_count=len(events), analysis_event_count=limit)


def _analysis_scope_warning(*, normalized_event_count: int, analysis_event_count: int) -> SignalWarning:
    warning = make_warning(
        "ANALYSIS_SCOPE_LIMIT",
        artifact="normalized_events",
        severity="HIGH",
        impact=(
            f"correlation, validation, and reports used {analysis_event_count} of "
            f"{normalized_event_count} normalized events; "
            "full accounting retains all exported rows"
        ),
        confidence_penalty=0.12,
        metadata={
            "analysis_events": analysis_event_count,
            "normalized_events": normalized_event_count,
            "full_accounting_required": True,
        },
    )
    return warning


def _warning_key(warning: SignalWarning) -> tuple[str, str, str, str | None, str]:
    return (
        warning.warning_type,
        warning.severity,
        warning.artifact,
        warning.tool,
        warning.impact,
    )


def _analysis_event_limit() -> int | None:
    raw = os.environ.get("BLITZ_ANALYSIS_EVENT_LIMIT")
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError:
        return None
    if value < 1:
        return None
    return min(value, 2_000_000)


def _sqlite_analysis_event_memory_limit(*, max_events: int, full_sql_correlation: bool) -> int:
    configured = _analysis_event_limit()
    if full_sql_correlation:
        sqlite_limit = _bounded_int_env("BLITZ_SQLITE_ANALYSIS_EVENT_MEMORY_LIMIT", default=50_000, upper=250_000)
        if configured is not None:
            return min(sqlite_limit, configured, max_events)
        return min(sqlite_limit, max_events)
    if configured is not None:
        return min(configured, max_events)
    return max_events


def _sqlite_normalization_checkpoint_interval() -> int:
    return _bounded_int_env("BLITZ_SQLITE_NORMALIZATION_CHECKPOINT_INTERVAL", default=100_000, upper=1_000_000)


def _sql_correlation_finding_limit() -> int:
    return _bounded_int_env("BLITZ_SQL_CORRELATION_FINDING_LIMIT", default=25_000, upper=100_000)


def _sql_correlation_support_event_limit() -> int:
    return _bounded_int_env("BLITZ_SQL_CORRELATION_SUPPORT_EVENT_LIMIT", default=50_000, upper=250_000)


def _sql_no_finding_context_event_limit() -> int:
    return _bounded_int_env("BLITZ_SQL_NO_FINDING_CONTEXT_EVENT_LIMIT", default=500, upper=10_000)


def _bounded_int_env(env_name: str, *, default: int, upper: int) -> int:
    raw = os.environ.get(env_name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return min(max(value, 0), upper)


def _load_tool_results_checkpoint(session: CaseSession) -> list[dict[str, Any]]:
    path = session.findings_dir / "tool_results.json"
    if path.exists():
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
    return _recover_tool_results_from_audit(session)


def _serializable_parser_results(results: list[ParserResult]) -> list[dict[str, Any]]:
    limit = _export_limit("BLITZ_PARSER_RECORD_EXPORT_LIMIT")
    output: list[dict[str, Any]] = []
    for result in results:
        records = result.records if limit is None else result.records[:limit]
        item = result.model_dump(mode="json", exclude={"records"})
        item["record_count"] = len(result.records)
        item["records_exported"] = len(records)
        item["records_omitted"] = max(result.processed_count - len(records), 0)
        item["records"] = [record.model_dump(mode="json") for record in records]
        output.append(item)
    return output


def _serializable_normalized_events(
    events: tuple[NormalizedEvent, ...],
    *,
    total_events: int | None = None,
) -> dict[str, Any] | list[dict[str, Any]]:
    limit = _export_limit("BLITZ_NORMALIZED_EXPORT_LIMIT")
    total = len(events) if total_events is None else total_events
    if total == len(events) and (limit is None or len(events) <= limit):
        return [event.model_dump(mode="json") for event in events]
    exported = events[:limit]
    return {
        "schema_version": "normalized-events-export.v1",
        "total_events": total,
        "events_exported": len(exported),
        "events_omitted": max(total - len(exported), 0),
        "export_policy": "bounded_sample",
        "note": (
            "Full exported rows are preserved in findings/event_store.sqlite "
            "and summarized in full_accounting.json."
        ),
        "events": [event.model_dump(mode="json") for event in exported],
    }


def _export_limit(env_name: str) -> int | None:
    raw = os.environ.get(env_name)
    if raw is None or raw == "":
        return _default_export_limit(env_name)
    try:
        value = int(raw)
    except ValueError:
        return _default_export_limit(env_name)
    if value < 0:
        return _default_export_limit(env_name)
    return min(value, 2_000_000)


def _default_export_limit(env_name: str) -> int | None:
    if env_name == "BLITZ_NORMALIZED_EXPORT_LIMIT":
        return DEFAULT_NORMALIZED_EXPORT_LIMIT
    if env_name == "BLITZ_PARSER_RECORD_EXPORT_LIMIT":
        return DEFAULT_PARSER_RECORD_EXPORT_LIMIT
    return None


def _recover_tool_results_from_audit(session: CaseSession) -> list[dict[str, Any]]:
    if not session.audit_log_path.exists():
        return []
    recovered: list[dict[str, Any]] = []
    for line in session.audit_log_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        if payload.get("event_type") != "analysis_tool_result":
            continue
        data = payload.get("data")
        if not isinstance(data, dict):
            continue
        primary_output = data.get("primary_output")
        tool = str(data.get("typed_tool") or data.get("tool_name") or "")
        evidence_id = str(data.get("evidence_id") or "")
        if not isinstance(primary_output, str) or not tool or not evidence_id:
            continue
        recovered.append(
            {
                "typed_tool": tool,
                "tool_name": str(data.get("tool_name") or tool),
                "evidence_id": evidence_id,
                "session_id": session.session_id,
                "case_id": session.case_id,
                "execution": {
                    "exit_code": _int_value(data.get("exit_code")),
                    "duration_ms": _int_value(data.get("duration_ms")),
                    "timed_out": bool(data.get("timed_out")),
                    "command_args_hash": "recovered-from-audit",
                    "executable_name": str(data.get("tool_name") or tool),
                },
                "outputs": {
                    "primary_output": primary_output,
                    "stdout": _derived_stdio_output(primary_output, evidence_id, tool, "stdout"),
                    "stderr": _derived_stdio_output(primary_output, evidence_id, tool, "stderr"),
                    "output_hash": data.get("output_hash"),
                    "stdout_hash": None,
                    "stderr_hash": None,
                },
                "tool_integrity": {
                    "executable": str(data.get("tool_name") or tool),
                    "resolved_executable": str(data.get("tool_name") or tool),
                    "expected_sha256": None,
                    "actual_sha256": None,
                    "verified": bool(data.get("tool_verified")),
                    "warnings": [],
                },
                "warnings": [],
                "raw_output_returned": False,
            }
        )
    return recovered


def _derived_stdio_output(primary_output: str, evidence_id: str, tool: str, stream: str) -> str:
    parent = str(Path(primary_output).parent).replace("\\", "/")
    if parent == ".":
        parent = ""
    prefix = f"{parent}/" if parent else ""
    return f"{prefix}{evidence_id}.{tool}.{stream}.txt"


def _relative_session_path(path: Path, session: CaseSession) -> str:
    try:
        return str(path.resolve().relative_to(session.session_root.resolve())).replace("\\", "/")
    except ValueError:
        return str(path)


def _load_full_accounting_checkpoint(path: Path) -> FullAccountingSummary | None:
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    return FullAccountingSummary.model_validate(payload)


def _recover_full_accounting_from_store(
    session: CaseSession,
    tool_results: list[dict[str, Any]],
) -> FullAccountingSummary | None:
    store_path = session.findings_dir / "event_store.sqlite"
    if not store_path.exists():
        return None

    from blitz_dfir.accounting.models import AccountingArtifact

    source_by_artifact = _accounting_sources_by_artifact(session, tool_results)
    artifacts = []
    with sqlite3.connect(store_path) as connection:
        try:
            rows = connection.execute(
                """
                SELECT artifact_id, evidence_id, source_tool, parser, COUNT(*)
                FROM event_rows
                GROUP BY artifact_id, evidence_id, source_tool, parser
                ORDER BY artifact_id
                """
            ).fetchall()
        except sqlite3.Error:
            return None
        for artifact_id, evidence_id, source_tool, parser, row_count in rows:
            source = source_by_artifact.get(str(artifact_id), {})
            artifacts.append(
                AccountingArtifact(
                    artifact_id=str(artifact_id),
                    evidence_id=str(evidence_id),
                    source_tool=str(source_tool),
                    parser=str(parser),
                    source_path=str(source.get("source_path") or ""),
                    source_sha256=source.get("source_sha256"),
                    source_size_bytes=int(source.get("source_size_bytes") or 0),
                    row_count=int(row_count),
                    malformed_count=_count_missing_timestamps(connection, str(artifact_id)),
                    partial=bool(source.get("timed_out")),
                    timed_out=bool(source.get("timed_out")),
                    table_name="event_rows",
                    counts_by_source=_group_counts(connection, str(artifact_id), "source"),
                    counts_by_parser=_group_counts(connection, str(artifact_id), "parser"),
                    counts_by_data_type=_group_counts(connection, str(artifact_id), "data_type"),
                    counts_by_day=_group_day_counts(connection, str(artifact_id)),
                )
            )

    if not artifacts:
        return None
    return FullAccountingSummary(
        event_store_path="findings/event_store.sqlite",
        artifact_count=len(artifacts),
        total_rows=sum(artifact.row_count for artifact in artifacts),
        artifacts=tuple(artifacts),
    )


def _accounting_sources_by_artifact(
    session: CaseSession,
    tool_results: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    sources: dict[str, dict[str, Any]] = {}
    for index, result in enumerate(tool_results, 1):
        outputs = _dict_value(result, "outputs")
        primary = outputs.get("primary_output")
        if not isinstance(primary, str) or not primary.endswith(".csv"):
            continue
        evidence_id = str(result.get("evidence_id") or f"artifact-{index}")
        tool = str(result.get("typed_tool") or result.get("tool_name") or "unknown")
        artifact_id = f"{evidence_id}-{tool}-{index}"
        source_path = session.session_root / primary
        source: dict[str, Any] = {
            "source_path": primary,
            "timed_out": bool(_dict_value(result, "execution").get("timed_out")),
        }
        if source_path.exists():
            source["source_sha256"] = sha256_file(source_path)
            source["source_size_bytes"] = source_path.stat().st_size
        sources[artifact_id] = source
    return sources


def _group_counts(connection: sqlite3.Connection, artifact_id: str, column: str) -> dict[str, int]:
    if column not in {"source", "parser", "data_type"}:
        return {}
    rows = connection.execute(
        f"SELECT COALESCE(NULLIF({column}, ''), 'unknown'), COUNT(*) FROM event_rows WHERE artifact_id = ? GROUP BY {column}",
        (artifact_id,),
    ).fetchall()
    return {str(key): int(count) for key, count in rows}


def _group_day_counts(connection: sqlite3.Connection, artifact_id: str) -> dict[str, int]:
    rows = connection.execute(
        """
        SELECT
          CASE
            WHEN length(timestamp) >= 10
              AND substr(timestamp, 5, 1) = '-'
              AND substr(timestamp, 8, 1) = '-'
            THEN substr(timestamp, 1, 10)
            ELSE 'unknown'
          END AS day,
          COUNT(*)
        FROM event_rows
        WHERE artifact_id = ?
        GROUP BY day
        """,
        (artifact_id,),
    ).fetchall()
    return {str(day): int(count) for day, count in rows}


def _count_missing_timestamps(connection: sqlite3.Connection, artifact_id: str) -> int:
    value = connection.execute(
        "SELECT COUNT(*) FROM event_rows WHERE artifact_id = ? AND COALESCE(timestamp, '') = ''",
        (artifact_id,),
    ).fetchone()
    return int(value[0]) if value else 0


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def _deduplicate_warnings(warnings: tuple[SignalWarning, ...]) -> list[SignalWarning]:
    deduplicated: list[SignalWarning] = []
    seen: set[tuple[str, str, str, str | None, str]] = set()
    for warning in warnings:
        key = (
            warning.warning_type,
            warning.severity,
            warning.artifact,
            warning.tool,
            warning.impact,
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(warning)
    return deduplicated


def _deduplicate_signal_report(report: SignalIntegrityReport) -> SignalIntegrityReport:
    warnings = tuple(_deduplicate_warnings(report.warnings))
    return report.model_copy(
        update={
            "warnings": warnings,
            "confidence_penalty": confidence_penalty_from_warnings(warnings),
            "critical_count": sum(1 for warning in warnings if warning.severity == "CRITICAL"),
            "high_count": sum(1 for warning in warnings if warning.severity == "HIGH"),
        }
    )
