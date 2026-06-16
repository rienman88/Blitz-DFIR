from __future__ import annotations

import json
from pathlib import Path

from blitz_dfir.core.models import EvidenceManifest, EvidenceType
from blitz_dfir.inventory.models import EvidenceInventoryReport, ToolDiscoveryReport
from blitz_dfir.planning.models import (
    CaseObjectiveReport,
    EvidencePriority,
    EvidenceTriageItem,
    EvidenceTriageReport,
    InvestigationPhase,
    InvestigationPlanReport,
)
from blitz_dfir.recovery.models import RecoveryPlanReport
from blitz_dfir.reporting.findings import scrub_report_text

DEFAULT_OBJECTIVE = (
    "Identify evidence-backed malicious, suspicious, or policy-relevant activity while preserving "
    "evidence integrity, documenting unknowns, and avoiding unsupported conclusions."
)

FAMILY_PRIORITY = (
    "event_logs",
    "plaso_timeline",
    "registry",
    "memory",
    "execution_artifacts",
    "pcap",
    "disk_timeline",
    "filesystem",
    "direct_processed",
    "unsupported",
)

FAMILY_NAMES = {
    "direct_processed": "Direct processed evidence",
    "event_logs": "Windows event logs",
    "plaso_timeline": "PLASO timeline",
    "registry": "Registry and persistence",
    "execution_artifacts": "Execution artifacts",
    "memory": "Memory",
    "pcap": "Network PCAP",
    "disk_timeline": "Disk timeline",
    "filesystem": "Filesystem artifacts",
    "unsupported": "Unsupported or manual-review evidence",
}


def build_case_objective(
    *,
    manifest: EvidenceManifest,
    objective_text: str | None = None,
) -> CaseObjectiveReport:
    objective = scrub_report_text((objective_text or DEFAULT_OBJECTIVE).strip() or DEFAULT_OBJECTIVE)
    source = "cli" if objective_text and objective_text.strip() else "default_evidence_first"
    return CaseObjectiveReport(
        case_id=manifest.case_id,
        objective=objective,
        source=source,
        evidence_ids_in_scope=tuple(evidence.evidence_id for evidence in manifest.evidence),
        success_criteria=(
            "Every report claim references normalized evidence or an explicit unknown zone.",
            "Evidence hashes are preserved and generated artifacts are hashed.",
            "Correlation confidence reflects single-source limits, contradictions, and coverage gaps.",
            "Unsupported or unavailable evidence routes remain visible instead of becoming findings.",
        ),
        constraints=(
            "No case objective, prompt, or analyst note can create a finding without evidence support.",
            "Only manifest-registered evidence can enter the automated pipeline.",
            "Only typed and allowlisted tool routes can execute automatically.",
            "Bounded LLM reasoning is disabled unless explicitly enabled and remains INFERRED over bounded summaries.",
        ),
    )


def build_investigation_plan(
    *,
    manifest: EvidenceManifest,
    objective: CaseObjectiveReport,
    tool_discovery: ToolDiscoveryReport,
) -> InvestigationPlanReport:
    families = _families_from_manifest(manifest)
    prioritized = _prioritize_families(families)
    family_to_evidence = {
        family: tuple(
            evidence.evidence_id for evidence in manifest.evidence if _family_for_type(evidence.evidence_type) == family
        )
        for family in prioritized
    }
    available_tools = {tool.tool_name for tool in tool_discovery.tools if tool.status == "AVAILABLE"}
    limitations: list[str] = []
    if not manifest.evidence:
        limitations.append("No evidence records are registered in the manifest.")
    if not available_tools:
        limitations.append("No configured SIFT tools are currently available according to tool discovery.")
    unsupported = family_to_evidence.get("unsupported", ())
    if unsupported:
        limitations.append(f"Unsupported evidence requires manual review: {', '.join(unsupported)}.")

    phases = _build_phases(prioritized, family_to_evidence)
    return InvestigationPlanReport(
        case_id=manifest.case_id,
        mode="evidence_first",
        objective=objective.objective,
        prioritized_artifact_families=prioritized,
        evidence_ids_in_scope=tuple(evidence.evidence_id for evidence in manifest.evidence),
        phases=phases,
        limitations=tuple(scrub_report_text(item) for item in limitations),
    )


def build_evidence_triage(
    *,
    manifest: EvidenceManifest,
    objective: CaseObjectiveReport,
    inventory: EvidenceInventoryReport,
    recovery: RecoveryPlanReport,
    investigation_plan: InvestigationPlanReport,
) -> EvidenceTriageReport:
    inventory_by_id = {item.evidence_id: item for item in inventory.items}
    recovery_by_id = {item.evidence_id: item for item in recovery.items}
    family_rank = {
        family: index for index, family in enumerate(investigation_plan.prioritized_artifact_families, start=1)
    }
    items: list[EvidenceTriageItem] = []
    limitations: list[str] = []
    for evidence in manifest.evidence:
        inventory_item = inventory_by_id.get(evidence.evidence_id)
        recovery_item = recovery_by_id.get(evidence.evidence_id)
        family = (
            inventory_item.artifact_family
            if inventory_item is not None and inventory_item.artifact_family
            else _family_for_type(evidence.evidence_type)
        )
        priority, reasons = _priority_and_reasons(
            family=family,
            verified=evidence.verified,
            inventory_item=inventory_item,
            recovery_item=recovery_item,
        )
        items.append(
            EvidenceTriageItem(
                rank=1,
                evidence_id=evidence.evidence_id,
                evidence_type=evidence.evidence_type.value,
                artifact_family=family,
                priority=priority,
                recommended_tool=inventory_item.recommended_tool if inventory_item else "manual_review",
                tool_status=str(inventory_item.tool_status) if inventory_item else "UNKNOWN",
                resource_risk=str(inventory_item.resource_risk) if inventory_item else "UNKNOWN",
                recovery_candidate_count=recovery_item.candidate_count if recovery_item else 0,
                blocked_recovery_count=recovery_item.blocked_candidate_count if recovery_item else 0,
                reasons=tuple(scrub_report_text(item) for item in reasons),
                expected_questions=_expected_questions(family),
            )
        )
        if recovery_item and recovery_item.blocked_candidate_count:
            limitations.append(
                f"{evidence.evidence_id} has {recovery_item.blocked_candidate_count} blocked recovery path(s)."
            )

    priority_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_items = sorted(
        items,
        key=lambda item: (
            priority_rank[item.priority],
            family_rank.get(item.artifact_family, len(FAMILY_PRIORITY) + 1),
            item.evidence_id,
        ),
    )
    ranked = tuple(item.model_copy(update={"rank": index}) for index, item in enumerate(sorted_items, start=1))
    counts = {priority: sum(1 for item in ranked if item.priority == priority) for priority in priority_rank}
    return EvidenceTriageReport(
        case_id=manifest.case_id,
        objective=objective.objective,
        evidence_count=len(ranked),
        critical_count=counts["CRITICAL"],
        high_count=counts["HIGH"],
        medium_count=counts["MEDIUM"],
        low_count=counts["LOW"],
        prioritized_evidence_ids=tuple(item.evidence_id for item in ranked),
        items=ranked,
        limitations=tuple(scrub_report_text(item) for item in sorted(set(limitations))),
    )


def export_case_objective(report: CaseObjectiveReport, path: Path | None = None) -> str:
    return _export(report.model_dump(mode="json"), path)


def export_investigation_plan(report: InvestigationPlanReport, path: Path | None = None) -> str:
    return _export(report.model_dump(mode="json"), path)


def export_evidence_triage(report: EvidenceTriageReport, path: Path | None = None) -> str:
    return _export(report.model_dump(mode="json"), path)


def render_case_objective_markdown(report: CaseObjectiveReport, path: Path | None = None) -> str:
    lines = [
        "# Blitz DFIR Case Objective",
        "",
        f"- Case: `{scrub_report_text(report.case_id)}`",
        f"- Source: `{report.source}`",
        f"- Objective: {scrub_report_text(report.objective)}",
        "",
        "## Success Criteria",
        "",
    ]
    lines.extend(f"- {scrub_report_text(item)}" for item in report.success_criteria)
    lines.extend(["", "## Constraints", ""])
    lines.extend(f"- {scrub_report_text(item)}" for item in report.constraints)
    return _write_markdown(lines, path)


def render_investigation_plan_markdown(report: InvestigationPlanReport, path: Path | None = None) -> str:
    lines = [
        "# Blitz DFIR Investigation Plan",
        "",
        f"- Case: `{scrub_report_text(report.case_id)}`",
        f"- Mode: `{report.mode}`",
        f"- Objective: {scrub_report_text(report.objective)}",
        f"- Operating rule: {scrub_report_text(report.operating_rule)}",
        "",
        "## Prioritized Artifact Families",
        "",
    ]
    lines.extend(f"- `{family}` - {scrub_report_text(FAMILY_NAMES.get(family, family))}" for family in report.prioritized_artifact_families)
    lines.extend(["", "## Phases", ""])
    for phase in report.phases:
        lines.extend(
            [
                f"### {phase.sequence}. {scrub_report_text(phase.name)}",
                "",
                f"- Purpose: {scrub_report_text(phase.purpose)}",
                f"- Artifact families: `{', '.join(phase.artifact_families) or 'none'}`",
                f"- Evidence IDs: `{', '.join(phase.evidence_ids) or 'none'}`",
                "",
            ]
        )
    lines.extend(["## Limitations", ""])
    lines.extend(f"- {scrub_report_text(item)}" for item in (report.limitations or ("none recorded",)))
    return _write_markdown(lines, path)


def render_evidence_triage_markdown(report: EvidenceTriageReport, path: Path | None = None) -> str:
    lines = [
        "# Blitz DFIR Evidence Triage",
        "",
        f"- Case: `{scrub_report_text(report.case_id)}`",
        f"- Evidence count: `{report.evidence_count}`",
        f"- Priority counts: critical `{report.critical_count}`, high `{report.high_count}`, medium `{report.medium_count}`, low `{report.low_count}`",
        "",
        "## Prioritized Evidence",
        "",
    ]
    for item in report.items:
        lines.extend(
            [
                f"### {item.rank}. `{scrub_report_text(item.evidence_id)}`",
                "",
                f"- Priority: `{item.priority}`",
                f"- Type/family: `{item.evidence_type}` / `{item.artifact_family}`",
                f"- Tool/status: `{item.recommended_tool}` / `{item.tool_status}`",
                f"- Resource risk: `{item.resource_risk}`",
                f"- Recovery candidates: `{item.recovery_candidate_count}` total, `{item.blocked_recovery_count}` blocked",
                f"- Reasons: {scrub_report_text('; '.join(item.reasons) or 'none recorded')}",
                f"- Questions: {scrub_report_text('; '.join(item.expected_questions) or 'none recorded')}",
                "",
            ]
        )
    if report.limitations:
        lines.extend(["## Limitations", ""])
        lines.extend(f"- {scrub_report_text(item)}" for item in report.limitations)
    return _write_markdown(lines, path)


def _families_from_manifest(manifest: EvidenceManifest) -> tuple[str, ...]:
    families: list[str] = []
    for evidence in manifest.evidence:
        family = _family_for_type(evidence.evidence_type)
        if family not in families:
            families.append(family)
    return tuple(families)


def _prioritize_families(families: tuple[str, ...]) -> tuple[str, ...]:
    present = set(families)
    ordered = [family for family in FAMILY_PRIORITY if family in present]
    ordered.extend(family for family in families if family not in ordered)
    return tuple(ordered)


def _family_for_type(evidence_type: EvidenceType) -> str:
    if evidence_type in {EvidenceType.EVTX, EvidenceType.PREPROCESSED_EVTX}:
        return "event_logs"
    if evidence_type in {EvidenceType.PLASO, EvidenceType.CSV_TIMELINE, EvidenceType.JSON_EXPORT}:
        return "plaso_timeline"
    if evidence_type is EvidenceType.VOLATILITY_JSON:
        return "memory"
    if evidence_type in {EvidenceType.YARA_MATCHES, EvidenceType.STRINGS_OUTPUT}:
        return "execution_artifacts"
    if evidence_type is EvidenceType.REGISTRY_HIVE:
        return "registry"
    if evidence_type is EvidenceType.MEMORY:
        return "memory"
    if evidence_type is EvidenceType.PCAP:
        return "pcap"
    if evidence_type in {EvidenceType.E01, EvidenceType.DD}:
        return "disk_timeline"
    if evidence_type is EvidenceType.FILESYSTEM_ARTIFACT:
        return "filesystem"
    return "unsupported"


def _build_phases(
    prioritized: tuple[str, ...],
    family_to_evidence: dict[str, tuple[str, ...]],
) -> tuple[InvestigationPhase, ...]:
    phases: list[InvestigationPhase] = []
    phase_specs = (
        (
            "scope-and-integrity",
            "Scope and evidence integrity",
            "Verify registered evidence, tool availability, resource risk, and unsupported paths before extraction.",
            ("event_logs", "plaso_timeline", "registry", "memory", "pcap", "disk_timeline", "filesystem", "direct_processed"),
        ),
        (
            "high-signal-timeline",
            "High-signal timeline and execution review",
            "Prioritize time-ordered execution, logon, persistence, and suspicious process evidence.",
            ("event_logs", "plaso_timeline", "direct_processed", "execution_artifacts"),
        ),
        (
            "corroboration",
            "Cross-source corroboration",
            "Use registry, memory, network, and disk context to support, contradict, or bound timeline findings.",
            ("registry", "memory", "pcap", "disk_timeline", "filesystem"),
        ),
        (
            "coverage-and-unknowns",
            "Coverage, contradictions, and unknowns",
            "Surface missing sources, blocked recovery paths, single-source claims, contradictions, and confidence penalties.",
            tuple(FAMILY_PRIORITY),
        ),
    )
    for phase_id, name, purpose, candidate_families in phase_specs:
        families = tuple(family for family in candidate_families if family in prioritized)
        evidence_ids = tuple(evidence_id for family in families for evidence_id in family_to_evidence.get(family, ()))
        if not families and phase_id != "coverage-and-unknowns":
            continue
        phases.append(
            InvestigationPhase(
                sequence=len(phases) + 1,
                phase_id=phase_id,
                name=name,
                purpose=purpose,
                artifact_families=families,
                evidence_ids=evidence_ids,
            )
        )
    return tuple(phases)


def _priority_and_reasons(
    *,
    family: str,
    verified: bool,
    inventory_item: object,
    recovery_item: object,
) -> tuple[EvidencePriority, list[str]]:
    reasons: list[str] = []
    if not verified:
        reasons.append("evidence hash did not verify; preserve but treat as critical review before relying on it")
        return "CRITICAL", reasons

    resource_risk = str(getattr(inventory_item, "resource_risk", "LOW"))
    tool_status = str(getattr(inventory_item, "tool_status", "UNKNOWN"))
    blocked = int(getattr(recovery_item, "blocked_candidate_count", 0) or 0)
    if family in {"event_logs", "plaso_timeline", "registry", "memory"}:
        reasons.append("high forensic value for execution, logon, persistence, or process context")
    if family in {"pcap", "disk_timeline", "filesystem"}:
        reasons.append("useful corroboration source for timeline and host findings")
    if resource_risk in {"HIGH", "CRITICAL"}:
        reasons.append(f"resource risk is {resource_risk}; process with checkpointing and bounded exports")
    if tool_status not in {"AVAILABLE", "NOT_REQUIRED"}:
        reasons.append(f"tool status is {tool_status}; route may require manual review or recovery planning")
    if blocked:
        reasons.append(f"{blocked} recovery path(s) are blocked and must remain documented")

    if tool_status not in {"AVAILABLE", "NOT_REQUIRED"}:
        return "CRITICAL", reasons
    if family in {"event_logs", "plaso_timeline", "registry", "memory"}:
        return "HIGH", reasons
    if family in {"pcap", "disk_timeline", "filesystem"} or resource_risk in {"HIGH", "CRITICAL"}:
        return "MEDIUM", reasons
    return "LOW", reasons or ["standard evidence route available"]


def _expected_questions(family: str) -> tuple[str, ...]:
    return {
        "event_logs": (
            "Which users, processes, services, PowerShell, logon, and privilege events are present?",
            "Do timestamps and event IDs support or contradict suspected activity?",
        ),
        "plaso_timeline": (
            "What sequence of events emerges across the exported timeline?",
            "Which high-signal records deserve correlation and confidence scoring?",
        ),
        "registry": (
            "Are persistence, service, autorun, account, or policy artifacts present?",
            "Do registry artifacts corroborate execution or persistence claims?",
        ),
        "memory": (
            "Which processes, network handles, modules, or suspicious strings are recoverable?",
            "Does memory support or contradict timeline/process evidence?",
        ),
        "pcap": (
            "Do DNS, HTTP, TLS, or connection records corroborate process or timeline activity?",
            "Is network evidence missing, partial, or contradictory?",
        ),
        "disk_timeline": (
            "Which file, execution, persistence, and timeline artifacts can be extracted safely?",
            "Does disk context expand or contradict the current timeline?",
        ),
        "filesystem": (
            "Which file creation, modification, staging, or payload indicators are present?",
            "Can filesystem evidence support a finding without overclaiming intent?",
        ),
    }.get(family, ("What can this evidence safely prove, and what must remain unknown?",))


def _export(value: dict[str, object], path: Path | None) -> str:
    text = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True)
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
    return text


def _write_markdown(lines: list[str], path: Path | None) -> str:
    text = "\n".join(lines).rstrip() + "\n"
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return text
