from __future__ import annotations

from blitz_dfir.batching.models import BatchPlan, BatchTask
from blitz_dfir.core.models import EvidenceManifest, EvidenceRecord, EvidenceType
from blitz_dfir.inventory.models import EvidenceInventoryItem, EvidenceInventoryReport, ResourceRisk, ToolDiscoveryReport, ToolStatus

TASK_TO_CONFIG_TOOL = {
    "timeline": "log2timeline",
    "psort": "psort",
    "memory": "volatility",
    "events": "chainsaw",
    "pcap": "tshark",
    "yara": "yara",
    "strings": "strings",
}


def build_inventory_report(
    *,
    manifest: EvidenceManifest,
    batch_plan: BatchPlan,
    tool_discovery: ToolDiscoveryReport,
) -> EvidenceInventoryReport:
    task_by_evidence = _task_by_evidence(batch_plan)
    batch_by_evidence = _batch_by_evidence(batch_plan)
    tool_status: dict[str, ToolStatus] = {tool.tool_name: tool.status for tool in tool_discovery.tools}

    items = tuple(
        _inventory_item(
            evidence,
            task=task_by_evidence.get(evidence.evidence_id),
            batch_id=batch_by_evidence.get(evidence.evidence_id),
            tool_status=tool_status,
        )
        for evidence in manifest.evidence
    )
    unavailable = sum(
        1
        for item in items
        if item.tool_status not in {"AVAILABLE", "NOT_REQUIRED"}
    )
    high_risk = sum(1 for item in items if item.resource_risk in {"HIGH", "CRITICAL"})
    return EvidenceInventoryReport(
        case_id=manifest.case_id,
        evidence_count=len(items),
        high_or_critical_risk_count=high_risk,
        unavailable_tool_count=unavailable,
        items=items,
    )


def _task_by_evidence(batch_plan: BatchPlan) -> dict[str, BatchTask]:
    return {
        task.evidence_id: task
        for batch in batch_plan.batches
        for task in batch.tasks
    }


def _batch_by_evidence(batch_plan: BatchPlan) -> dict[str, str]:
    return {
        task.evidence_id: batch.batch_id
        for batch in batch_plan.batches
        for task in batch.tasks
    }


def _inventory_item(
    evidence: EvidenceRecord,
    *,
    task: BatchTask | None,
    batch_id: str | None,
    tool_status: dict[str, ToolStatus],
) -> EvidenceInventoryItem:
    recommended_tool = task.tool if task else "manual_review"
    config_tool_name = TASK_TO_CONFIG_TOOL.get(recommended_tool)
    status = "NOT_REQUIRED" if config_tool_name is None else tool_status.get(config_tool_name, "MISSING")
    risk, reason = _resource_risk(evidence)
    notes = _notes(evidence=evidence, recommended_tool=recommended_tool, tool_status=status)
    controls = (
        "manifest_sha256_verification",
        "read_only_evidence_scope",
        "max_parallel_tools_1",
        "checkpoint_after_batch",
        "artifact_manifest_sha256",
    )
    return EvidenceInventoryItem(
        evidence_id=evidence.evidence_id,
        evidence_type=evidence.evidence_type.value,
        category=evidence.category.value,
        pipeline=evidence.pipeline.value,
        trust_tier=evidence.trust_tier.value,
        path=str(evidence.path),
        size_bytes=evidence.size_bytes,
        sha256=evidence.sha256,
        verified=evidence.verified,
        artifact_family=task.artifact_family if task else "unsupported",
        recommended_tool=recommended_tool,
        config_tool_name=config_tool_name,
        tool_status=status,
        batch_id=batch_id,
        task_id=task.task_id if task else None,
        resource_risk=risk,
        resource_reason=reason,
        expected_controls=controls,
        notes=notes,
    )


def _resource_risk(evidence: EvidenceRecord) -> tuple[ResourceRisk, str]:
    gib = evidence.size_bytes / (1024**3)
    if evidence.evidence_type in {EvidenceType.E01, EvidenceType.DD}:
        return "CRITICAL", "full disk images require scoped artifact extraction before broad parsing"
    if evidence.evidence_type is EvidenceType.MEMORY:
        return "HIGH", "memory images require plugin-scoped execution and can be RAM intensive"
    if evidence.evidence_type in {
        EvidenceType.PLASO,
        EvidenceType.CSV_TIMELINE,
        EvidenceType.JSON_EXPORT,
        EvidenceType.VOLATILITY_JSON,
    } and gib >= 1:
        return "HIGH", "large timeline exports can create multi-GB CSV, SQLite, JSON, and HTML outputs"
    if evidence.evidence_type in {EvidenceType.YARA_MATCHES, EvidenceType.STRINGS_OUTPUT} and gib >= 1:
        return "HIGH", "large processed scan outputs should be split or parsed in a dedicated batch"
    if evidence.evidence_type is EvidenceType.PCAP and gib >= 1:
        return "HIGH", "large PCAP requires protocol-scoped tshark or Zeek triage"
    if gib >= 4:
        return "HIGH", "large artifact should be processed in a dedicated batch"
    if gib >= 0.25:
        return "MEDIUM", "medium artifact should be batched and checkpointed"
    return "LOW", "small artifact is suitable for normal bounded processing"


def _notes(*, evidence: EvidenceRecord, recommended_tool: str, tool_status: str) -> tuple[str, ...]:
    notes: list[str] = []
    if recommended_tool == "unsupported":
        notes.append("no automated typed tool is currently assigned; manual review required")
    if tool_status not in {"AVAILABLE", "NOT_REQUIRED"}:
        notes.append("recommended tool is not available for automated execution")
    if evidence.pipeline.value == "processed" and not evidence.internally_generated:
        notes.append("external processed evidence should be treated as lower-trust derived input")
    return tuple(notes)
