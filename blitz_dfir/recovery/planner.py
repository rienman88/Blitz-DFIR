from __future__ import annotations

from dataclasses import dataclass

from blitz_dfir.batching.models import BatchPlan, BatchTask
from blitz_dfir.core.models import EvidenceManifest, EvidenceRecord, EvidenceType
from blitz_dfir.inventory.models import ToolDiscoveryReport, ToolStatus
from blitz_dfir.mcp.allowlist import is_allowed_tool
from blitz_dfir.recovery.models import (
    EvidenceRecoveryPlan,
    RecoveryCandidate,
    RecoveryCandidateStatus,
    RecoveryPlanReport,
)

TOOL_TO_CONFIG_TOOL = {
    "timeline": "log2timeline",
    "psort": "psort",
    "disk_triage": "disk_triage",
    "memory": "volatility",
    "events": "chainsaw",
    "pcap": "tshark",
    "yara": "yara",
    "strings": "strings",
    "velociraptor": "velociraptor",
}

INTEGRATED_TOOLS = frozenset(
    {"direct_parse", "timeline", "psort", "disk_triage", "memory", "events", "pcap", "yara", "strings"}
)
AUTO_RUNNABLE_STATUSES: frozenset[RecoveryCandidateStatus] = frozenset({"PRIMARY_PLANNED", "TYPED_AVAILABLE"})


@dataclass(frozen=True)
class CandidateSpec:
    tool: str
    rationale: str
    preconditions: tuple[str, ...] = ()
    expected_output: str | None = None


def build_recovery_plan(
    *,
    manifest: EvidenceManifest,
    batch_plan: BatchPlan,
    tool_discovery: ToolDiscoveryReport,
) -> RecoveryPlanReport:
    task_by_evidence = _task_by_evidence(batch_plan)
    batch_by_evidence = _batch_by_evidence(batch_plan)
    tool_status = {tool.tool_name: tool.status for tool in tool_discovery.tools}

    items = tuple(
        _evidence_recovery_plan(
            evidence,
            task=task_by_evidence.get(evidence.evidence_id),
            batch_id=batch_by_evidence.get(evidence.evidence_id),
            tool_status=tool_status,
        )
        for evidence in manifest.evidence
    )
    candidate_count = sum(item.candidate_count for item in items)
    auto_runnable_count = sum(item.auto_runnable_candidate_count for item in items)
    blocked_count = sum(item.blocked_candidate_count for item in items)
    return RecoveryPlanReport(
        case_id=manifest.case_id,
        evidence_count=len(items),
        candidate_count=candidate_count,
        auto_runnable_candidate_count=auto_runnable_count,
        blocked_candidate_count=blocked_count,
        evidence_with_blocked_recovery_count=sum(1 for item in items if item.blocked_candidate_count),
        unsupported_evidence_count=sum(1 for item in items if item.primary_tool == "unsupported"),
        items=items,
        notes=(
            "Recovery candidates are planned sequentially. Blitz does not run untyped or non-allowlisted tools.",
            "Blocked recovery paths are recorded as unchecked until a typed adapter, parser, and allowlist entry exist.",
        ),
    )


def _evidence_recovery_plan(
    evidence: EvidenceRecord,
    *,
    task: BatchTask | None,
    batch_id: str | None,
    tool_status: dict[str, ToolStatus],
) -> EvidenceRecoveryPlan:
    primary_tool = task.tool if task else None
    specs = _candidate_specs(evidence=evidence, primary_tool=primary_tool)
    candidates = tuple(
        _candidate(
            sequence=index,
            spec=spec,
            primary_tool=primary_tool,
            tool_status=tool_status,
        )
        for index, spec in enumerate(specs, start=1)
    )
    blocked = tuple(candidate.tool for candidate in candidates if not candidate.auto_runnable)
    return EvidenceRecoveryPlan(
        evidence_id=evidence.evidence_id,
        evidence_type=evidence.evidence_type.value,
        category=evidence.category.value,
        pipeline=evidence.pipeline.value,
        primary_batch_id=batch_id,
        primary_task_id=task.task_id if task else None,
        primary_tool=primary_tool,
        primary_artifact_family=task.artifact_family if task else None,
        candidate_count=len(candidates),
        auto_runnable_candidate_count=sum(1 for candidate in candidates if candidate.auto_runnable),
        blocked_candidate_count=len(blocked),
        unchecked_recovery_paths=blocked,
        candidates=candidates,
    )


def _candidate_specs(*, evidence: EvidenceRecord, primary_tool: str | None) -> tuple[CandidateSpec, ...]:
    specs: list[CandidateSpec] = []
    if primary_tool and primary_tool != "unsupported":
        specs.append(
            CandidateSpec(
                tool=primary_tool,
                rationale="Primary typed route selected by the batch planner.",
                expected_output=_expected_output(primary_tool),
            )
        )

    if evidence.evidence_type is EvidenceType.EVTX:
        _append_unique(
            specs,
            CandidateSpec(
                tool="timeline",
                rationale="Fallback timeline extraction can produce PLASO from EVTX if direct event hunting is degraded.",
                expected_output="derived PLASO timeline for later psort parsing",
            ),
        )
        _append_velociraptor(specs, "Velociraptor can collect targeted Windows event artifacts when integrated.")
    elif evidence.evidence_type in {EvidenceType.E01, EvidenceType.DD}:
        _append_unique(
            specs,
            CandidateSpec(
                tool="psort",
                rationale="Second-stage PLASO export after log2timeline creates a derived timeline.",
                preconditions=("requires successful timeline-derived PLASO output",),
                expected_output="bounded CSV timeline",
            ),
        )
        _append_unique(
            specs,
            CandidateSpec(
                tool="disk_triage",
                rationale="Fallback bounded Sleuth Kit filesystem triage if full log2timeline/dfVFS extraction fails.",
                expected_output="bounded JSON filesystem metadata and high-value artifact path inventory",
            ),
        )
        _append_unique(
            specs,
            CandidateSpec(
                tool="events",
                rationale="Chainsaw can triage extracted EVTX files if event logs are carved or mounted from the image.",
                preconditions=("requires extracted EVTX files registered as evidence",),
                expected_output="bounded Chainsaw JSON findings",
            ),
        )
        _append_velociraptor(specs, "Velociraptor can collect targeted artifacts from live/offline collection workflows when integrated.")
    elif evidence.evidence_type is EvidenceType.REGISTRY_HIVE:
        _append_velociraptor(specs, "Velociraptor can collect registry persistence artifacts when integrated.")
    elif evidence.evidence_type is EvidenceType.MEMORY:
        _append_unique(
            specs,
            CandidateSpec(
                tool="strings",
                rationale="Strings can provide a bounded fallback view when memory plugin output is degraded.",
                expected_output="bounded strings text",
            ),
        )
        _append_unique(
            specs,
            CandidateSpec(
                tool="yara",
                rationale="YARA can scan memory when an approved rule is configured.",
                preconditions=("requires an allowlisted YARA rule parameter",),
                expected_output="bounded YARA matches",
            ),
        )
    elif evidence.evidence_type is EvidenceType.FILESYSTEM_ARTIFACT:
        _append_unique(
            specs,
            CandidateSpec(
                tool="strings",
                rationale="Strings can provide a lightweight fallback for unknown filesystem artifacts.",
                expected_output="bounded strings text",
            ),
        )
        _append_unique(
            specs,
            CandidateSpec(
                tool="yara",
                rationale="YARA can scan the artifact when an approved rule is configured.",
                preconditions=("requires an allowlisted YARA rule parameter",),
                expected_output="bounded YARA matches",
            ),
        )
    elif evidence.evidence_type is EvidenceType.THIRD_PARTY_EXPORT:
        _append_velociraptor(specs, "Third-party export recovery requires a typed parser or typed source collector.")

    if not specs:
        specs.append(
            CandidateSpec(
                tool="unsupported",
                rationale="No automated typed recovery path is currently implemented for this evidence type.",
            )
        )
    return tuple(specs)


def _candidate(
    *,
    sequence: int,
    spec: CandidateSpec,
    primary_tool: str | None,
    tool_status: dict[str, ToolStatus],
) -> RecoveryCandidate:
    config_tool = TOOL_TO_CONFIG_TOOL.get(spec.tool)
    typed_adapter = spec.tool in INTEGRATED_TOOLS
    allowlisted = spec.tool == "direct_parse" or is_allowed_tool(spec.tool)
    discovered_status = tool_status.get(config_tool or "", "MISSING") if config_tool else None
    status: RecoveryCandidateStatus
    if spec.tool == "unsupported":
        status = "NOT_APPLICABLE"
    elif spec.tool == primary_tool:
        status = "PRIMARY_PLANNED"
    elif not typed_adapter:
        status = "NOT_INTEGRATED"
    elif not allowlisted:
        status = "NOT_ALLOWLISTED"
    elif discovered_status == "AVAILABLE":
        status = "TYPED_AVAILABLE"
    else:
        status = "TYPED_UNAVAILABLE"
    auto_runnable = status in AUTO_RUNNABLE_STATUSES and (config_tool is None or discovered_status == "AVAILABLE")
    notes: list[str] = []
    if discovered_status and discovered_status != "AVAILABLE":
        notes.append(f"tool discovery status: {discovered_status}")
    if not typed_adapter and spec.tool != "unsupported":
        notes.append("requires a Blitz typed adapter and parser before automated execution")
    if not allowlisted and spec.tool != "unsupported":
        notes.append("requires explicit allowlist approval before automated execution")
    return RecoveryCandidate(
        sequence=sequence,
        tool=spec.tool,
        config_tool_name=config_tool,
        typed_adapter_available=typed_adapter,
        allowlisted=allowlisted,
        status=status,
        auto_runnable=auto_runnable,
        rationale=spec.rationale,
        preconditions=spec.preconditions,
        expected_output=spec.expected_output,
        notes=tuple(notes),
    )


def _expected_output(tool: str) -> str | None:
    return {
        "timeline": "derived PLASO timeline",
        "disk_triage": "bounded disk triage JSON",
        "direct_parse": "bounded parsed records from already-processed evidence",
        "psort": "bounded CSV timeline",
        "events": "bounded Chainsaw JSON findings",
        "memory": "bounded Volatility JSON output",
        "pcap": "bounded tshark JSON/summary output",
        "strings": "bounded strings text",
        "yara": "bounded YARA matches",
    }.get(tool)


def _append_unique(specs: list[CandidateSpec], candidate: CandidateSpec) -> None:
    if all(spec.tool != candidate.tool for spec in specs):
        specs.append(candidate)


def _append_velociraptor(specs: list[CandidateSpec], rationale: str) -> None:
    _append_unique(
        specs,
        CandidateSpec(
            tool="velociraptor",
            rationale=rationale,
            preconditions=("requires a typed Velociraptor adapter, approved artifact list, and output parser",),
            expected_output="bounded Velociraptor artifact collection results",
        ),
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
