from __future__ import annotations

import os
from collections import defaultdict

from blitz_dfir.artifacts.windows_profiles import log2timeline_parsers_for_profile, psort_filter_for_profile
from blitz_dfir.batching.models import BatchPlan, BatchResourcePolicy, BatchTask, EvidenceBatch
from blitz_dfir.core.models import EvidenceManifest, EvidenceRecord, EvidenceType
from blitz_dfir.sanitization.sanitizer import get_max_events

from blitz_dfir.batching.tool_profiles import MEMORY_PROFILE

BATCH_ORDER = (
    "direct_processed",
    "event_logs",
    "plaso_timeline",
    "registry",
    "execution_artifacts",
    "browser_artifacts",
    "memory",
    "pcap",
    "disk_timeline",
    "filesystem",
    "unsupported",
)

BATCH_NAMES = {
    "direct_processed": "Direct Processed Inputs",
    "event_logs": "Windows Event Logs",
    "plaso_timeline": "PLASO Timeline",
    "registry": "Registry And Persistence",
    "execution_artifacts": "Execution Artifacts",
    "browser_artifacts": "Browser Artifacts",
    "memory": "Memory",
    "pcap": "Network PCAP",
    "disk_timeline": "Disk Timeline",
    "filesystem": "Filesystem Artifacts",
    "unsupported": "Unsupported Or Manual Review",
}

DEFAULT_MEMORY_TRIAGE_PLUGINS = MEMORY_PROFILE


def build_batch_plan(
    *,
    manifest: EvidenceManifest,
    mode: str,
    psort_profile: str,
    tool_timeout_seconds: int | None,
    psort_filter: str | None,
    psort_slice: str | None,
    psort_slice_size: int | None,
    prioritized_artifact_families: tuple[str, ...] = (),
    triage_context: str | None = None,
) -> BatchPlan:
    buckets: dict[str, list[BatchTask]] = defaultdict(list)
    for evidence in manifest.evidence:
        tasks = _tasks_for_evidence(
            evidence,
            psort_profile=psort_profile,
            tool_timeout_seconds=tool_timeout_seconds,
            psort_filter=psort_filter,
            psort_slice=psort_slice,
            psort_slice_size=psort_slice_size,
        )
        for task in tasks:
            buckets[task.artifact_family].append(task)

    batches: list[EvidenceBatch] = []
    sequence = 1
    for family in _ordered_families(prioritized_artifact_families):
        tasks = tuple(buckets.get(family, ()))
        if not tasks:
            continue
        batches.append(
            EvidenceBatch(
                batch_id=f"batch-{sequence:02d}-{family}",
                sequence=sequence,
                name=BATCH_NAMES[family],
                artifact_family=family,
                tasks=tasks,
                resource_policy=BatchResourcePolicy(
                    timeout_seconds=tool_timeout_seconds,
                    normalized_event_cap=get_max_events(),
                ),
            )
        )
        sequence += 1

    return BatchPlan(
        case_id=manifest.case_id,
        mode=mode,
        triage_context=triage_context,
        prioritized_artifact_families=tuple(
            family for family in prioritized_artifact_families if family in BATCH_ORDER
        ),
        batch_count=len(batches),
        task_count=sum(len(batch.tasks) for batch in batches),
        batches=tuple(batches),
    )


def _ordered_families(prioritized_artifact_families: tuple[str, ...]) -> tuple[str, ...]:
    prioritized: list[str] = []
    for family in prioritized_artifact_families:
        if family in BATCH_ORDER and family not in prioritized:
            prioritized.append(family)
    return (*prioritized, *(family for family in BATCH_ORDER if family not in prioritized))


def _tasks_for_evidence(
    evidence: EvidenceRecord,
    *,
    psort_profile: str,
    tool_timeout_seconds: int | None,
    psort_filter: str | None,
    psort_slice: str | None,
    psort_slice_size: int | None,
) -> tuple[BatchTask, ...]:
    if evidence.evidence_type is EvidenceType.MEMORY:
        params = _tool_params("memory", tool_timeout_seconds)
        tasks: list[BatchTask] = []
        for plugin in _memory_triage_plugins():
            plugin_params = dict(params)
            plugin_params["plugin"] = plugin
            safe_plugin = plugin.replace(".", "_")
            tasks.append(
                BatchTask(
                    task_id=f"memory:{evidence.evidence_id}:memory:{safe_plugin}",
                    tool="memory",
                    evidence_id=evidence.evidence_id,
                    evidence_type=evidence.evidence_type.value,
                    artifact_family="memory",
                    params=plugin_params,
                    status="PENDING",
                    rationale="Run allowlisted Volatility memory triage plugins for process, network, and injection coverage.",
                )
            )
        return tuple(tasks)

    family, tool, params, rationale = _route_evidence(
        evidence,
        psort_profile=psort_profile,
        tool_timeout_seconds=tool_timeout_seconds,
        psort_filter=psort_filter,
        psort_slice=psort_slice,
        psort_slice_size=psort_slice_size,
    )
    return (
        BatchTask(
            task_id=f"{family}:{evidence.evidence_id}:{tool}",
            tool=tool,
            evidence_id=evidence.evidence_id,
            evidence_type=evidence.evidence_type.value,
            artifact_family=family,
            params=params,
            status="SKIPPED" if tool == "unsupported" else "PENDING",
            rationale=rationale,
        ),
    )


def _route_evidence(
    evidence: EvidenceRecord,
    *,
    psort_profile: str,
    tool_timeout_seconds: int | None,
    psort_filter: str | None,
    psort_slice: str | None,
    psort_slice_size: int | None,
) -> tuple[str, str, dict[str, object], str]:
    if evidence.evidence_type in {
        EvidenceType.CSV_TIMELINE,
        EvidenceType.PREPROCESSED_EVTX,
        EvidenceType.JSON_EXPORT,
        EvidenceType.VOLATILITY_JSON,
        EvidenceType.YARA_MATCHES,
        EvidenceType.STRINGS_OUTPUT,
    }:
        return "direct_processed", "direct_parse", {}, "Parse already-processed evidence without an external tool."
    if evidence.evidence_type is EvidenceType.EVTX:
        return "event_logs", "events", _tool_params("events", tool_timeout_seconds), "Parse EVTX with the event-log adapter."
    if evidence.evidence_type is EvidenceType.PLASO:
        return (
            "plaso_timeline",
            "psort",
            _psort_params(
                psort_profile=psort_profile,
                tool_timeout_seconds=tool_timeout_seconds,
                psort_filter=psort_filter,
                psort_slice=psort_slice,
                psort_slice_size=psort_slice_size,
            ),
            "Export PLASO with psort, then preserve complete exported rows in full accounting.",
        )
    if evidence.evidence_type is EvidenceType.REGISTRY_HIVE:
        return "registry", "timeline", _tool_params("timeline", tool_timeout_seconds), "Route registry hive through the timeline adapter until a dedicated registry typed tool is available."
    if evidence.evidence_type is EvidenceType.MEMORY:
        return (
            "memory",
            "memory",
            _tool_params("memory", tool_timeout_seconds),
            "Memory evidence routed for multi-plugin triage.",
    )
    if evidence.evidence_type is EvidenceType.PCAP:
        return "pcap", "pcap", _tool_params("pcap", tool_timeout_seconds), "Run bounded PCAP summary extraction."
    if evidence.evidence_type in {EvidenceType.E01, EvidenceType.DD}:
        return "disk_timeline", "timeline", _tool_params("timeline", tool_timeout_seconds), "Generate a disk timeline before narrower artifact-family exports."
    if evidence.evidence_type is EvidenceType.FILESYSTEM_ARTIFACT:
        return "filesystem", "timeline", _tool_params("timeline", tool_timeout_seconds), "Process filesystem artifact through timeline-capable tooling."
    return "unsupported", "unsupported", {}, "No bounded typed tool route is currently implemented for this evidence type."


def _memory_triage_plugins() -> tuple[str, ...]:
    raw = os.environ.get("BLITZ_MEMORY_PLUGINS")
    if not raw:
        return DEFAULT_MEMORY_TRIAGE_PLUGINS
    plugins: list[str] = []
    seen: set[str] = set()
    for item in raw.split(","):
        plugin = item.strip()
        if not plugin or plugin in seen:
            continue
        seen.add(plugin)
        plugins.append(plugin)
    return tuple(plugins) or DEFAULT_MEMORY_TRIAGE_PLUGINS


def _tool_params(tool: str, timeout_seconds: int | None) -> dict[str, object]:
    params: dict[str, object] = {}
    if timeout_seconds is not None:
        params["timeout_seconds"] = timeout_seconds
    if tool == "timeline":
        params["partitions"] = os.environ.get("BLITZ_LOG2TIMELINE_PARTITIONS", "all")
        params["vss_stores"] = os.environ.get("BLITZ_LOG2TIMELINE_VSS_STORES", "none")
        parsers = log2timeline_parsers_for_profile()
        if parsers:
            params["parsers"] = parsers
    return params


def _psort_params(
    *,
    psort_profile: str,
    tool_timeout_seconds: int | None,
    psort_filter: str | None,
    psort_slice: str | None,
    psort_slice_size: int | None,
) -> dict[str, object]:
    params = _tool_params("psort", tool_timeout_seconds)
    params["profile"] = psort_profile
    selected_filter = psort_filter or psort_filter_for_profile()
    if selected_filter:
        params["filter"] = selected_filter
    if psort_slice:
        params["slice"] = psort_slice
    if psort_slice_size is not None:
        params["slice_size"] = psort_slice_size
    return params
