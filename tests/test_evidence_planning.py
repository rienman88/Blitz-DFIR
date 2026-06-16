from __future__ import annotations

import hashlib

from blitz_dfir.batching.planner import build_batch_plan
from blitz_dfir.core.manifest import load_manifest
from blitz_dfir.inventory.models import ToolDiscoveryItem, ToolDiscoveryReport
from blitz_dfir.inventory.report import build_inventory_report
from blitz_dfir.planning.evidence_first import (
    build_case_objective,
    build_evidence_triage,
    build_investigation_plan,
)
from blitz_dfir.recovery.planner import build_recovery_plan


def test_evidence_first_planning_prioritizes_manifest_evidence(tmp_path):
    manifest = _manifest(
        tmp_path,
        files={
            "Security.evtx": ("evtx", "EVTX"),
            "memory.raw": ("memory", "MEMORY"),
            "capture.pcap": ("pcap", "PCAP"),
        },
    )
    discovery = ToolDiscoveryReport(
        tool_count=3,
        available_count=3,
        missing_count=0,
        disabled_count=0,
        hash_mismatch_count=0,
        tools=(
            ToolDiscoveryItem(tool_name="chainsaw", executable="chainsaw", allowed=True, status="AVAILABLE"),
            ToolDiscoveryItem(tool_name="volatility", executable="vol", allowed=True, status="AVAILABLE"),
            ToolDiscoveryItem(tool_name="tshark", executable="tshark", allowed=True, status="AVAILABLE"),
        ),
    )

    objective = build_case_objective(
        manifest=manifest,
        objective_text="Find evidence-backed execution, memory, and network activity.",
    )
    investigation_plan = build_investigation_plan(
        manifest=manifest,
        objective=objective,
        tool_discovery=discovery,
    )
    batch_plan = build_batch_plan(
        manifest=manifest,
        mode="timeline",
        psort_profile="triage",
        tool_timeout_seconds=1800,
        psort_filter=None,
        psort_slice=None,
        psort_slice_size=None,
        prioritized_artifact_families=investigation_plan.prioritized_artifact_families,
        triage_context=investigation_plan.mode,
    )
    inventory = build_inventory_report(
        manifest=manifest,
        batch_plan=batch_plan,
        tool_discovery=discovery,
    )
    recovery = build_recovery_plan(
        manifest=manifest,
        batch_plan=batch_plan,
        tool_discovery=discovery,
    )

    triage = build_evidence_triage(
        manifest=manifest,
        objective=objective,
        inventory=inventory,
        recovery=recovery,
        investigation_plan=investigation_plan,
    )

    assert objective.source == "cli"
    assert "without evidence support" in objective.constraints[0].lower()
    assert investigation_plan.mode == "evidence_first"
    assert investigation_plan.prioritized_artifact_families == ("event_logs", "memory", "pcap")
    assert investigation_plan.phases[0].phase_id == "scope-and-integrity"
    assert batch_plan.triage_context == "evidence_first"
    assert [batch.artifact_family for batch in batch_plan.batches] == ["event_logs", "memory", "pcap"]
    assert triage.evidence_count == 3
    assert triage.high_count == 2
    assert triage.medium_count == 1
    assert triage.prioritized_evidence_ids[:2] == ("evidence-1", "evidence-2")


def _manifest(tmp_path, *, files: dict[str, tuple[str, str]]):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    lines = ["case_id: evidence-first-case", "evidence_root: evidence", "output_root: output", "evidence:"]
    for index, (name, (content, evidence_type)) in enumerate(files.items(), start=1):
        path = evidence_root / name
        data = content.encode("utf-8")
        path.write_bytes(data)
        lines.extend(
            [
                f"  - id: evidence-{index}",
                f"    path: {name}",
                f"    type: {evidence_type}",
                f"    sha256: {hashlib.sha256(data).hexdigest()}",
            ]
        )
    manifest_path = tmp_path / "case.yaml"
    manifest_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return load_manifest(manifest_path)
