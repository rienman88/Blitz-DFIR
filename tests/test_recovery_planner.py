from __future__ import annotations

import hashlib

from blitz_dfir.batching.planner import build_batch_plan
from blitz_dfir.core.manifest import load_manifest
from blitz_dfir.inventory.tool_discovery import discover_tools
from blitz_dfir.recovery.planner import build_recovery_plan
from blitz_dfir.tools.config import ToolConfig, ToolSettings


def test_recovery_plan_records_sequential_fallbacks_and_blocked_velociraptor(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "")
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    image = evidence_root / "disk.E01"
    image.write_bytes(b"e01")
    manifest_path = tmp_path / "case.yaml"
    manifest_path.write_text(
        f"""
case_id: recovery-case
evidence_root: evidence
output_root: output
evidence:
  - id: disk
    path: disk.E01
    type: E01
    sha256: {hashlib.sha256(b"e01").hexdigest()}
""".strip(),
        encoding="utf-8",
    )
    manifest = load_manifest(manifest_path)
    batch_plan = build_batch_plan(
        manifest=manifest,
        mode="timeline",
        psort_profile="triage",
        tool_timeout_seconds=3600,
        psort_filter=None,
        psort_slice=None,
        psort_slice_size=None,
    )
    tool_discovery = discover_tools(
        ToolConfig(
            tools={
                "log2timeline": ToolSettings(executable="definitely-missing-log2timeline"),
                "psort": ToolSettings(executable="definitely-missing-psort"),
                "chainsaw": ToolSettings(executable="definitely-missing-chainsaw"),
            }
        )
    )

    report = build_recovery_plan(
        manifest=manifest,
        batch_plan=batch_plan,
        tool_discovery=tool_discovery,
    )

    item = report.items[0]
    candidates = {candidate.tool: candidate for candidate in item.candidates}
    assert item.sequential_execution_required is True
    assert candidates["timeline"].status == "PRIMARY_PLANNED"
    assert candidates["timeline"].auto_runnable is False
    assert candidates["psort"].preconditions == ("requires successful timeline-derived PLASO output",)
    assert candidates["events"].preconditions == ("requires extracted EVTX files registered as evidence",)
    assert candidates["velociraptor"].status == "NOT_INTEGRATED"
    assert candidates["velociraptor"].auto_runnable is False
    assert "velociraptor" in item.unchecked_recovery_paths
    assert report.blocked_candidate_count >= 1


def test_recovery_plan_keeps_direct_processed_inputs_internal(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    timeline = evidence_root / "timeline.csv"
    timeline.write_text("datetime,message\n2026-01-01T00:00:00Z,ok\n", encoding="utf-8")
    manifest_path = tmp_path / "case.yaml"
    manifest_path.write_text(
        f"""
case_id: recovery-direct-case
evidence_root: evidence
output_root: output
evidence:
  - id: timeline
    path: timeline.csv
    type: CSV_TIMELINE
    sha256: {hashlib.sha256(timeline.read_bytes()).hexdigest()}
""".strip(),
        encoding="utf-8",
    )
    manifest = load_manifest(manifest_path)
    batch_plan = build_batch_plan(
        manifest=manifest,
        mode="timeline",
        psort_profile="triage",
        tool_timeout_seconds=None,
        psort_filter=None,
        psort_slice=None,
        psort_slice_size=None,
    )

    report = build_recovery_plan(
        manifest=manifest,
        batch_plan=batch_plan,
        tool_discovery=discover_tools(ToolConfig(tools={})),
    )

    candidate = report.items[0].candidates[0]
    assert candidate.tool == "direct_parse"
    assert candidate.status == "PRIMARY_PLANNED"
    assert candidate.auto_runnable is True
    assert candidate.config_tool_name is None
