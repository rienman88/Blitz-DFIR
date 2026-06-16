from __future__ import annotations

import hashlib

from blitz_dfir.batching.planner import build_batch_plan
from blitz_dfir.core.manifest import load_manifest
from blitz_dfir.inventory.report import build_inventory_report
from blitz_dfir.inventory.tool_discovery import discover_tools
from blitz_dfir.tools.config import ToolConfig, ToolSettings


def test_tool_discovery_marks_missing_and_available_tools(monkeypatch):
    monkeypatch.setenv("PATH", "")
    config = ToolConfig(
        tools={
            "psort": ToolSettings(executable="definitely-missing-psort"),
            "strings": ToolSettings(executable="strings", allowed=False),
        }
    )

    report = discover_tools(config)

    statuses = {tool.tool_name: tool.status for tool in report.tools}
    assert statuses["psort"] == "MISSING"
    assert statuses["strings"] == "DISABLED"
    assert report.missing_count == 1
    assert report.disabled_count == 1


def test_evidence_inventory_maps_batch_tool_status_and_risk(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "")
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    plaso = evidence_root / "case.plaso"
    plaso.write_bytes(b"plaso")
    manifest_path = tmp_path / "case.yaml"
    manifest_path.write_text(
        f"""
case_id: inventory-case
evidence_root: evidence
output_root: output
evidence:
  - id: rd01-plaso
    path: case.plaso
    type: PLASO
    sha256: {hashlib.sha256(b"plaso").hexdigest()}
    internally_generated: true
""".strip(),
        encoding="utf-8",
    )
    manifest = load_manifest(manifest_path)
    batch_plan = build_batch_plan(
        manifest=manifest,
        mode="timeline",
        psort_profile="triage",
        tool_timeout_seconds=3600,
        psort_filter="data_type contains 'windows:evtx'",
        psort_slice=None,
        psort_slice_size=None,
    )
    tool_discovery = discover_tools(ToolConfig(tools={"psort": ToolSettings(executable="definitely-missing-psort")}))

    inventory = build_inventory_report(
        manifest=manifest,
        batch_plan=batch_plan,
        tool_discovery=tool_discovery,
    )

    item = inventory.items[0]
    assert item.artifact_family == "plaso_timeline"
    assert item.recommended_tool == "psort"
    assert item.config_tool_name == "psort"
    assert item.tool_status == "MISSING"
    assert item.batch_id == "batch-01-plaso_timeline"
    assert inventory.unavailable_tool_count == 1
