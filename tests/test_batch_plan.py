from __future__ import annotations

import hashlib

from blitz_dfir.artifacts.windows_profiles import WINDOWS_LIGHT_LOG2TIMELINE_PARSER_LIST
from blitz_dfir.batching.planner import build_batch_plan
from blitz_dfir.core.manifest import load_manifest


def test_batch_plan_routes_evidence_to_ordered_specialized_batches(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    files = {
        "Security.evtx": b"evtx",
        "memory.raw": b"memory",
        "capture.pcap": b"pcap",
        "case.plaso": b"plaso",
    }
    for name, data in files.items():
        (evidence_root / name).write_bytes(data)
    manifest_path = tmp_path / "case.yaml"
    manifest_path.write_text(
        f"""
case_id: batch-case
evidence_root: evidence
output_root: output
evidence:
  - id: security
    path: Security.evtx
    type: EVTX
    sha256: {hashlib.sha256(files["Security.evtx"]).hexdigest()}
  - id: memory
    path: memory.raw
    type: MEMORY
    sha256: {hashlib.sha256(files["memory.raw"]).hexdigest()}
  - id: pcap
    path: capture.pcap
    type: PCAP
    sha256: {hashlib.sha256(files["capture.pcap"]).hexdigest()}
  - id: plaso
    path: case.plaso
    type: PLASO
    sha256: {hashlib.sha256(files["case.plaso"]).hexdigest()}
""".strip(),
        encoding="utf-8",
    )
    manifest = load_manifest(manifest_path)

    plan = build_batch_plan(
        manifest=manifest,
        mode="timeline",
        psort_profile="triage",
        tool_timeout_seconds=1800,
        psort_filter="data_type contains 'windows:evtx'",
        psort_slice=None,
        psort_slice_size=None,
    )

    assert [batch.artifact_family for batch in plan.batches] == [
        "event_logs",
        "plaso_timeline",
        "memory",
        "pcap",
    ]
    assert [batch.tasks[0].tool for batch in plan.batches] == ["events", "psort", "memory", "pcap"]
    memory_tasks = plan.batches[2].tasks
    assert [task.params["plugin"] for task in memory_tasks] == [
        "windows.pslist",
        "windows.pstree",
        "windows.cmdline",
        "windows.psscan",
        "windows.netscan",
        "windows.malfind",
    ]
    assert all(batch.resource_policy.max_parallel_tools == 1 for batch in plan.batches)
    psort_task = plan.batches[1].tasks[0]
    assert psort_task.params["filter"] == "data_type contains 'windows:evtx'"
    assert psort_task.params["timeout_seconds"] == 1800


def test_batch_plan_marks_unsupported_evidence_for_manual_review(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    export = evidence_root / "third-party.bin"
    export.write_bytes(b"export")
    manifest_path = tmp_path / "case.yaml"
    manifest_path.write_text(
        f"""
case_id: batch-unsupported-case
evidence_root: evidence
output_root: output
evidence:
  - id: export
    path: third-party.bin
    type: THIRD_PARTY_EXPORT
    sha256: {hashlib.sha256(b"export").hexdigest()}
""".strip(),
        encoding="utf-8",
    )

    plan = build_batch_plan(
        manifest=load_manifest(manifest_path),
        mode="timeline",
        psort_profile="triage",
        tool_timeout_seconds=None,
        psort_filter=None,
        psort_slice=None,
        psort_slice_size=None,
    )

    assert plan.batches[0].artifact_family == "unsupported"
    assert plan.batches[0].tasks[0].status == "SKIPPED"
    assert plan.batches[0].tasks[0].tool == "unsupported"


def test_batch_plan_routes_typed_processed_tool_outputs_to_direct_parse(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    files = {
        "memory.json": (b"[]", "VOLATILITY_JSON"),
        "matches.txt": (b"RuleName target.bin\n", "YARA_MATCHES"),
        "strings.txt": (b"powershell -nop\n", "STRINGS_OUTPUT"),
    }
    rows: list[str] = []
    for index, (filename, (content, evidence_type)) in enumerate(files.items(), 1):
        (evidence_root / filename).write_bytes(content)
        rows.append(
            f"""
  - id: processed-{index}
    path: {filename}
    type: {evidence_type}
    sha256: {hashlib.sha256(content).hexdigest()}
""".rstrip()
        )
    manifest_path = tmp_path / "case.yaml"
    manifest_path.write_text(
        f"""
case_id: batch-processed-case
evidence_root: evidence
output_root: output
evidence:
{chr(10).join(rows)}
""".strip(),
        encoding="utf-8",
    )

    plan = build_batch_plan(
        manifest=load_manifest(manifest_path),
        mode="timeline",
        psort_profile="triage",
        tool_timeout_seconds=None,
        psort_filter=None,
        psort_slice=None,
        psort_slice_size=None,
    )

    assert {batch.artifact_family for batch in plan.batches} == {"direct_processed"}
    assert [task.tool for batch in plan.batches for task in batch.tasks] == ["direct_parse", "direct_parse", "direct_parse"]


def test_windows_light_profile_targets_lightweight_plaso_artifacts(tmp_path, monkeypatch):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    disk = evidence_root / "disk.E01"
    plaso = evidence_root / "case.plaso"
    disk.write_bytes(b"disk")
    plaso.write_bytes(b"plaso")
    manifest_path = tmp_path / "case.yaml"
    manifest_path.write_text(
        f"""
case_id: windows-light-case
evidence_root: evidence
output_root: output
evidence:
  - id: disk
    path: disk.E01
    type: E01
    sha256: {hashlib.sha256(b"disk").hexdigest()}
  - id: plaso
    path: case.plaso
    type: PLASO
    sha256: {hashlib.sha256(b"plaso").hexdigest()}
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setenv("BLITZ_WINDOWS_ARTIFACT_PROFILE", "windows-light")

    plan = build_batch_plan(
        manifest=load_manifest(manifest_path),
        mode="timeline",
        psort_profile="triage",
        tool_timeout_seconds=None,
        psort_filter=None,
        psort_slice=None,
        psort_slice_size=None,
    )

    tasks = {task.tool: task for batch in plan.batches for task in batch.tasks}
    assert tasks["timeline"].params["parsers"] == WINDOWS_LIGHT_LOG2TIMELINE_PARSER_LIST
    assert "winevtx" in tasks["timeline"].params["parsers"]
    assert "winreg/amcache" in tasks["timeline"].params["parsers"]
    assert "winreg/bam" in tasks["timeline"].params["parsers"]
    assert "winreg/windows_usbstor_devices" in tasks["timeline"].params["parsers"]
    assert "mft" not in tasks["timeline"].params["parsers"]
    assert "usnjrnl" not in tasks["timeline"].params["parsers"]
    assert "windows:evtx" in tasks["psort"].params["filter"]
    assert "windows:prefetch" in tasks["psort"].params["filter"]
    assert "windows:lnk" in tasks["psort"].params["filter"]
    assert "srum" in tasks["psort"].params["filter"]
