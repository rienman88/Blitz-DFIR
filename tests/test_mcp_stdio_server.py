from __future__ import annotations

import hashlib
import json

from blitz_dfir.audit.audit_log import AuditLogger
from blitz_dfir.core.manifest import load_manifest
from blitz_dfir.core.session import create_session
from blitz_dfir.mcp.dispatcher import ToolDispatcher
from blitz_dfir.mcp.stdio_server import StdioMCPServer
from blitz_dfir.mcp.tool_registry import ToolRegistry


def _runtime(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    evtx = evidence_root / "Security.evtx"
    evtx.write_bytes(b"evtx")
    digest = hashlib.sha256(b"evtx").hexdigest()
    manifest_path = tmp_path / "case.yaml"
    manifest_path.write_text(
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
    manifest = load_manifest(manifest_path)
    session = create_session(manifest)
    audit = AuditLogger(session.audit_log_path, session_id=session.session_id, case_id=manifest.case_id)
    registry = ToolRegistry()
    registry.register(
        "strings",
        lambda context, params: {
            "typed_tool": context.tool_name,
            "case_id": context.case_id,
            "evidence_id": context.evidence_id,
            "raw_output_returned": False,
            "params": params,
        },
    )
    dispatcher = ToolDispatcher(manifest=manifest, session=session, registry=registry, audit=audit)
    return StdioMCPServer(dispatcher=dispatcher, manifest=manifest, session=session), session


def test_mcp_server_lists_and_calls_typed_tool(tmp_path):
    server, session = _runtime(tmp_path)

    init_response = server.handle_payload(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    )
    assert init_response is not None
    assert init_response["result"]["serverInfo"]["name"] == "blitz-dfir"

    list_response = server.handle_payload({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert list_response is not None
    assert any(tool["name"] == "strings" for tool in list_response["result"]["tools"])

    call_response = server.handle_payload(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "strings",
                "arguments": {"evidence_id": "security", "limit": 10},
            },
        }
    )

    assert call_response is not None
    content = call_response["result"]["content"][0]["text"]
    result = json.loads(content)
    assert result == {
        "typed_tool": "strings",
        "case_id": "case-001",
        "evidence_id": "security",
        "raw_output_returned": False,
        "params": {"limit": 10},
    }
    entries = [json.loads(line) for line in session.audit_log_path.read_text(encoding="utf-8").splitlines()]
    assert [entry["event_type"] for entry in entries] == [
        "tool_request_validated",
        "tool_request_completed",
    ]
    assert {entry["case_id"] for entry in entries} == {"case-001"}
    assert all(entry["session_id"] == session.session_id for entry in entries)


def test_mcp_server_rejects_generic_shell_tool(tmp_path):
    server, _ = _runtime(tmp_path)

    response = server.handle_payload(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "execute_shell_cmd",
                "arguments": {"evidence_id": "security"},
            },
        }
    )

    assert response is not None
    assert response["error"]["code"] == -32602
    assert "not allowlisted" in response["error"]["message"]


def test_mcp_server_exposes_session_scoped_read_only_tools(tmp_path):
    server, session = _runtime(tmp_path)
    (session.reports_dir / "report.json").write_text(
        json.dumps({"findings": [{"finding_id": "F-1", "finding": "Suspicious execution"}]}),
        encoding="utf-8",
    )
    (session.findings_dir / "unknowns.json").write_text(json.dumps({"unknown_count": 1}), encoding="utf-8")
    (session.findings_dir / "coverage.json").write_text(json.dumps({"overall_case_coverage": 0.75}), encoding="utf-8")
    (session.findings_dir / "agent_trace.json").write_text(
        json.dumps({"schema_version": "agent-trace.v1", "summary": {"finding_count": 1}}),
        encoding="utf-8",
    )
    (session.findings_dir / "artifact_manifest.json").write_text(
        json.dumps({"status": "COMPLETED", "artifacts": []}),
        encoding="utf-8",
    )

    list_response = server.handle_payload({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert list_response is not None
    tool_names = {tool["name"] for tool in list_response["result"]["tools"]}
    assert {"get_status", "get_findings", "get_unknowns", "get_agent_trace", "get_artifact_manifest"} <= tool_names

    call_response = server.handle_payload(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "get_agent_trace", "arguments": {}},
        }
    )

    assert call_response is not None
    payload = json.loads(call_response["result"]["content"][0]["text"])
    assert payload["read_only"] is True
    assert payload["raw_evidence_returned"] is False
    assert payload["raw_tool_output_returned"] is False
    assert payload["agent_trace"]["schema_version"] == "agent-trace.v1"
    assert payload["agent_journal_path"] == "reports/agent_journal.md"
