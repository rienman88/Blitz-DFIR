from __future__ import annotations

import hashlib
import json

import pytest

from blitz_dfir.audit.audit_log import AuditLogger
from blitz_dfir.core.manifest import load_manifest
from blitz_dfir.core.session import create_session
from blitz_dfir.exceptions import EvidenceSecurityError, ValidationError
from blitz_dfir.mcp.dispatcher import ToolDispatcher
from blitz_dfir.mcp.tool_registry import ToolRegistry


def _manifest_and_session(tmp_path):
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
    return manifest, session


def test_dispatcher_runs_registered_allowlisted_handler(tmp_path):
    manifest, session = _manifest_and_session(tmp_path)
    registry = ToolRegistry()

    def handler(context, params):
        return {
            "case_id": context.case_id,
            "evidence_id": context.evidence_id,
            "param": params["value"],
        }

    registry.register("events", handler)
    audit = AuditLogger(session.audit_log_path)
    dispatcher = ToolDispatcher(manifest=manifest, session=session, registry=registry, audit=audit)

    result = dispatcher.dispatch({"tool": "events", "evidence_id": "security", "params": {"value": 7}})

    assert result == {"case_id": "case-001", "evidence_id": "security", "param": 7}
    entries = [json.loads(line) for line in session.audit_log_path.read_text(encoding="utf-8").splitlines()]
    assert [entry["event_type"] for entry in entries] == [
        "tool_request_validated",
        "tool_request_completed",
    ]


def test_dispatcher_rejects_disallowed_tool(tmp_path):
    manifest, session = _manifest_and_session(tmp_path)
    audit = AuditLogger(session.audit_log_path)
    dispatcher = ToolDispatcher(manifest=manifest, session=session, registry=ToolRegistry(), audit=audit)

    with pytest.raises(ValidationError):
        dispatcher.dispatch({"tool": "execute_shell_cmd", "evidence_id": "security"})

    entries = [json.loads(line) for line in session.audit_log_path.read_text(encoding="utf-8").splitlines()]
    assert entries[0]["event_type"] == "tool_request_rejected"
    assert entries[0]["data"]["reason"] == "tool_not_allowlisted"


def test_dispatcher_rejects_unknown_evidence_id(tmp_path):
    manifest, session = _manifest_and_session(tmp_path)
    registry = ToolRegistry()
    registry.register("events", lambda context, params: {})
    dispatcher = ToolDispatcher(manifest=manifest, session=session, registry=registry)

    with pytest.raises(EvidenceSecurityError):
        dispatcher.dispatch({"tool": "events", "evidence_id": "missing"})


def test_dispatcher_rejects_unregistered_allowlisted_handler(tmp_path):
    manifest, session = _manifest_and_session(tmp_path)
    dispatcher = ToolDispatcher(manifest=manifest, session=session, registry=ToolRegistry())

    with pytest.raises(ValidationError):
        dispatcher.dispatch({"tool": "events", "evidence_id": "security"})


def test_registry_rejects_unallowlisted_handler():
    registry = ToolRegistry()

    with pytest.raises(ValidationError):
        registry.register("execute_shell_cmd", lambda context, params: {})
