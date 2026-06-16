from __future__ import annotations

import json

from blitz_dfir.audit.audit_log import AuditLogger


def test_audit_logger_chains_entries(tmp_path):
    log_path = tmp_path / "audit" / "session.ndjson"
    logger = AuditLogger(log_path)

    first = logger.append("manifest_loaded", {"case_id": "case-001"})
    second = logger.append("evidence_verified", {"evidence_id": "security"})

    assert first.sequence == 1
    assert first.previous_hash is None
    assert second.sequence == 2
    assert second.previous_hash == first.entry_hash
    assert logger.verify_chain() is True


def test_audit_chain_detects_tamper(tmp_path):
    log_path = tmp_path / "audit" / "session.ndjson"
    logger = AuditLogger(log_path)
    logger.append("manifest_loaded", {"case_id": "case-001"})
    logger.append("evidence_verified", {"evidence_id": "security"})
    text = log_path.read_text(encoding="utf-8").replace("security", "tampered")
    log_path.write_text(text, encoding="utf-8")

    assert logger.verify_chain() is False


def test_audit_logger_enriches_checkpoint_initiator_component_boundary_and_behavior(tmp_path, monkeypatch):
    monkeypatch.setenv("BLITZ_AGENT_FRAMEWORK", "Protocol SIFT")
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    monkeypatch.setenv("LLM_MODEL", "llama3.2:1b")
    log_path = tmp_path / "audit" / "session.ndjson"
    logger = AuditLogger(log_path)

    logger.append("analysis_started", {"case_id": "case-001"}, timestamp_utc="2026-05-31T00:00:00Z")
    payload = json.loads(log_path.read_text(encoding="utf-8"))
    data = payload["data"]

    assert data["initiated_by"] == "Protocol SIFT -> Blitz DFIR (LLM configured: ollama/llama3.2:1b)"
    assert data["component"] == "pipeline_orchestrator"
    assert data["trust_boundary"] == "Blitz deterministic control plane"
    assert data["behavior"] == "expected"
    assert logger.verify_chain() is True


def test_audit_logger_marks_rejected_tool_request_as_security_relevant(tmp_path):
    log_path = tmp_path / "audit" / "session.ndjson"
    logger = AuditLogger(log_path)

    entry = logger.append(
        "tool_request_rejected",
        {"tool": "execute_shell_cmd", "evidence_id": "security", "reason": "tool_not_allowlisted"},
    )

    assert entry.data["initiated_by"] == "Blitz MCP dispatcher -> execute_shell_cmd"
    assert entry.data["component"] == "security_boundary"
    assert entry.data["trust_boundary"] == "MCP typed allowlist"
    assert entry.data["behavior"] == "security_relevant_rejection"
    assert logger.verify_chain() is True
