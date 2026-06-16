from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, TextIO

from pydantic import ValidationError as PydanticValidationError

from blitz_dfir.audit.audit_log import AuditLogger
from blitz_dfir.core.manifest import load_manifest
from blitz_dfir.core.models import EvidenceManifest
from blitz_dfir.core.session import CaseSession
from blitz_dfir.core.session import create_session
from blitz_dfir.exceptions import BlitzError
from blitz_dfir.mcp.default_tools import build_default_tool_registry
from blitz_dfir.mcp.dispatcher import ToolDispatcher
from blitz_dfir.tools.config import load_tool_config

SERVER_NAME = "blitz-dfir"
SERVER_VERSION = "0.1.0"
DEFAULT_PROTOCOL_VERSION = "2024-11-05"
_READ_ONLY_TOOLS = frozenset(
    {
        "get_status",
        "get_findings",
        "get_unknowns",
        "get_agent_trace",
        "get_artifact_manifest",
    }
)


class StdioMCPServer:
    def __init__(self, *, dispatcher: ToolDispatcher, manifest: EvidenceManifest, session: CaseSession):
        self.dispatcher = dispatcher
        self.manifest = manifest
        self.session = session

    def handle_payload(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        request_id = payload.get("id")
        method = payload.get("method")
        if method == "notifications/initialized":
            return None
        try:
            result = self._dispatch_method(method, payload.get("params"))
            return _result_response(request_id, result)
        except Exception as exc:  # noqa: BLE001 - MCP must convert failures into JSON-RPC errors.
            return _error_response(request_id, exc)

    def _dispatch_method(self, method: object, params: object) -> dict[str, Any]:
        if method == "initialize":
            client_version = _param_dict(params).get("protocolVersion")
            return {
                "protocolVersion": str(client_version or DEFAULT_PROTOCOL_VERSION),
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            }
        if method == "tools/list":
            return {"tools": _tool_specs()}
        if method == "tools/call":
            return self._tool_call(_param_dict(params))
        raise ValueError(f"unsupported MCP method: {method}")

    def _tool_call(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError("tools/call requires a non-empty tool name")
        if name in _READ_ONLY_TOOLS:
            return _read_only_tool_call(name=name, session=self.session, manifest=self.manifest)
        arguments = _param_dict(params.get("arguments"))
        evidence_id = arguments.get("evidence_id")
        if not isinstance(evidence_id, str) or not evidence_id:
            raise ValueError("typed Blitz tool call requires evidence_id")
        tool_params = _tool_params(arguments)
        result = self.dispatcher.dispatch(
            {
                "tool": name,
                "evidence_id": evidence_id,
                "params": tool_params,
            }
        )
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(result, sort_keys=True, ensure_ascii=True),
                }
            ],
            "isError": False,
        }


def run_mcp_stdio_server(
    *,
    manifest_path: Path,
    tool_config_path: Path,
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    manifest = load_manifest(manifest_path)
    session = create_session(manifest)
    audit = AuditLogger(
        session.audit_log_path,
        session_id=session.session_id,
        case_id=manifest.case_id,
    )
    audit.append(
        "mcp_server_started",
        {
            "manifest": str(manifest.source_path),
            "tool_config": str(tool_config_path),
            "registered_evidence": [record.evidence_id for record in manifest.evidence],
        },
    )
    registry = build_default_tool_registry(
        manifest=manifest,
        session=session,
        tool_config=load_tool_config(tool_config_path),
    )
    dispatcher = ToolDispatcher(manifest=manifest, session=session, registry=registry, audit=audit)
    server = StdioMCPServer(dispatcher=dispatcher, manifest=manifest, session=session)
    print(
        f"blitz-dfir MCP server ready: case={manifest.case_id} session={session.session_id}",
        file=stderr,
        flush=True,
    )
    _serve_stdio(server=server, stdin=stdin, stdout=stdout, stderr=stderr)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m blitz_dfir.mcp.stdio_server")
    parser.add_argument("--manifest", required=True, help="Path to case manifest YAML.")
    parser.add_argument(
        "--tool-config",
        default="config/tools.yaml",
        help="Path to Blitz tool configuration YAML.",
    )
    args = parser.parse_args()
    return run_mcp_stdio_server(
        manifest_path=Path(args.manifest),
        tool_config_path=Path(args.tool_config),
    )


def _serve_stdio(
    *,
    server: StdioMCPServer,
    stdin: TextIO,
    stdout: TextIO,
    stderr: TextIO,
) -> None:
    for line in stdin:
        if not line.strip():
            continue
        method_label = "invalid"
        try:
            payload = json.loads(line)
            if not isinstance(payload, dict):
                raise ValueError("JSON-RPC payload must be an object")
            method_label = str(payload.get("method", "unknown"))
            response = server.handle_payload(payload)
        except json.JSONDecodeError as exc:
            response = _error_response(None, exc)
        if response is None:
            continue
        stdout.write(json.dumps(response, sort_keys=True, ensure_ascii=True) + "\n")
        stdout.flush()
        print(f"handled MCP method: {method_label}", file=stderr, flush=True)


def _tool_params(arguments: dict[str, Any]) -> dict[str, Any]:
    nested = arguments.get("params")
    if isinstance(nested, dict):
        return dict(nested)
    return {key: value for key, value in arguments.items() if key != "evidence_id"}


def _read_only_tool_call(*, name: str, session: CaseSession, manifest: EvidenceManifest) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "typed_tool": name,
        "case_id": session.case_id,
        "session_id": session.session_id,
        "read_only": True,
        "raw_evidence_returned": False,
        "raw_tool_output_returned": False,
    }
    if name == "get_status":
        payload.update(
            {
                "session_state": _load_json(session.audit_dir / "session_state.json"),
                "progress": _load_json(session.audit_dir / "progress.json"),
                "registered_evidence": [record.evidence_id for record in manifest.evidence],
                "available_artifacts": _available_artifacts(session),
            }
        )
    elif name == "get_findings":
        report = _load_json(session.reports_dir / "report.json")
        payload.update(
            {
                "findings": report.get("findings", []) if isinstance(report.get("findings"), list) else [],
                "report_path": _relative(session.reports_dir / "report.json", session),
                "overall_findings_path": _relative(session.findings_dir / "overall_findings.md", session),
            }
        )
    elif name == "get_unknowns":
        payload.update(
            {
                "unknowns": _load_json(session.findings_dir / "unknowns.json"),
                "coverage": _load_json(session.findings_dir / "coverage.json"),
            }
        )
    elif name == "get_agent_trace":
        payload.update(
            {
                "agent_trace": _load_json(session.findings_dir / "agent_trace.json"),
                "agent_journal_path": _relative(session.reports_dir / "agent_journal.md", session),
            }
        )
    elif name == "get_artifact_manifest":
        payload.update({"artifact_manifest": _load_json(session.findings_dir / "artifact_manifest.json")})
    else:
        raise ValueError(f"unsupported read-only tool: {name}")
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(payload, sort_keys=True, ensure_ascii=True),
            }
        ],
        "isError": False,
    }


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"unparsed": True, "path": str(path.name)}
    return value if isinstance(value, dict) else {"value": value}


def _available_artifacts(session: CaseSession) -> dict[str, str]:
    candidates = {
        "report_json": session.reports_dir / "report.json",
        "overall_findings": session.findings_dir / "overall_findings.md",
        "overall_reports": session.reports_dir / "overall_reports.md",
        "collated_audit": session.audit_dir / "collated_audit.md",
        "agent_trace": session.findings_dir / "agent_trace.json",
        "agent_journal": session.reports_dir / "agent_journal.md",
        "unknowns": session.findings_dir / "unknowns.json",
        "validation": session.findings_dir / "validation.json",
        "artifact_manifest": session.findings_dir / "artifact_manifest.json",
    }
    return {name: _relative(path, session) for name, path in candidates.items() if path.exists()}


def _relative(path: Path, session: CaseSession) -> str:
    try:
        return str(path.resolve().relative_to(session.session_root.resolve())).replace("\\", "/")
    except ValueError:
        return "[outside-session-root]"


def _param_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _result_response(request_id: object, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error_response(request_id: object, exc: Exception) -> dict[str, Any]:
    code = -32602 if isinstance(exc, (PydanticValidationError, ValueError, BlitzError)) else -32000
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": code,
            "message": str(exc),
            "type": exc.__class__.__name__,
        },
    }


def _tool_specs() -> list[dict[str, Any]]:
    return [
        _read_only_tool_spec("get_status", "Read the current Blitz session state, progress, and artifact availability."),
        _read_only_tool_spec("get_findings", "Read current session report findings without raw evidence or raw tool output."),
        _read_only_tool_spec("get_unknowns", "Read current session unknowns and coverage summaries."),
        _read_only_tool_spec("get_agent_trace", "Read current session agent_trace.json and agent journal reference."),
        _read_only_tool_spec("get_artifact_manifest", "Read current session artifact manifest hashes."),
        _tool_spec("strings", "Run bounded strings extraction against registered evidence."),
        _tool_spec("timeline", "Run log2timeline against supported registered evidence."),
        _tool_spec(
            "disk_triage",
            "Run bounded Sleuth Kit filesystem triage against registered E01/DD evidence.",
            optional_properties={
                "max_partitions": {
                    "type": "integer",
                    "description": "Maximum selected partitions to enumerate.",
                },
                "max_entries": {
                    "type": "integer",
                    "description": "Maximum filesystem entries to record across selected partitions.",
                },
                "max_seconds_per_partition": {
                    "type": "integer",
                    "description": "Maximum fls runtime per partition.",
                },
                "timeout_seconds": {
                    "type": "integer",
                    "description": "Optional bounded tool timeout, 1-7200 seconds.",
                },
            },
        ),
        _tool_spec(
            "psort",
            "Convert registered PLASO evidence to a bounded CSV timeline.",
            optional_properties={
                "profile": {
                    "type": "string",
                    "enum": ["triage", "full"],
                    "description": "triage applies high-signal filters; full exports every event.",
                },
                "filter": {
                    "type": "string",
                    "description": "Optional Plaso event filter expression.",
                },
                "slice": {
                    "type": "string",
                    "description": "Optional psort --slice timestamp.",
                },
                "slice_size": {
                    "type": "integer",
                    "description": "Optional psort --slice_size in minutes.",
                },
                "timeout_seconds": {
                    "type": "integer",
                    "description": "Optional bounded tool timeout, 1-7200 seconds.",
                },
            },
        ),
        _tool_spec("events", "Run Chainsaw EVTX triage against registered EVTX evidence."),
        _tool_spec("pcap", "Run bounded tshark PCAP triage against registered PCAP evidence."),
        _tool_spec(
            "memory",
            "Run an allowlisted Volatility plugin against registered memory evidence.",
            extra_properties={"plugin": {"type": "string"}},
        ),
        _tool_spec(
            "yara",
            "Run an allowlisted YARA rule against registered evidence.",
            extra_properties={"rule": {"type": "string"}},
        ),
    ]


def _read_only_tool_spec(name: str, description: str) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {},
            "required": [],
        },
    }


def _tool_spec(
    name: str,
    description: str,
    *,
    extra_properties: dict[str, dict[str, Any]] | None = None,
    optional_properties: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "evidence_id": {
            "type": "string",
            "description": "Evidence ID from the Blitz case manifest.",
        }
    }
    required = ["evidence_id"]
    if extra_properties:
        properties.update(extra_properties)
        required.extend(extra_properties)
    if optional_properties:
        properties.update(optional_properties)
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": properties,
            "required": required,
        },
    }


if __name__ == "__main__":
    raise SystemExit(main())
