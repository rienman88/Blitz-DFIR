from __future__ import annotations

from pathlib import Path
from collections.abc import Callable
from typing import Any

from blitz_dfir.core.models import EvidenceManifest, EvidenceRecord
from blitz_dfir.core.session import CaseSession
from blitz_dfir.mcp.tool_registry import ToolContext, ToolRegistry
from blitz_dfir.tools.base import SafeToolAdapter, ToolAdapterResult
from blitz_dfir.tools.chainsaw_tool import ChainsawAdapter
from blitz_dfir.tools.disk_triage_tool import DiskTriageAdapter
from blitz_dfir.tools.config import ToolConfig
from blitz_dfir.tools.log2timeline_tool import Log2TimelineAdapter
from blitz_dfir.tools.pcap_tool import PcapAdapter
from blitz_dfir.tools.psort_tool import PsortAdapter
from blitz_dfir.tools.strings_tool import StringsAdapter
from blitz_dfir.tools.volatility_tool import VolatilityAdapter
from blitz_dfir.tools.yara_tool import YaraAdapter


def build_default_tool_registry(
    *,
    manifest: EvidenceManifest,
    session: CaseSession,
    tool_config: ToolConfig,
) -> ToolRegistry:
    evidence_by_id = {record.evidence_id: record for record in manifest.evidence}
    registry = ToolRegistry()
    registry.register(
        "timeline",
        _adapter_handler(
            _standard_adapter(Log2TimelineAdapter, tool_config, "log2timeline"),
            session,
            evidence_by_id,
        ),
    )
    registry.register(
        "psort",
        _adapter_handler(_standard_adapter(PsortAdapter, tool_config, "psort"), session, evidence_by_id),
    )
    registry.register(
        "disk_triage",
        _adapter_handler(_standard_adapter(DiskTriageAdapter, tool_config, "disk_triage"), session, evidence_by_id),
    )
    registry.register(
        "memory",
        _adapter_handler(
            VolatilityAdapter(
                executable=tool_config.require("volatility").executable,
                expected_sha256=tool_config.require("volatility").expected_sha256,
                default_timeout_seconds=tool_config.require("volatility").timeout_seconds,
                allowed_plugins=frozenset(tool_config.require("volatility").allowed_plugins),
                symbols_dir=tool_config.require("volatility").symbols_dir,
            ),
            session,
            evidence_by_id,
        ),
    )
    registry.register(
        "events",
        _adapter_handler(_standard_adapter(ChainsawAdapter, tool_config, "chainsaw"), session, evidence_by_id),
    )
    registry.register(
        "pcap",
        _adapter_handler(_standard_adapter(PcapAdapter, tool_config, "tshark"), session, evidence_by_id),
    )
    registry.register(
        "yara",
        _adapter_handler(
            YaraAdapter(
                executable=tool_config.require("yara").executable,
                expected_sha256=tool_config.require("yara").expected_sha256,
                default_timeout_seconds=tool_config.require("yara").timeout_seconds,
                allowed_rules=frozenset(tool_config.require("yara").allowed_rules),
            ),
            session,
            evidence_by_id,
        ),
    )
    registry.register(
        "strings",
        _adapter_handler(_standard_adapter(StringsAdapter, tool_config, "strings"), session, evidence_by_id),
    )
    return registry


def _standard_adapter(
    adapter_cls: type[SafeToolAdapter],
    tool_config: ToolConfig,
    tool_name: str,
) -> SafeToolAdapter:
    settings = tool_config.require(tool_name)
    return adapter_cls(
        executable=settings.executable,
        expected_sha256=settings.expected_sha256,
        tool_version=settings.version,
        default_timeout_seconds=settings.timeout_seconds,
    )


def _adapter_handler(
    adapter: SafeToolAdapter,
    session: CaseSession,
    evidence_by_id: dict[str, EvidenceRecord],
) -> Callable[[ToolContext, dict[str, Any]], dict[str, Any]]:
    def handler(context: ToolContext, params: dict[str, Any]) -> dict[str, Any]:
        result = adapter.run(
            session=session,
            evidence=evidence_by_id[context.evidence_id],
            params=params,
        )
        return _safe_tool_result(result, session=session, typed_tool=context.tool_name)

    return handler


def _safe_tool_result(
    result: ToolAdapterResult,
    *,
    session: CaseSession,
    typed_tool: str,
) -> dict[str, Any]:
    return {
        "typed_tool": typed_tool,
        "tool_name": result.tool_name,
        "evidence_id": result.evidence_id,
        "session_id": session.session_id,
        "case_id": session.case_id,
        "execution": {
            "exit_code": result.exit_code,
            "duration_ms": result.duration_ms,
            "timed_out": result.timed_out,
            "command": _safe_command(result.command, session),
            "command_args_hash": result.args_hash,
            "executable_name": Path(result.command[0]).name,
        },
        "outputs": {
            "primary_output": _relative_output(result.primary_output_path, session),
            "stdout": _relative_output(result.stdout_path, session),
            "stderr": _relative_output(result.stderr_path, session),
            "output_hash": result.output_hash,
            "stdout_hash": result.stdout_hash,
            "stderr_hash": result.stderr_hash,
        },
        "tool_integrity": {
            "executable": Path(result.provenance.executable).name,
            "resolved_executable": (
                Path(result.provenance.resolved_path).name
                if result.provenance.resolved_path
                else None
            ),
            "expected_sha256": result.provenance.expected_sha256,
            "actual_sha256": result.provenance.actual_sha256,
            "verified": result.provenance.verified,
            "warnings": [warning.__dict__ for warning in result.provenance.warnings],
        },
        "warnings": [warning.__dict__ for warning in result.warnings],
        "raw_output_returned": False,
    }


def _relative_output(path: Path, session: CaseSession) -> str:
    try:
        return str(path.resolve().relative_to(session.session_root.resolve())).replace("\\", "/")
    except ValueError:
        return "[outside-session-root]"


def _safe_command(command: tuple[str, ...], session: CaseSession) -> list[str]:
    session_root = session.session_root.resolve()
    safe: list[str] = []
    for index, part in enumerate(command):
        text = str(part)
        if index == 0:
            safe.append(Path(text).name)
            continue
        try:
            path = Path(text)
            if path.is_absolute():
                resolved = path.resolve()
                try:
                    safe.append(str(resolved.relative_to(session_root)).replace("\\", "/"))
                except ValueError:
                    safe.append(f"[outside-session-root]/{resolved.name}")
                continue
        except OSError:
            pass
        safe.append(text)
    return safe
