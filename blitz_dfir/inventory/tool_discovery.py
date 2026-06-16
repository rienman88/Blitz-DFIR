from __future__ import annotations

import shutil
from pathlib import Path

from blitz_dfir.core.integrity import sha256_file
from blitz_dfir.inventory.models import ToolDiscoveryItem, ToolDiscoveryReport, ToolStatus
from blitz_dfir.tools.config import ToolConfig, ToolSettings


def discover_tools(tool_config: ToolConfig) -> ToolDiscoveryReport:
    items = tuple(
        _discover_tool(tool_name, settings)
        for tool_name, settings in sorted(tool_config.tools.items())
    )
    return ToolDiscoveryReport(
        tool_count=len(items),
        available_count=sum(1 for item in items if item.status == "AVAILABLE"),
        missing_count=sum(1 for item in items if item.status == "MISSING"),
        disabled_count=sum(1 for item in items if item.status == "DISABLED"),
        hash_mismatch_count=sum(1 for item in items if item.status == "HASH_MISMATCH"),
        tools=items,
    )


def _discover_tool(tool_name: str, settings: ToolSettings) -> ToolDiscoveryItem:
    notes: list[str] = []
    if not settings.allowed:
        return _item(tool_name, settings, status="DISABLED", notes=("tool disabled in config",))

    resolved = shutil.which(settings.executable)
    if resolved is None:
        return _item(tool_name, settings, status="MISSING", notes=("executable not found on PATH",))

    try:
        actual_sha256 = sha256_file(Path(resolved))
    except OSError:
        return _item(
            tool_name,
            settings,
            status="UNREADABLE",
            resolved_path=resolved,
            notes=("resolved executable could not be hashed",),
        )

    status: ToolStatus = "AVAILABLE"
    if settings.expected_sha256 and actual_sha256 != settings.expected_sha256:
        status = "HASH_MISMATCH"
        notes.append("resolved executable hash does not match configured baseline")

    return _item(
        tool_name,
        settings,
        status=status,
        resolved_path=resolved,
        actual_sha256=actual_sha256,
        notes=tuple(notes),
    )


def _item(
    tool_name: str,
    settings: ToolSettings,
    *,
    status: ToolStatus,
    resolved_path: str | None = None,
    actual_sha256: str | None = None,
    notes: tuple[str, ...] = (),
) -> ToolDiscoveryItem:
    return ToolDiscoveryItem(
        tool_name=tool_name,
        executable=settings.executable,
        allowed=settings.allowed,
        status=status,
        resolved_path=resolved_path,
        expected_sha256=settings.expected_sha256,
        actual_sha256=actual_sha256,
        timeout_seconds=settings.timeout_seconds,
        allowed_plugins=settings.allowed_plugins,
        allowed_rules=settings.allowed_rules,
        notes=notes,
    )
