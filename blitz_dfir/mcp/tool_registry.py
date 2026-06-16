from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from blitz_dfir.exceptions import ValidationError
from blitz_dfir.mcp.allowlist import is_allowed_tool

ToolHandler = Callable[["ToolContext", dict[str, Any]], dict[str, Any]]


@dataclass(frozen=True)
class ToolContext:
    case_id: str
    session_id: str
    tool_name: str
    evidence_id: str
    evidence_path: str
    evidence_type: str
    pipeline: str


class ToolRegistry:
    def __init__(self) -> None:
        self._handlers: dict[str, ToolHandler] = {}

    def register(self, tool_name: str, handler: ToolHandler) -> None:
        if not is_allowed_tool(tool_name):
            raise ValidationError(f"tool is not allowlisted: {tool_name}")
        if tool_name in self._handlers:
            raise ValidationError(f"tool already registered: {tool_name}")
        self._handlers[tool_name] = handler

    def get(self, tool_name: str) -> ToolHandler:
        try:
            return self._handlers[tool_name]
        except KeyError as exc:
            raise ValidationError(f"tool handler not registered: {tool_name}") from exc

    def registered_tools(self) -> tuple[str, ...]:
        return tuple(sorted(self._handlers))
