from __future__ import annotations

from blitz_dfir.mcp.dispatcher import ToolDispatcher, ToolRequest


class BlitzMCPServer:
    """Minimal in-process server facade until external MCP transport is wired."""

    def __init__(self, dispatcher: ToolDispatcher):
        self.dispatcher = dispatcher

    def call_tool(self, payload: dict) -> dict:
        return self.dispatcher.dispatch(ToolRequest.model_validate(payload))

