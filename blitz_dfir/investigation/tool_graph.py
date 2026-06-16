from __future__ import annotations

from blitz_dfir.investigation.tool_catalog import TOOL_CATALOG


def recommended_next_tools(tool_name: str) -> tuple[str, ...]:
    capability = TOOL_CATALOG.get(tool_name)

    if capability is None:
        return ()

    return capability.next_tools