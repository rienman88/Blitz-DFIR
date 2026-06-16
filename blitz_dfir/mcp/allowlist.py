from __future__ import annotations

ALLOWED_TOOLS = frozenset(
    {
        "timeline",
        "disk_triage",
        "memory",
        "events",
        "pcap",
        "strings",
        "yara",
        "psort",
    }
)


def is_allowed_tool(tool_name: str) -> bool:
    return tool_name in ALLOWED_TOOLS
