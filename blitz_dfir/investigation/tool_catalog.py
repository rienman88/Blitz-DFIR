from __future__ import annotations

from blitz_dfir.investigation.models import (
    InvestigationPhase,
    ToolCapability,
)

TOOL_CATALOG = {
    "events": ToolCapability(
        tool_name="events",
        phase=InvestigationPhase.ACQUISITION,
        artifact_family="event_logs",
        description="Extract Windows event log activity",
        produces=("authentication", "process_creation", "logon"),
        next_tools=("timeline",),
    ),
    "memory": ToolCapability(
        tool_name="memory",
        phase=InvestigationPhase.ACQUISITION,
        artifact_family="memory",
        description="Volatility memory acquisition and triage",
        produces=("processes", "process_tree", "command_lines", "network_connections", "injection_candidates"),
        next_tools=("strings", "yara"),
    ),
    "timeline": ToolCapability(
        tool_name="timeline",
        phase=InvestigationPhase.CORRELATION,
        artifact_family="filesystem",
        description="Generate timeline artifacts",
        produces=("timeline",),
        next_tools=(),
    ),
    "pcap": ToolCapability(
        tool_name="pcap",
        phase=InvestigationPhase.ACQUISITION,
        artifact_family="pcap",
        description="Network traffic extraction",
        produces=("connections", "dns", "http"),
        next_tools=("timeline",),
    ),
    "strings": ToolCapability(
        tool_name="strings",
        phase=InvestigationPhase.ACQUISITION,
        artifact_family="memory",
        description="Extract printable strings",
        produces=("indicators",),
        next_tools=("yara",),
    ),
    "yara": ToolCapability(
        tool_name="yara",
        phase=InvestigationPhase.VALIDATION,
        artifact_family="memory",
        description="Indicator validation using rules",
        produces=("matches",),
        next_tools=(),
    ),
    "psort": ToolCapability(
        tool_name="psort",
        phase=InvestigationPhase.ACQUISITION,
        artifact_family="plaso_timeline",
        description="Export PLASO timeline",
        produces=("timeline",),
        next_tools=(),
    ),
}
