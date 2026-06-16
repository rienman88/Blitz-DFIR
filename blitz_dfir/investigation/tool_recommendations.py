from __future__ import annotations

TOOL_RECOMMENDATIONS: dict[str, tuple[str, ...]] = {
    "initial_access_or_lateral_movement": (
        "events",
        "timeline",
    ),
    "Initial Access": (
        "events",
        "timeline",
    ),
    "execution": (
        "memory",
        "strings",
        "timeline",
    ),
    "Execution": (
        "memory",
        "strings",
        "timeline",
    ),
    "persistence": (
        "events",
        "timeline",
        "yara",
    ),
    "Persistence": (
        "events",
        "timeline",
        "yara",
    ),
    "privilege_or_credential_use": (
        "events",
        "memory",
    ),
    "Privilege Escalation": (
        "events",
        "memory",
    ),
    "defense_evasion_or_injection": (
        "memory",
        "yara",
        "strings",
    ),
    "Defense Evasion": (
        "memory",
        "yara",
        "strings",
    ),
    "credential_access": (
        "memory",
        "events",
        "strings",
    ),
    "Credential Access": (
        "memory",
        "events",
        "strings",
    ),
    "command_and_control_or_discovery": (
        "pcap",
        "memory",
        "timeline",
    ),
    "Discovery": (
        "memory",
        "timeline",
    ),
    "Lateral Movement": (
        "events",
        "pcap",
        "timeline",
    ),
    "Collection": (
        "timeline",
        "memory",
    ),
    "Command and Control": (
        "pcap",
        "memory",
    ),
    "Exfiltration": (
        "pcap",
        "timeline",
    ),
    "Impact": (
        "events",
        "timeline",
    ),
}
