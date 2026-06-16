from __future__ import annotations

from blitz_dfir.core.models import NormalizedEvent

PERSISTENCE_CATEGORIES = {
    "service_install",
    "scheduled_task",
    "registry_persistence",
    "autorun",
}

AUTH_CATEGORIES = {
    "privileged_logon",
    "explicit_credential_logon",
    "authentication_failure",
}

NETWORK_CATEGORIES = {
    "network_dns",
    "network_http",
    "network_tls",
    "network_flow",
}

MEMORY_PROCESS_CATEGORIES = {
    "memory_process",
    "memory_process_tree",
    "memory_process_scan",
}

MEMORY_HIGH_SIGNAL_CATEGORIES = {
    "memory_injection_candidate",
}

LOLBIN_TOKENS = (
    "powershell",
    "cmd.exe",
    "rundll32",
    "regsvr32",
    "mshta",
    "wscript",
    "cscript",
    "certutil",
    "bitsadmin",
    "wmic",
    "schtasks",
)

HIGH_SIGNAL_TOKENS = (
    "encodedcommand",
    "frombase64string",
    "downloadstring",
    "invoke-expression",
    "iex",
    "mimikatz",
    "sekurlsa",
    "credential",
    "dump",
    "reverse shell",
)

MEMORY_PROCESS_TOKENS = (
    "powershell.exe",
    "powershell",
    "cmd.exe",
    "rundll32.exe",
    "rundll32",
    "regsvr32.exe",
    "regsvr32",
    "mshta.exe",
    "mshta",
    "wscript.exe",
    "cscript.exe",
    "wmic.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "psexec",
    "procdump",
    "mimikatz",
)

USER_WRITABLE_PATH_TOKENS = (
    "\\users\\",
    "/users/",
    "\\appdata\\",
    "/appdata/",
    "\\temp\\",
    "/temp/",
    "\\programdata\\",
    "/programdata/",
)

PERSISTENCE_LOCATION_TOKENS = (
    "currentversion\\run",
    "currentversion/run",
    "currentversion\\runonce",
    "currentversion/runonce",
    "\\services\\",
    "/services/",
    "\\startup\\",
    "/startup/",
    "winlogon",
)


def assess_group_suspicion(events: tuple[NormalizedEvent, ...] | list[NormalizedEvent]) -> tuple[float, tuple[str, ...]]:
    reasons: list[str] = []
    score = 0.0
    for event in events:
        event_score, event_reasons = assess_event_suspicion(event)
        score = max(score, event_score)
        reasons.extend(event_reasons)

    unique_sources = {
        (event.evidence_id, event.source_tool, event.source_parser)
        for event in events
    }
    if len(events) >= 5:
        score += 0.05
        reasons.append("multiple related events observed in the same correlation group")
    if len(unique_sources) > 1:
        score += 0.10
        reasons.append("same activity is supported by more than one evidence source or parser")

    deduped = _dedupe(reasons)
    if not deduped:
        return 0.05, ("no deterministic suspicious condition matched; retained as low-priority timeline context",)
    return _clamp(score), deduped


def assess_event_suspicion(event: NormalizedEvent) -> tuple[float, tuple[str, ...]]:
    reasons: list[str] = []
    score = 0.05
    haystack = _event_haystack(event)

    if event.category in PERSISTENCE_CATEGORIES:
        score += 0.55
        reasons.append("event category indicates a persistence-capable change")
    if event.category in AUTH_CATEGORIES:
        score += 0.30
        reasons.append("event category involves authentication or privileged credential activity")
    if event.category in NETWORK_CATEGORIES:
        score += 0.20
        reasons.append("network activity is present and should be correlated with host artifacts")
    if event.category in {"yara_match", "string_artifact"}:
        score += 0.40
        reasons.append("content-based detection artifact is present")
    if event.category in MEMORY_PROCESS_CATEGORIES:
        score += 0.15
        reasons.append("memory process inventory row requires host-artifact correlation")
    if event.category in MEMORY_HIGH_SIGNAL_CATEGORIES:
        score += 0.60
        reasons.append("memory plugin output indicates possible injected or suspicious memory region")

    matched_lolbin = _first_token(haystack, LOLBIN_TOKENS)
    if matched_lolbin:
        score += 0.20
        reasons.append(f"living-off-the-land binary or shell token observed: {matched_lolbin}")

    matched_high_signal = _first_token(haystack, HIGH_SIGNAL_TOKENS)
    if matched_high_signal:
        score += 0.30
        reasons.append(f"high-signal command or malware-analysis token observed: {matched_high_signal}")

    matched_memory_process = _first_token(haystack, MEMORY_PROCESS_TOKENS)
    if event.category in MEMORY_PROCESS_CATEGORIES and matched_memory_process:
        score += 0.35
        reasons.append(f"memory process name or command token merits review: {matched_memory_process}")

    if _first_token(haystack, USER_WRITABLE_PATH_TOKENS):
        score += 0.15
        reasons.append("path references a user-writable or temporary execution location")

    if _first_token(haystack, PERSISTENCE_LOCATION_TOKENS):
        score += 0.25
        reasons.append("artifact references a common persistence location")

    unusual_port = event.normalized_fields.get("unusual_port")
    if unusual_port:
        score += 0.20
        reasons.append(f"network destination uses unusual or high-signal port {unusual_port}")

    if event.warnings:
        score += 0.05
        reasons.append("source event carried parser or signal warnings requiring analyst review")

    return _clamp(score), _dedupe(reasons)


def _event_haystack(event: NormalizedEvent) -> str:
    parts = [
        event.category,
        event.artifact,
        event.message,
        " ".join(f"{key}={value}" for key, value in event.normalized_fields.items()),
    ]
    return " ".join(parts).lower()


def _first_token(text: str, tokens: tuple[str, ...]) -> str | None:
    for token in tokens:
        if token in text:
            return token
    return None


def _dedupe(values: list[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return tuple(output)


def _clamp(value: float) -> float:
    return min(max(round(value, 3), 0.0), 1.0)
