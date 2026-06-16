from __future__ import annotations

import os

WINDOWS_LIGHT_PROFILE = "windows-light"
NO_WINDOWS_ARTIFACT_PROFILE = "none"

WINDOWS_LIGHT_LOG2TIMELINE_PARSERS = (
    "winevtx",
    "prefetch",
    "lnk",
    "text/setupapi",
    "sqlite/windows_timeline",
    "esedb/srum",
    "winreg/amcache",
    "winreg/bam",
    "winreg/windows_usbstor_devices",
    "winreg/windows_usb_devices",
)
WINDOWS_LIGHT_LOG2TIMELINE_PARSER_LIST = ",".join(WINDOWS_LIGHT_LOG2TIMELINE_PARSERS)

WINDOWS_LIGHT_PSORT_FILTER = (
    "("
    "data_type contains 'windows:evtx' or "
    "data_type contains 'windows:prefetch' or "
    "data_type contains 'windows:lnk' or "
    "data_type contains 'windows:registry' or "
    "data_type contains 'windows:timeline' or "
    "data_type contains 'setupapi' or "
    "data_type contains 'srum'"
    ")"
)

SUPPORTED_WINDOWS_ARTIFACT_PROFILES = frozenset({NO_WINDOWS_ARTIFACT_PROFILE, WINDOWS_LIGHT_PROFILE})


def normalize_windows_artifact_profile(value: str | None) -> str:
    profile = (value or os.environ.get("BLITZ_WINDOWS_ARTIFACT_PROFILE") or NO_WINDOWS_ARTIFACT_PROFILE).strip().lower()
    if profile in {"", "0", "false", "off", "disabled"}:
        return NO_WINDOWS_ARTIFACT_PROFILE
    if profile not in SUPPORTED_WINDOWS_ARTIFACT_PROFILES:
        raise ValueError(
            "unsupported Windows artifact profile: "
            f"{profile}; expected one of {', '.join(sorted(SUPPORTED_WINDOWS_ARTIFACT_PROFILES))}"
        )
    return profile


def log2timeline_parsers_for_profile(profile: str | None = None) -> str | None:
    explicit = os.environ.get("BLITZ_LOG2TIMELINE_PARSERS")
    if explicit:
        return explicit
    if normalize_windows_artifact_profile(profile) == WINDOWS_LIGHT_PROFILE:
        return WINDOWS_LIGHT_LOG2TIMELINE_PARSER_LIST
    return None


def psort_filter_for_profile(profile: str | None = None) -> str | None:
    if normalize_windows_artifact_profile(profile) == WINDOWS_LIGHT_PROFILE:
        return WINDOWS_LIGHT_PSORT_FILTER
    return None

