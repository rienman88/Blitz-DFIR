from __future__ import annotations

from pathlib import Path

from blitz_dfir.core.models import EvidenceType
from blitz_dfir.exceptions import ValidationError


EXTENSION_TYPE_HINTS: dict[str, EvidenceType] = {
    ".e01": EvidenceType.E01,
    ".dd": EvidenceType.DD,
    ".img": EvidenceType.DD,
    ".raw": EvidenceType.MEMORY,
    ".mem": EvidenceType.MEMORY,
    ".evtx": EvidenceType.EVTX,
    ".pcap": EvidenceType.PCAP,
    ".pcapng": EvidenceType.PCAP,
    ".plaso": EvidenceType.PLASO,
    ".csv": EvidenceType.CSV_TIMELINE,
    ".json": EvidenceType.JSON_EXPORT,
    ".dat": EvidenceType.REGISTRY_HIVE,
}

REGISTRY_HIVE_NAMES = {
    "ntuser.dat",
    "sam",
    "security",
    "software",
    "system",
    "usrclass.dat",
}


def detect_evidence_type(path: Path) -> EvidenceType | None:
    name = path.name.lower()
    if name in REGISTRY_HIVE_NAMES:
        return EvidenceType.REGISTRY_HIVE
    return EXTENSION_TYPE_HINTS.get(path.suffix.lower())


def validate_detected_type(path: Path, declared_type: EvidenceType) -> None:
    detected = detect_evidence_type(path)
    if detected is None:
        return
    compatible = detected == declared_type
    if detected == EvidenceType.JSON_EXPORT and declared_type in {
        EvidenceType.JSON_EXPORT,
        EvidenceType.VOLATILITY_JSON,
        EvidenceType.PREPROCESSED_EVTX,
    }:
        compatible = True
    if detected == EvidenceType.DD and declared_type == EvidenceType.E01:
        compatible = False
    if not compatible:
        raise ValidationError(
            f"declared evidence type {declared_type.value} conflicts with detected type "
            f"{detected.value} for {path.name}"
        )
