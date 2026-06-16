from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EvidenceCategory(str, Enum):
    RAW = "RAW"
    DERIVED = "DERIVED"
    INFERRED = "INFERRED"


class TrustTier(str, Enum):
    TIER_1_HIGH = "TIER_1_HIGH"
    TIER_2_MEDIUM_HIGH = "TIER_2_MEDIUM_HIGH"
    TIER_3_LOW = "TIER_3_LOW"
    TIER_4_VERY_LOW = "TIER_4_VERY_LOW"


class Pipeline(str, Enum):
    RAW = "raw"
    PROCESSED = "processed"


class EvidenceType(str, Enum):
    E01 = "E01"
    DD = "DD"
    MEMORY = "MEMORY"
    EVTX = "EVTX"
    PCAP = "PCAP"
    REGISTRY_HIVE = "REGISTRY_HIVE"
    FILESYSTEM_ARTIFACT = "FILESYSTEM_ARTIFACT"
    PLASO = "PLASO"
    CSV_TIMELINE = "CSV_TIMELINE"
    JSON_EXPORT = "JSON_EXPORT"
    VOLATILITY_JSON = "VOLATILITY_JSON"
    YARA_MATCHES = "YARA_MATCHES"
    STRINGS_OUTPUT = "STRINGS_OUTPUT"
    PREPROCESSED_EVTX = "PREPROCESSED_EVTX"
    THIRD_PARTY_EXPORT = "THIRD_PARTY_EXPORT"


RAW_TYPES = {
    EvidenceType.E01,
    EvidenceType.DD,
    EvidenceType.MEMORY,
    EvidenceType.EVTX,
    EvidenceType.PCAP,
    EvidenceType.REGISTRY_HIVE,
    EvidenceType.FILESYSTEM_ARTIFACT,
}

PROCESSED_TYPES = {
    EvidenceType.PLASO,
    EvidenceType.CSV_TIMELINE,
    EvidenceType.JSON_EXPORT,
    EvidenceType.VOLATILITY_JSON,
    EvidenceType.YARA_MATCHES,
    EvidenceType.STRINGS_OUTPUT,
    EvidenceType.PREPROCESSED_EVTX,
    EvidenceType.THIRD_PARTY_EXPORT,
}

MAX_MANIFEST_EVIDENCE_INPUTS = 6


def category_for_evidence_type(evidence_type: EvidenceType) -> EvidenceCategory:
    if evidence_type in RAW_TYPES:
        return EvidenceCategory.RAW
    return EvidenceCategory.DERIVED


def pipeline_for_evidence_type(evidence_type: EvidenceType) -> Pipeline:
    if evidence_type in RAW_TYPES:
        return Pipeline.RAW
    return Pipeline.PROCESSED


def trust_for_evidence_type(evidence_type: EvidenceType, internally_generated: bool) -> TrustTier:
    if evidence_type in RAW_TYPES:
        return TrustTier.TIER_1_HIGH
    if internally_generated:
        return TrustTier.TIER_2_MEDIUM_HIGH
    return TrustTier.TIER_3_LOW


class EvidenceRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    evidence_id: str = Field(min_length=1)
    path: Path
    evidence_type: EvidenceType
    category: EvidenceCategory
    pipeline: Pipeline
    trust_tier: TrustTier
    sha256: str
    verified: bool
    size_bytes: int = Field(ge=0)
    internally_generated: bool = False
    description: str | None = None


class EvidenceManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    case_id: str = Field(min_length=1)
    evidence_root: Path
    output_root: Path
    source_path: Path
    evidence: tuple[EvidenceRecord, ...]
    external_evidence: bool = False

    @field_validator("evidence")
    @classmethod
    def require_evidence(cls, value: tuple[EvidenceRecord, ...]) -> tuple[EvidenceRecord, ...]:
        if not value:
            raise ValueError("manifest must include at least one evidence record")
        if len(value) > MAX_MANIFEST_EVIDENCE_INPUTS:
            raise ValueError(f"manifest supports at most {MAX_MANIFEST_EVIDENCE_INPUTS} evidence records per run")
        return value


class RawReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    path: str | None = None
    offset: int | None = Field(default=None, ge=0)
    record_index: int | None = Field(default=None, ge=0)
    original_hash: str | None = None


class SignalWarning(BaseModel):
    model_config = ConfigDict(extra="forbid")

    warning_type: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    artifact: str
    impact: str
    tool: str | None = None
    confidence_penalty: float = Field(default=0.0, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class NormalizedEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    timestamp_utc: str
    category: str
    artifact: str = ""
    message: str = ""
    source_tool: str
    source_parser: str
    evidence_id: str
    evidence_type: EvidenceCategory
    trust_level: TrustTier
    trust_tier: TrustTier
    raw_reference: RawReference
    confidence: float = Field(ge=0.0, le=1.0)
    normalized_fields: dict[str, str] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)
    warnings: tuple[SignalWarning, ...] = ()
