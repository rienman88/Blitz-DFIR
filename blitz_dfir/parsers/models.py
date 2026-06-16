from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from blitz_dfir.core.models import EvidenceCategory, SignalWarning, TrustTier


class ParsedRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    parser: str
    source_tool: str
    evidence_id: str
    evidence_type: EvidenceCategory
    trust_tier: TrustTier
    timestamp: str | None = None
    event_type: str
    artifact: str
    message: str = ""
    raw_reference: str | None = None
    fields: dict[str, Any] = Field(default_factory=dict)
    warnings: tuple[SignalWarning, ...] = ()


class ParserResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    parser: str
    source_tool: str
    evidence_id: str
    records: tuple[ParsedRecord, ...]
    warnings: tuple[SignalWarning, ...] = ()
    processed_count: int = Field(ge=0)
    malformed_count: int = Field(ge=0)
    truncated: bool = False

