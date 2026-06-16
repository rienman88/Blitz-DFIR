from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


UnknownStatus = Literal["UNKNOWN", "NEEDS_REVIEW", "UNSUPPORTED"]
UnknownSeverity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class UnknownRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    unknown_id: str
    status: UnknownStatus
    severity: UnknownSeverity
    category: str
    source: str
    reason: str
    impact: str
    evidence_id: str | None = None
    recommended_action: str
    metadata: dict[str, object] = Field(default_factory=dict)


class UnknownsReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "unknowns.v1"
    unknown_count: int = Field(ge=0)
    critical_count: int = Field(ge=0)
    high_count: int = Field(ge=0)
    records: tuple[UnknownRecord, ...] = ()
