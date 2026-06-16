from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class AccountingArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact_id: str
    evidence_id: str
    source_tool: str
    parser: str
    source_path: str
    source_sha256: str | None = None
    source_size_bytes: int = Field(ge=0)
    row_count: int = Field(ge=0)
    malformed_count: int = Field(ge=0)
    partial: bool = False
    timed_out: bool = False
    table_name: str
    indexes_created: bool = True
    counts_by_source: dict[str, int] = Field(default_factory=dict)
    counts_by_parser: dict[str, int] = Field(default_factory=dict)
    counts_by_data_type: dict[str, int] = Field(default_factory=dict)
    counts_by_day: dict[str, int] = Field(default_factory=dict)


class FullAccountingSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "full-accounting.v1"
    event_store_path: str
    artifact_count: int = Field(ge=0)
    total_rows: int = Field(ge=0)
    artifacts: tuple[AccountingArtifact, ...] = ()
