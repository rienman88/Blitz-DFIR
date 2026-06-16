from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ToolStatus = Literal["AVAILABLE", "MISSING", "DISABLED", "HASH_MISMATCH", "UNREADABLE"]
ResourceRisk = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class ToolDiscoveryItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_name: str
    executable: str
    allowed: bool
    status: ToolStatus
    resolved_path: str | None = None
    expected_sha256: str | None = None
    actual_sha256: str | None = None
    timeout_seconds: int | None = None
    allowed_plugins: tuple[str, ...] = ()
    allowed_rules: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()


class ToolDiscoveryReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "tool-discovery.v1"
    tool_count: int = Field(ge=0)
    available_count: int = Field(ge=0)
    missing_count: int = Field(ge=0)
    disabled_count: int = Field(ge=0)
    hash_mismatch_count: int = Field(ge=0)
    tools: tuple[ToolDiscoveryItem, ...]


class EvidenceInventoryItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    evidence_type: str
    category: str
    pipeline: str
    trust_tier: str
    path: str
    size_bytes: int = Field(ge=0)
    sha256: str
    verified: bool
    artifact_family: str
    recommended_tool: str
    config_tool_name: str | None = None
    tool_status: ToolStatus | Literal["NOT_REQUIRED"] = "NOT_REQUIRED"
    batch_id: str | None = None
    task_id: str | None = None
    resource_risk: ResourceRisk
    resource_reason: str
    expected_controls: tuple[str, ...]
    notes: tuple[str, ...] = ()


class EvidenceInventoryReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "evidence-inventory.v1"
    case_id: str
    evidence_count: int = Field(ge=0)
    high_or_critical_risk_count: int = Field(ge=0)
    unavailable_tool_count: int = Field(ge=0)
    items: tuple[EvidenceInventoryItem, ...]


class ObjectInventoryItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    object_type: str
    value: str
    event_count: int = Field(ge=0)
    first_seen_utc: str | None = None
    last_seen_utc: str | None = None
    evidence_ids: tuple[str, ...] = ()
    sample_event_ids: tuple[str, ...] = ()
    risk_tags: tuple[str, ...] = ()


class ObjectInventoryReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "object-inventory.v1"
    case_id: str
    source: str
    normalized_event_count: int = Field(ge=0)
    object_count: int = Field(ge=0)
    object_mention_count: int = Field(ge=0)
    object_type_counts: dict[str, int] = Field(default_factory=dict)
    object_mention_counts: dict[str, int] = Field(default_factory=dict)
    event_category_counts: dict[str, int] = Field(default_factory=dict)
    evidence_event_counts: dict[str, int] = Field(default_factory=dict)
    evidence_without_normalized_events: tuple[str, ...] = ()
    unchecked_or_unsupported_evidence: tuple[str, ...] = ()
    omitted_object_mentions_by_type: dict[str, int] = Field(default_factory=dict)
    max_objects_per_type: int = Field(ge=1)
    items: tuple[ObjectInventoryItem, ...]
    notes: tuple[str, ...] = ()
