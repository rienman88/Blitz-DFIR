from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

BatchStatus = Literal["PENDING", "RUNNING", "COMPLETED", "SKIPPED", "FAILED"]


class BatchResourcePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_parallel_tools: int = Field(default=1, ge=1, le=1)
    timeout_seconds: int | None = Field(default=None, ge=1, le=7200)
    normalized_event_cap: int = Field(default=5000, ge=1)
    full_accounting_required: bool = True
    checkpoint_after_batch: bool = True


class BatchTask(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: str
    tool: str
    evidence_id: str
    evidence_type: str
    artifact_family: str
    params: dict[str, object] = Field(default_factory=dict)
    status: BatchStatus = "PENDING"
    rationale: str


class EvidenceBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    batch_id: str
    sequence: int = Field(ge=1)
    name: str
    artifact_family: str
    tasks: tuple[BatchTask, ...]
    resource_policy: BatchResourcePolicy
    status: BatchStatus = "PENDING"


class BatchPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "batch-plan.v1"
    case_id: str
    mode: str
    triage_context: str | None = None
    prioritized_artifact_families: tuple[str, ...] = ()
    batch_count: int = Field(ge=0)
    task_count: int = Field(ge=0)
    batches: tuple[EvidenceBatch, ...]
