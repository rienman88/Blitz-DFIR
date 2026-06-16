from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

RecoveryCandidateStatus = Literal[
    "PRIMARY_PLANNED",
    "TYPED_AVAILABLE",
    "TYPED_UNAVAILABLE",
    "NOT_ALLOWLISTED",
    "NOT_INTEGRATED",
    "NOT_APPLICABLE",
]


class RecoveryCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sequence: int = Field(ge=1)
    tool: str
    config_tool_name: str | None = None
    typed_adapter_available: bool
    allowlisted: bool
    status: RecoveryCandidateStatus
    auto_runnable: bool
    rationale: str
    preconditions: tuple[str, ...] = ()
    expected_output: str | None = None
    notes: tuple[str, ...] = ()


class EvidenceRecoveryPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    evidence_type: str
    category: str
    pipeline: str
    primary_batch_id: str | None = None
    primary_task_id: str | None = None
    primary_tool: str | None = None
    primary_artifact_family: str | None = None
    sequential_execution_required: bool = True
    candidate_count: int = Field(ge=0)
    auto_runnable_candidate_count: int = Field(ge=0)
    blocked_candidate_count: int = Field(ge=0)
    unchecked_recovery_paths: tuple[str, ...] = ()
    candidates: tuple[RecoveryCandidate, ...]


class RecoveryPlanReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "recovery-plan.v1"
    case_id: str
    sequential_execution_required: bool = True
    evidence_count: int = Field(ge=0)
    candidate_count: int = Field(ge=0)
    auto_runnable_candidate_count: int = Field(ge=0)
    blocked_candidate_count: int = Field(ge=0)
    evidence_with_blocked_recovery_count: int = Field(ge=0)
    unsupported_evidence_count: int = Field(ge=0)
    items: tuple[EvidenceRecoveryPlan, ...]
    notes: tuple[str, ...] = ()
