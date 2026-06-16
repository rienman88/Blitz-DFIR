from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

EvidencePriority = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]


class CaseObjectiveReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "case-objective.v1"
    case_id: str
    objective: str
    source: Literal["default_evidence_first", "cli"]
    evidence_ids_in_scope: tuple[str, ...] = ()
    success_criteria: tuple[str, ...] = ()
    constraints: tuple[str, ...] = ()


class InvestigationPhase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sequence: int = Field(ge=1)
    phase_id: str
    name: str
    purpose: str
    artifact_families: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()


class InvestigationPlanReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "investigation-plan.v1"
    case_id: str
    mode: Literal["evidence_first"]
    objective: str
    prioritized_artifact_families: tuple[str, ...] = ()
    evidence_ids_in_scope: tuple[str, ...] = ()
    phases: tuple[InvestigationPhase, ...] = ()
    limitations: tuple[str, ...] = ()
    operating_rule: str = (
        "Evidence planning can prioritize work, but findings require manifest-verified evidence, "
        "typed tool output, parser validation, correlation, and traceability."
    )


class EvidenceTriageItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rank: int = Field(ge=1)
    evidence_id: str
    evidence_type: str
    artifact_family: str
    priority: EvidencePriority
    recommended_tool: str
    tool_status: str
    resource_risk: str
    recovery_candidate_count: int = Field(ge=0)
    blocked_recovery_count: int = Field(ge=0)
    reasons: tuple[str, ...] = ()
    expected_questions: tuple[str, ...] = ()


class EvidenceTriageReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "evidence-triage.v1"
    case_id: str
    objective: str
    evidence_count: int = Field(ge=0)
    critical_count: int = Field(ge=0)
    high_count: int = Field(ge=0)
    medium_count: int = Field(ge=0)
    low_count: int = Field(ge=0)
    prioritized_evidence_ids: tuple[str, ...] = ()
    items: tuple[EvidenceTriageItem, ...] = ()
    limitations: tuple[str, ...] = ()
