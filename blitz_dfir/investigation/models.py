from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class InvestigationPhase(str, Enum):
    ACQUISITION = "acquisition"
    CORRELATION = "correlation"
    VALIDATION = "validation"
    REASONING = "reasoning"
    REPORTING = "reporting"


class ToolCapability(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_name: str
    phase: InvestigationPhase
    artifact_family: str
    description: str
    produces: tuple[str, ...] = ()
    next_tools: tuple[str, ...] = ()


class InvestigationGuidanceReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "investigation-guidance.v1"
    finding_count: int = Field(ge=0)
    attack_stage_count: int = Field(ge=0)
    recommendation_count: int = Field(ge=0)
    recommendations: tuple[str, ...] = ()
    recommended_tools: tuple[str, ...] = ()
    attack_stages: tuple[str, ...] = ()
    finding_categories: tuple[str, ...] = ()
