from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class TruthEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp_utc: str
    category: str
    description: str

    attack_stage: str | None = None


class TruthFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_type: str
    category: str
    title: str

    attack_stages: tuple[str, ...] = ()

    required_events: tuple[str, ...] = ()


class DatasetTruth(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dataset_name: str
    case_id: str

    narrative: str

    expected_findings: tuple[TruthFinding, ...]
    expected_events: tuple[TruthEvent, ...]


class TruthScore(BaseModel):
    model_config = ConfigDict(extra="forbid")

    precision: float = Field(
        ge=0.0,
        le=1.0,
    )

    recall: float = Field(
        ge=0.0,
        le=1.0,
    )

    f1: float = Field(
        ge=0.0,
        le=1.0,
    )

    matched: int = Field(ge=0)

    missed: int = Field(ge=0)

    unexpected: int = Field(ge=0)