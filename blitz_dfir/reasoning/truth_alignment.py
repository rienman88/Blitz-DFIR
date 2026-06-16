from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from blitz_dfir.validation.truth_report import (
    TruthValidationReport,
)


class TruthAlignment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict_matches_truth: bool

    precision: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    recall: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    f1: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    matched_findings: int = 0
    missed_findings: int = 0
    unexpected_findings: int = 0