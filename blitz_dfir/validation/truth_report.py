from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from .truth_models import TruthScore


class TruthValidationReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dataset_name: str

    precision: float
    recall: float
    f1: float

    matched_findings: int
    missed_findings: int
    unexpected_findings: int

    passed: bool