from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

MAX_RETRIES = 2
MAX_CORRECTIONS = 2
MAX_PERSISTENT_ITERATIONS = 3

IssueSeverity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
CorrectionStatus = Literal["PENDING", "SUCCESS", "FAILED", "SKIPPED", "FAILED_LOW_CONFIDENCE"]

APPROVED_TRIGGER_REASONS = {
    "MISSING_EVIDENCE_OR_BROKEN_LINEAGE",
    "LOW_CONFIDENCE",
    "PARSER_DEGRADATION_OR_SIGNAL_LOSS",
    "TIMELINE_GAP_OR_CONTRADICTION",
    "CONTRADICTION_LIMIT_EXCEEDED",
    "TOOL_INTEGRITY_MISMATCH",
}

APPROVED_ACTION_TYPES = {
    "NARROW_EVTX_TIME_RANGE",
    "FILTER_STRINGS_EXECUTABLE_REGIONS",
    "RUN_SPECIFIC_VOLATILITY_PLUGIN",
    "SCOPED_PSORT_FILTER",
    "CHUNK_MEMORY_EXTRACTION",
    "ALTERNATE_PARSER_FALLBACK",
    "FALLBACK_CORRELATION_AVAILABLE_SOURCES",
    "DOWNGRADE_CONFIDENCE_FLAG_UNVERIFIED",
    "SCOPED_CORRELATION_REVIEW",
}


class ValidationIssue(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issue_id: str
    issue_type: str
    severity: IssueSeverity
    message: str
    finding_id: str | None = None
    event_ids: tuple[str, ...] = ()
    metadata: dict[str, object] = Field(default_factory=dict)


class ValidationReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    passed: bool
    issues: tuple[ValidationIssue, ...] = ()
    confidence_threshold: float = Field(default=0.50, ge=0.0, le=1.0)
    contradiction_count: int = Field(default=0, ge=0)
    parser_integrity_ok: bool = True


class CorrectionTrigger(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trigger_id: str
    reason: str
    severity: IssueSeverity
    source_issue_id: str
    message: str
    metadata: dict[str, object] = Field(default_factory=dict)


class RecoveryAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_id: str
    action_type: str
    scope: str
    rationale: str
    allowed_tools: tuple[str, ...] = ()
    params: dict[str, object] = Field(default_factory=dict)


class CorrectionAttempt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    correction_id: str
    iteration: int = Field(ge=1)
    trigger: CorrectionTrigger
    action: RecoveryAction
    status: CorrectionStatus
    result: str
    confidence_before: float = Field(ge=0.0, le=1.0)
    confidence_after: float = Field(ge=0.0, le=1.0)
    confidence_delta: float
    changed_from_prior: str
    why: str


class CorrectionHistory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attempts: tuple[CorrectionAttempt, ...] = ()
    final_confidence: float = Field(ge=0.0, le=1.0)
    status: CorrectionStatus
    max_retries: int = Field(default=MAX_RETRIES, ge=0)
    max_corrections: int = Field(default=MAX_CORRECTIONS, ge=0)
    max_iterations: int = Field(default=MAX_PERSISTENT_ITERATIONS, ge=1)

    def as_report_section(self) -> dict[str, object]:
        return {
            "status": self.status,
            "final_confidence": self.final_confidence,
            "max_retries": self.max_retries,
            "max_corrections": self.max_corrections,
            "max_iterations": self.max_iterations,
            "attempts": [attempt.model_dump() for attempt in self.attempts],
        }

