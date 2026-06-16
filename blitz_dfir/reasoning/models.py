from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from blitz_dfir.core.models import EvidenceCategory


class TokenUsage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prompt_tokens: int | None = Field(default=None, ge=0)
    completion_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)


class ProviderMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str
    model: str
    base_url: str | None = None
    response_id: str | None = None


class LLMMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["system", "user", "assistant"]
    content: str


class LLMRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    messages: tuple[LLMMessage, ...]
    model: str
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    max_tokens: int = Field(default=1200, ge=1, le=8000)


class LLMResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str
    provider_metadata: ProviderMetadata
    token_usage: TokenUsage | None = None


class Hypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hypothesis: str
    status: Literal["supported", "unsupported", "needs_validation"]
    evidence_event_ids: tuple[str, ...] = ()
    rationale: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_type: EvidenceCategory = EvidenceCategory.INFERRED


class AnalystDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision_id: str
    why: str
    expected: str
    actual: str
    evidence_event_ids: tuple[str, ...] = ()
    evidence_type: EvidenceCategory = EvidenceCategory.INFERRED

class ForensicPerspective(BaseModel):
    model_config = ConfigDict(extra="forbid")

    firstness: str = ""
    secondness: str = ""
    thirdness: str = ""
    devil_advocate: str = ""
    verdict: str = ""

    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

class CompetingHypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hypothesis: str

    status: Literal[
        "supported",
        "alternative",
        "rejected",
    ]

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    rationale: str

    evidence_event_ids: tuple[str, ...] = ()

class ReasoningResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_type: EvidenceCategory = EvidenceCategory.INFERRED

    hypotheses: tuple[Hypothesis, ...] = ()

    uncertainty: tuple[str, ...] = ()

    contradiction_notes: tuple[str, ...] = ()

    narrative: str = ""

    decisions: tuple[AnalystDecision, ...] = ()

    blocked_tool_requests: tuple[str, ...] = ()

    prompt_hash: str

    provider_metadata: ProviderMetadata | None = None

    token_usage: TokenUsage | None = None

    forensic_reasoning: ForensicPerspective | None = None

    campaign_reconstruction: str = ""

    explainability: dict[str, object] = Field(
        default_factory=dict,
    )

    competing_hypotheses: tuple[
        CompetingHypothesis,
        ...
    ] = ()