from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from blitz_dfir.core.models import EvidenceCategory, NormalizedEvent
from blitz_dfir.correlation.models import CorrelatedFinding
from blitz_dfir.reasoning.models import ReasoningResult
from blitz_dfir.reasoning.narrative import FORBIDDEN_LANGUAGE_RE, TOOL_REQUEST_RE
from blitz_dfir.reporting.findings import scrub_report_text


class LLMVerificationIssue(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    category: str
    message: str
    references: tuple[str, ...] = ()


class LLMReportVerification(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "llm-report-verification.v1"
    status: Literal["not_run", "passed", "needs_review", "failed"]
    reasoning_enabled: bool
    evidence_type: str | None = None
    raw_evidence_sent: bool = False
    raw_tool_output_sent: bool = False
    checked_hypotheses: int = Field(ge=0)
    checked_decisions: int = Field(ge=0)
    unsupported_hypotheses: int = Field(ge=0)
    invalid_evidence_reference_count: int = Field(ge=0)
    supported_hypotheses_without_evidence: int = Field(ge=0)
    blocked_tool_request_count: int = Field(ge=0)
    forbidden_language_hit_count: int = Field(ge=0)
    finding_count: int = Field(ge=0)
    event_count: int = Field(ge=0)
    issues: tuple[LLMVerificationIssue, ...] = ()
    interpretation: str


def build_llm_report_verification(
    *,
    reasoning: ReasoningResult | None,
    events: tuple[NormalizedEvent, ...],
    findings: tuple[CorrelatedFinding, ...],
    reasoning_error: str | None = None,
) -> LLMReportVerification:
    if reasoning is None:
        if reasoning_error:
            return LLMReportVerification(
                status="not_run",
                reasoning_enabled=True,
                checked_hypotheses=0,
                checked_decisions=0,
                unsupported_hypotheses=0,
                invalid_evidence_reference_count=0,
                supported_hypotheses_without_evidence=0,
                blocked_tool_request_count=0,
                forbidden_language_hit_count=0,
                finding_count=len(findings),
                event_count=len(events),
                issues=(
                    LLMVerificationIssue(
                        severity="MEDIUM",
                        category="reasoning_provider_failed",
                        message=(
                            "Bounded LLM reasoning was enabled, but the provider call failed. "
                            "Deterministic findings and audit artifacts remain the authority."
                        ),
                        references=(scrub_report_text(reasoning_error),),
                    ),
                ),
                interpretation=(
                    "LLM reasoning was enabled but no LLM reasoning was generated because the provider failed. "
                    "Blitz continued with deterministic evidence processing and reporting."
                ),
            )
        return LLMReportVerification(
            status="not_run",
            reasoning_enabled=False,
            checked_hypotheses=0,
            checked_decisions=0,
            unsupported_hypotheses=0,
            invalid_evidence_reference_count=0,
            supported_hypotheses_without_evidence=0,
            blocked_tool_request_count=0,
            forbidden_language_hit_count=0,
            finding_count=len(findings),
            event_count=len(events),
            issues=(
                LLMVerificationIssue(
                    severity="LOW",
                    category="reasoning_disabled",
                    message="Bounded LLM reasoning was not enabled for this run.",
                ),
            ),
            interpretation="No LLM report verification was required because reasoning was disabled.",
        )

    known_event_ids = {event.event_id for event in events}
    issues: list[LLMVerificationIssue] = []
    invalid_refs: set[str] = set()
    missing_supported = 0
    unsupported = 0

    if reasoning.evidence_type is not EvidenceCategory.INFERRED:
        issues.append(
            LLMVerificationIssue(
                severity="CRITICAL",
                category="wrong_evidence_type",
                message="LLM reasoning must remain labeled as INFERRED evidence.",
                references=(reasoning.evidence_type.value,),
            )
        )

    for hypothesis in reasoning.hypotheses:
        if hypothesis.status == "unsupported":
            unsupported += 1
        if hypothesis.status == "supported" and not hypothesis.evidence_event_ids:
            missing_supported += 1
            issues.append(
                LLMVerificationIssue(
                    severity="HIGH",
                    category="supported_hypothesis_without_evidence",
                    message="A supported LLM hypothesis had no normalized event references.",
                    references=(scrub_report_text(hypothesis.hypothesis),),
                )
            )
        for event_id in hypothesis.evidence_event_ids:
            if event_id not in known_event_ids:
                invalid_refs.add(event_id)

    for decision in reasoning.decisions:
        for event_id in decision.evidence_event_ids:
            if event_id not in known_event_ids:
                invalid_refs.add(event_id)

    if invalid_refs:
        issues.append(
            LLMVerificationIssue(
                severity="CRITICAL",
                category="invalid_evidence_reference",
                message="LLM reasoning referenced event IDs that are absent from the bounded report evidence set.",
                references=tuple(sorted(invalid_refs)),
            )
        )

    blocked_tool_requests = tuple(scrub_report_text(item) for item in reasoning.blocked_tool_requests)
    if blocked_tool_requests:
        issues.append(
            LLMVerificationIssue(
                severity="MEDIUM",
                category="blocked_tool_request_observed",
                message="The LLM attempted or echoed a disallowed tool/action request; Blitz blocked it from becoming a report action.",
                references=blocked_tool_requests,
            )
        )

    forbidden_hits = _forbidden_language_hits(reasoning)
    if forbidden_hits:
        issues.append(
            LLMVerificationIssue(
                severity="HIGH",
                category="forbidden_language_detected",
                message="LLM reasoning retained language outside the approved conservative reporting policy.",
                references=tuple(sorted(forbidden_hits)),
            )
        )

    status = _status_from_issues(issues)
    return LLMReportVerification(
        status=status,
        reasoning_enabled=True,
        evidence_type=reasoning.evidence_type.value,
        checked_hypotheses=len(reasoning.hypotheses),
        checked_decisions=len(reasoning.decisions),
        unsupported_hypotheses=unsupported,
        invalid_evidence_reference_count=len(invalid_refs),
        supported_hypotheses_without_evidence=missing_supported,
        blocked_tool_request_count=len(blocked_tool_requests),
        forbidden_language_hit_count=len(forbidden_hits),
        finding_count=len(findings),
        event_count=len(events),
        issues=tuple(issues),
        interpretation=_interpretation(status),
    )


def export_llm_report_verification(report: LLMReportVerification, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report.model_dump(mode="json"), sort_keys=True, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def render_llm_report_verification_markdown(report: LLMReportVerification, path: Path | None = None) -> str:
    lines = [
        "# LLM Report Verification",
        "",
        f"- Status: `{report.status}`",
        f"- Reasoning enabled: `{report.reasoning_enabled}`",
        f"- Evidence type: `{report.evidence_type or 'none'}`",
        f"- Raw evidence sent: `{report.raw_evidence_sent}`",
        f"- Raw tool output sent: `{report.raw_tool_output_sent}`",
        f"- Checked hypotheses: `{report.checked_hypotheses}`",
        f"- Checked decisions: `{report.checked_decisions}`",
        f"- Invalid evidence references: `{report.invalid_evidence_reference_count}`",
        f"- Supported hypotheses without evidence: `{report.supported_hypotheses_without_evidence}`",
        f"- Blocked tool requests: `{report.blocked_tool_request_count}`",
        "",
        report.interpretation,
        "",
        "## Issues",
        "",
    ]
    if report.issues:
        for issue in report.issues:
            refs = ", ".join(issue.references) if issue.references else "none"
            lines.append(f"- `{issue.severity}` `{issue.category}`: {issue.message} References: `{refs}`")
    else:
        lines.append("No LLM verification issue was detected.")
    text = "\n".join(lines).rstrip() + "\n"
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return text


def _forbidden_language_hits(reasoning: ReasoningResult) -> set[str]:
    text_parts: list[str] = [reasoning.narrative]
    text_parts.extend(hypothesis.hypothesis for hypothesis in reasoning.hypotheses)
    text_parts.extend(hypothesis.rationale for hypothesis in reasoning.hypotheses)
    text_parts.extend(reasoning.uncertainty)
    text_parts.extend(reasoning.contradiction_notes)
    for decision in reasoning.decisions:
        text_parts.extend((decision.why, decision.expected, decision.actual))
    text = "\n".join(text_parts)
    hits = {match.group(0).lower() for match in FORBIDDEN_LANGUAGE_RE.finditer(text)}
    hits.update(match.group(0).lower() for match in TOOL_REQUEST_RE.finditer(text))
    return hits


def _status_from_issues(issues: list[LLMVerificationIssue]) -> Literal["passed", "needs_review", "failed"]:
    severities = {issue.severity for issue in issues}
    categories = {issue.category for issue in issues}
    if "CRITICAL" in severities or "invalid_evidence_reference" in categories or "supported_hypothesis_without_evidence" in categories:
        return "failed"
    if "HIGH" in severities or "MEDIUM" in severities:
        return "needs_review"
    return "passed"


def _interpretation(status: str) -> str:
    if status == "passed":
        return "LLM reasoning stayed inside bounded INFERRED reporting controls and referenced known normalized events."
    if status == "needs_review":
        return "LLM reasoning was bounded, but one or more non-critical verification issues need analyst review."
    if status == "failed":
        return "LLM reasoning produced unsupported or invalid references and must not be used as a case conclusion."
    return "No LLM reasoning was generated for this run."
