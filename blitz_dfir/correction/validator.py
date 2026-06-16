from __future__ import annotations

from blitz_dfir.core.integrity import hash_text
from blitz_dfir.core.models import SignalWarning
from blitz_dfir.correlation.models import Contradiction, CorrelatedFinding, ProcessLineageLink
from blitz_dfir.correction.models import ValidationIssue, ValidationReport
from blitz_dfir.signal.integrity import SignalIntegrityReport

PARSER_SIGNAL_TYPES = {
    "PARSER_DEGRADATION",
    "PARSER_CRASH",
    "EVENT_TRUNCATION",
    "ENCODING_CORRUPTION",
    "TOOL_TIMEOUT",
    "PARTIAL_EXTRACTION",
    "RETRY_EXHAUSTION",
    "ABNORMAL_EVENT_DENSITY",
}

INTEGRITY_SIGNAL_TYPES = {"HASH_MISMATCH", "TOOL_PROVENANCE"}


def validate_case_outputs(
    *,
    findings: tuple[CorrelatedFinding, ...] = (),
    contradictions: tuple[Contradiction, ...] = (),
    signal_report: SignalIntegrityReport | None = None,
    lineage_links: tuple[ProcessLineageLink, ...] = (),
    confidence_threshold: float = 0.50,
    max_contradictions: int = 3,
) -> ValidationReport:
    issues: list[ValidationIssue] = []
    issues.extend(_validate_finding_support(findings))
    issues.extend(_validate_confidence(findings, confidence_threshold))
    issues.extend(_validate_lineage(lineage_links))
    issues.extend(_validate_contradictions(contradictions, max_contradictions))
    parser_integrity_ok = True
    if signal_report is not None:
        parser_issues, parser_integrity_ok = _validate_signal_integrity(signal_report)
        issues.extend(parser_issues)
    return ValidationReport(
        passed=not issues,
        issues=tuple(issues),
        confidence_threshold=confidence_threshold,
        contradiction_count=len(contradictions),
        parser_integrity_ok=parser_integrity_ok,
    )


def downgrade_unverified_findings(
    findings: tuple[CorrelatedFinding, ...],
    warnings: tuple[SignalWarning, ...],
    *,
    penalty: float = 0.30,
) -> tuple[CorrelatedFinding, ...]:
    if not any(warning.warning_type in INTEGRITY_SIGNAL_TYPES for warning in warnings):
        return findings
    downgraded: list[CorrelatedFinding] = []
    for finding in findings:
        modifiers = tuple(dict.fromkeys((*finding.confidence_modifiers, "TOOL_INTEGRITY_UNVERIFIED")))
        downgraded.append(
            finding.model_copy(
                update={
                    "confidence": round(max(finding.confidence - penalty, 0.0), 6),
                    "confidence_modifiers": modifiers,
                    "warnings": tuple((*finding.warnings, *warnings)),
                }
            )
        )
    return tuple(downgraded)


def _validate_finding_support(findings: tuple[CorrelatedFinding, ...]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    for finding in findings:
        event_ids = set(finding.supporting_event_ids)
        anchored_ids = {anchor.event_id for anchor in finding.evidence}
        if not finding.evidence or not event_ids:
            issues.append(
                _issue(
                    "MISSING_EVIDENCE",
                    "CRITICAL",
                    "finding has no evidence anchors or supporting event IDs",
                    finding_id=finding.finding_id,
                    event_ids=tuple(sorted(event_ids)),
                )
            )
            continue
        if not event_ids.issubset(anchored_ids):
            issues.append(
                _issue(
                    "MISSING_EVIDENCE",
                    "HIGH",
                    "finding support event IDs are not fully anchored",
                    finding_id=finding.finding_id,
                    event_ids=tuple(sorted(event_ids - anchored_ids)),
                )
            )
        for anchor in finding.evidence:
            reference = anchor.raw_reference
            if not any((reference.path, reference.offset is not None, reference.record_index is not None)):
                issues.append(
                    _issue(
                        "MISSING_EVIDENCE",
                        "HIGH",
                        "finding evidence anchor lacks raw reference",
                        finding_id=finding.finding_id,
                        event_ids=(anchor.event_id,),
                    )
                )
    return issues


def _validate_confidence(
    findings: tuple[CorrelatedFinding, ...],
    threshold: float,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    for finding in findings:
        if finding.confidence < threshold:
            issues.append(
                _issue(
                    "LOW_CONFIDENCE",
                    "MEDIUM",
                    f"finding confidence {finding.confidence:.2f} is below threshold {threshold:.2f}",
                    finding_id=finding.finding_id,
                    event_ids=finding.supporting_event_ids,
                    metadata={"confidence": finding.confidence, "threshold": threshold},
                )
            )
    return issues


def _validate_lineage(links: tuple[ProcessLineageLink, ...]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    for link in links:
        if link.parent_event_id is None:
            issues.append(
                _issue(
                    "BROKEN_LINEAGE",
                    "HIGH",
                    "process parent ID has no supporting parent event",
                    event_ids=(link.child_event_id,),
                    metadata={
                        "child_process_id": link.child_process_id,
                        "parent_process_id": link.parent_process_id,
                    },
                )
            )
    return issues


def _validate_contradictions(
    contradictions: tuple[Contradiction, ...],
    max_contradictions: int,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    for contradiction in contradictions:
        issues.append(
            _issue(
                "TIMELINE_GAP_OR_CONTRADICTION",
                contradiction.severity,
                contradiction.reason,
                event_ids=tuple(anchor.event_id for anchor in contradiction.evidence),
                metadata={"contradiction_id": contradiction.contradiction_id},
            )
        )
    if len(contradictions) > max_contradictions:
        issues.append(
            _issue(
                "CONTRADICTION_LIMIT_EXCEEDED",
                "HIGH",
                "contradiction count exceeds configured threshold",
                metadata={"count": len(contradictions), "threshold": max_contradictions},
            )
        )
    return issues


def _validate_signal_integrity(
    report: SignalIntegrityReport,
) -> tuple[list[ValidationIssue], bool]:
    issues: list[ValidationIssue] = []
    parser_integrity_ok = True
    for warning in report.warnings:
        if warning.warning_type in PARSER_SIGNAL_TYPES:
            parser_integrity_ok = False
            issues.append(
                _issue(
                    "PARSER_DEGRADATION_OR_SIGNAL_LOSS",
                    warning.severity,
                    warning.impact,
                    metadata={"warning_type": warning.warning_type, "artifact": warning.artifact},
                )
            )
        if warning.warning_type in INTEGRITY_SIGNAL_TYPES:
            issues.append(
                _issue(
                    "TOOL_INTEGRITY_MISMATCH",
                    "CRITICAL",
                    warning.impact,
                    metadata={"warning_type": warning.warning_type, "artifact": warning.artifact},
                )
            )
    for gap in report.analysis_gaps:
        issues.append(
            _issue(
                "MISSING_EVIDENCE",
                gap.severity,
                gap.impact,
                metadata={"source": gap.source, "reason": gap.reason},
            )
        )
    return issues, parser_integrity_ok


def _issue(
    issue_type: str,
    severity: str,
    message: str,
    *,
    finding_id: str | None = None,
    event_ids: tuple[str, ...] = (),
    metadata: dict[str, object] | None = None,
) -> ValidationIssue:
    issue_id = f"ISSUE-{hash_text('|'.join([issue_type, message, finding_id or '', *event_ids]))[:12].upper()}"
    return ValidationIssue(
        issue_id=issue_id,
        issue_type=issue_type,
        severity=severity,  # type: ignore[arg-type]
        message=message,
        finding_id=finding_id,
        event_ids=event_ids,
        metadata=metadata or {},
    )
