from __future__ import annotations

from .truth_models import (
    DatasetTruth,
    TruthFinding,
    TruthScore,
)

def _signature(
    finding: TruthFinding,
) -> tuple[str, str, str]:

    return (
        finding.finding_type.lower().strip(),
        finding.category.lower().strip(),
        finding.title.lower().strip(),
    )

def score_truth_reconstruction(
    truth: DatasetTruth,
    reconstructed: tuple[TruthFinding, ...],
) -> TruthScore:

    expected = {
        _signature(finding)
        for finding in truth.expected_findings
    }

    observed = {
        _signature(finding)
        for finding in reconstructed
    }

    matched = len(expected & observed)

    missed = len(expected - observed)

    unexpected = len(observed - expected)

    precision = (
        matched / (matched + unexpected)
        if matched + unexpected
        else 0.0
    )

    recall = (
        matched / (matched + missed)
        if matched + missed
        else 0.0
    )

    f1 = (
        (2 * precision * recall) / (precision + recall)
        if precision + recall
        else 0.0
    )

    return TruthScore(
        precision=precision,
        recall=recall,
        f1=f1,
        matched=matched,
        missed=missed,
        unexpected=unexpected,
    )