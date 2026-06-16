from __future__ import annotations

from blitz_dfir.correlation.models import CorrelatedFinding

from .truth_models import DatasetTruth
from .truth_reconstruction import reconstruct_findings
from .truth_scoring import score_truth_reconstruction
from .truth_report import TruthValidationReport


def validate_truth(
    *,
    truth: DatasetTruth,
    findings: tuple[CorrelatedFinding, ...],
) -> TruthValidationReport:

    reconstructed = reconstruct_findings(
        findings
    )

    score = score_truth_reconstruction(
        truth,
        reconstructed,
    )

    return TruthValidationReport(
        dataset_name=truth.dataset_name,
        precision=score.precision,
        recall=score.recall,
        f1=score.f1,
        matched_findings=score.matched,
        missed_findings=score.missed,
        unexpected_findings=score.unexpected,
        passed=score.f1 >= 0.80,
    )