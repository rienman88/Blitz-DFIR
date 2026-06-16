from __future__ import annotations

from blitz_dfir.correlation.models import CorrelatedFinding

from .truth_models import TruthFinding


def reconstruct_findings(
    findings: tuple[CorrelatedFinding, ...],
) -> tuple[TruthFinding, ...]:

    output: list[TruthFinding] = []

    for finding in findings:
        output.append(
            TruthFinding(
                finding_type=finding.finding_type,
                category=finding.category,
                title=finding.title,
                attack_stages=finding.attack_stages,
            )
        )

    return tuple(output)