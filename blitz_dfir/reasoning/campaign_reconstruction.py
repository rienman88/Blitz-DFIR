from __future__ import annotations

from blitz_dfir.correlation.models import CorrelatedFinding


def reconstruct_campaign(
    findings: tuple[CorrelatedFinding, ...],
) -> str:

    stages = []

    for finding in findings:

        for stage in finding.attack_stages:

            stages.append(stage)

    ordered = sorted(set(stages))

    if not ordered:
        return "No attack chain reconstructed."

    return (
        "Observed attack progression: "
        + " -> ".join(ordered)
    )