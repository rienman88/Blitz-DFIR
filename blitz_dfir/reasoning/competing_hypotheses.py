from __future__ import annotations

from blitz_dfir.reasoning.models import (
    CompetingHypothesis,
    Hypothesis,
)


def build_competing_hypotheses(
    hypotheses: tuple[Hypothesis, ...],
) -> tuple[CompetingHypothesis, ...]:

    output = []

    for hypothesis in hypotheses:

        status = (
            "supported"
            if hypothesis.status == "supported"
            else "alternative"
        )

        output.append(
            CompetingHypothesis(
                hypothesis=hypothesis.hypothesis,
                status=status,
                confidence=hypothesis.confidence,
                rationale=hypothesis.rationale,
                evidence_event_ids=hypothesis.evidence_event_ids,
            )
        )

    return tuple(output)