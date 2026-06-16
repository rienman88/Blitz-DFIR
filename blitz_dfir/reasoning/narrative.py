from __future__ import annotations

import re

from blitz_dfir.reasoning.models import Hypothesis

FORBIDDEN_LANGUAGE_RE = re.compile(
    r"\b(confirmed beyond doubt|definitively malicious|i saw everything|tool output proves|certain|guaranteed)\b",
    re.I,
)
TOOL_REQUEST_RE = re.compile(
    r"\b(execute_shell_cmd|subprocess|bash\s+-c|run\s+command|delete\s+evidence|"
    r"run\s+(?:powershell|cmd\.exe|bash)|execute\s+(?:powershell|cmd\.exe|bash))\b",
    re.I,
)


def build_narrative(
    *,
    findings: tuple[dict[str, object], ...],
    hypotheses: tuple[Hypothesis, ...],
    contradictions: tuple[str, ...],
    model_narrative: str = "",
) -> str:
    best_confidence = _best_confidence(findings, hypotheses)
    phrase = confidence_phrase(best_confidence)
    lines = [f"{phrase} based on the bounded correlated evidence set."]
    if findings:
        lines.append(f"{len(findings)} structured finding candidate(s) have evidence anchors.")
    supported = [hypothesis for hypothesis in hypotheses if hypothesis.status == "supported"]
    unsupported = [hypothesis for hypothesis in hypotheses if hypothesis.status == "unsupported"]
    if supported:
        lines.append(f"{len(supported)} INFERRED hypothesis/hypotheses are evidence-supported.")
    if unsupported:
        lines.append(f"{len(unsupported)} INFERRED hypothesis/hypotheses are unsupported and downgraded.")
    if contradictions:
        lines.append(f"{len(contradictions)} contradiction note(s) remain inside deterministic evidence bounds.")
    if model_narrative:
        lines.append(scrub_forbidden_language(model_narrative))
    return scrub_forbidden_language(" ".join(lines))


def confidence_phrase(confidence: float) -> str:
    if confidence >= 0.80:
        return "Evidence strongly supports"
    if confidence >= 0.65:
        return "High-confidence reconstruction suggests"
    return "Coverage gaps documented; low-confidence reconstruction suggests"


def scrub_forbidden_language(value: str) -> str:
    text = FORBIDDEN_LANGUAGE_RE.sub("evidence does not fully establish", value)
    return TOOL_REQUEST_RE.sub("[blocked tool request]", text)


def _best_confidence(findings: tuple[dict[str, object], ...], hypotheses: tuple[Hypothesis, ...]) -> float:
    values: list[float] = []
    for finding in findings:
        value = finding.get("confidence", 0.0)
        try:
            values.append(float(str(value)))
        except (TypeError, ValueError):
            pass
    values.extend(hypothesis.confidence for hypothesis in hypotheses)
    return max(values) if values else 0.0
