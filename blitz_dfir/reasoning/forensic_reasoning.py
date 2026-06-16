from __future__ import annotations

from blitz_dfir.reasoning.models import (
    ForensicPerspective,
    LLMMessage,
    LLMRequest,
)
from blitz_dfir.reasoning.provider import LLMProvider
import json


def run_forensic_reasoning(
    *,
    provider: LLMProvider,
    model: str,
    context_json: str,
) -> ForensicPerspective:

    system = (
        "You are a senior DFIR analyst. "
        "Use only supplied evidence summaries. "
        "Never assume unseen evidence. "
        "Return JSON only."
    )

    user = (
        "Generate JSON fields:\n"
        "firstness\n"
        "secondness\n"
        "thirdness\n"
        "devil_advocate\n"
        "verdict\n"
        "confidence\n"
        "\n"
        f"Context:\n{context_json}"
    )

    request = LLMRequest(
        model=model,
        messages=(
            LLMMessage(
                role="system",
                content=system,
            ),
            LLMMessage(
                role="user",
                content=user,
            ),
        ),
    )

    response = provider.complete(request)

    payload = json.loads(response.content)

    return ForensicPerspective(
        firstness=str(payload.get("firstness", "")),
        secondness=str(payload.get("secondness", "")),
        thirdness=str(payload.get("thirdness", "")),
        devil_advocate=str(payload.get("devil_advocate", "")),
        verdict=str(payload.get("verdict", "")),
        confidence=float(payload.get("confidence", 0.0)),
    )