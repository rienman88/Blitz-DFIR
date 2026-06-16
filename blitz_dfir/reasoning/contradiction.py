from __future__ import annotations

from blitz_dfir.reasoning.analyst import ReasoningContext


def contradiction_notes_from_payload(
    value: object,
    *,
    context: ReasoningContext,
) -> tuple[str, ...]:
    deterministic_ids = {
        str(item.get("contradiction_id"))
        for item in context.contradictions
        if isinstance(item, dict) and item.get("contradiction_id")
    }
    notes: list[str] = []
    if isinstance(value, list | tuple):
        candidates = value
    elif isinstance(value, str) and value.strip():
        candidates = (value,)
    else:
        candidates = ()
    for item in candidates:
        text = _bounded(item)
        if not text:
            continue
        if deterministic_ids and not any(identifier in text for identifier in deterministic_ids):
            text = f"Within deterministic contradiction set: {text}"
        notes.append(text)

    if not notes:
        for contradiction in context.contradictions:
            notes.append(
                _bounded(
                    f"{contradiction['contradiction_id']}: field {contradiction['field']} "
                    f"has cross-source disagreement."
                )
            )
    return tuple(notes)


def _bounded(value: object, limit: int = 240) -> str:
    text = "" if value is None else str(value)
    return " ".join(text.split())[:limit]

