from __future__ import annotations

from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError as PydanticValidationError

from blitz_dfir.core.models import SignalWarning

ModelT = TypeVar("ModelT", bound=BaseModel)


def enforce_schema(
    model: type[ModelT],
    payload: dict[str, Any],
    *,
    artifact: str,
) -> tuple[ModelT | None, tuple[SignalWarning, ...]]:
    try:
        return model.model_validate(payload), ()
    except PydanticValidationError as exc:
        return (
            None,
            (
                SignalWarning(
                    warning_type="SCHEMA_VALIDATION_FAILED",
                    severity="HIGH",
                    artifact=artifact,
                    impact="record failed strict schema validation",
                    metadata={"errors": exc.errors(include_url=False)},
                ),
            ),
        )

