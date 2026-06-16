from __future__ import annotations

from dataclasses import dataclass

TOOL_TIMEOUT_SECONDS = 300
MAX_CAPTURED_OUTPUT_BYTES = 1024 * 1024


@dataclass(frozen=True)
class ResourceLimits:
    timeout_seconds: int = TOOL_TIMEOUT_SECONDS
    max_captured_output_bytes: int = MAX_CAPTURED_OUTPUT_BYTES

    def validate(self) -> None:
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_captured_output_bytes <= 0:
            raise ValueError("max_captured_output_bytes must be positive")

