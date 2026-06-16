from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from blitz_dfir.core.integrity import sha256_file, validate_sha256_hex
from blitz_dfir.exceptions import IntegrityError


@dataclass(frozen=True)
class ProvenanceWarning:
    severity: str
    message: str


@dataclass(frozen=True)
class ToolProvenance:
    executable: str
    resolved_path: str | None
    expected_sha256: str | None
    actual_sha256: str | None
    verified: bool
    warnings: tuple[ProvenanceWarning, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "executable": self.executable,
            "resolved_path": self.resolved_path,
            "expected_sha256": self.expected_sha256,
            "actual_sha256": self.actual_sha256,
            "verified": self.verified,
            "warnings": [warning.__dict__ for warning in self.warnings],
        }


def verify_tool_provenance(
    executable: str,
    *,
    expected_sha256: str | None,
    policy: str = "warn",
) -> ToolProvenance:
    resolved = _resolve_executable(executable)
    warnings: list[ProvenanceWarning] = []
    expected = validate_sha256_hex(expected_sha256) if expected_sha256 else None
    if resolved is None:
        warnings.append(ProvenanceWarning("HIGH", f"tool executable not found: {executable}"))
        if expected and policy == "block":
            raise IntegrityError(f"tool executable not found: {executable}")
        return ToolProvenance(executable, None, expected, None, False, tuple(warnings))

    actual = sha256_file(resolved)
    verified = expected is None or actual == expected
    if expected and actual != expected:
        warnings.append(
            ProvenanceWarning(
                "CRITICAL",
                f"tool hash mismatch for {resolved}: expected {expected}, got {actual}",
            )
        )
        if policy == "block":
            raise IntegrityError(f"tool hash mismatch for {resolved}")
    return ToolProvenance(executable, str(resolved), expected, actual, verified, tuple(warnings))


def _resolve_executable(executable: str) -> Path | None:
    path = Path(executable)
    if path.is_absolute() or path.parent != Path("."):
        return path.resolve() if path.exists() else None
    found = shutil.which(executable)
    return Path(found).resolve() if found else None

