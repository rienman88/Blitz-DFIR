from __future__ import annotations

import time
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from blitz_dfir.core.evidence import _is_relative_to
from blitz_dfir.core.integrity import hash_text, sha256_file
from blitz_dfir.core.models import EvidenceRecord, EvidenceType
from blitz_dfir.core.session import CaseSession
from blitz_dfir.exceptions import EvidenceSecurityError, ValidationError
from blitz_dfir.sandbox.limits import MAX_CAPTURED_OUTPUT_BYTES, TOOL_TIMEOUT_SECONDS, ResourceLimits
from blitz_dfir.sandbox.runner import SandboxRequest, SandboxResult, run_subprocess
from blitz_dfir.tools.provenance import ToolProvenance, verify_tool_provenance

Runner = Callable[[SandboxRequest], SandboxResult]


@dataclass(frozen=True)
class ToolWarning:
    warning_type: str
    severity: str
    message: str


@dataclass(frozen=True)
class ToolAdapterResult:
    tool_name: str
    evidence_id: str
    command: tuple[str, ...]
    cwd: Path
    primary_output_path: Path
    stdout_path: Path
    stderr_path: Path
    tool_version: str | None
    args_hash: str
    output_hash: str | None
    stdout_hash: str
    stderr_hash: str
    exit_code: int
    duration_ms: int
    timed_out: bool
    warnings: tuple[ToolWarning, ...]
    provenance: ToolProvenance

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "evidence_id": self.evidence_id,
            "command": list(self.command),
            "cwd": str(self.cwd),
            "primary_output_path": str(self.primary_output_path),
            "stdout_path": str(self.stdout_path),
            "stderr_path": str(self.stderr_path),
            "tool_version": self.tool_version,
            "args_hash": self.args_hash,
            "output_hash": self.output_hash,
            "stdout_hash": self.stdout_hash,
            "stderr_hash": self.stderr_hash,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "timed_out": self.timed_out,
            "warnings": [warning.__dict__ for warning in self.warnings],
            "provenance": self.provenance.as_dict(),
        }


@dataclass(frozen=True)
class BuiltCommand:
    command: tuple[str, ...]
    primary_output_path: Path


class SafeToolAdapter:
    tool_name: str
    executable: str
    output_subdir: str
    output_suffix: str
    allowed_evidence_types: frozenset[EvidenceType] | None = None
    stdout_is_primary_output: bool = False

    def __init__(
        self,
        *,
        executable: str | None = None,
        expected_sha256: str | None = None,
        integrity_policy: str = "warn",
        tool_version: str | None = None,
        default_timeout_seconds: int | None = None,
    ) -> None:
        if executable:
            self.executable = executable
        self.expected_sha256 = expected_sha256
        self.integrity_policy = integrity_policy
        self.tool_version = tool_version
        self.default_timeout_seconds = default_timeout_seconds

    def run(
        self,
        *,
        session: CaseSession,
        evidence: EvidenceRecord,
        params: dict[str, Any] | None = None,
        runner: Runner = run_subprocess,
    ) -> ToolAdapterResult:
        params = params or {}
        self._validate_evidence(evidence)
        output_dir = self._output_dir(session)
        built = self.build_command(session=session, evidence=evidence, output_dir=output_dir, params=params)
        self._assert_output_path_allowed(session, built.primary_output_path)
        provenance = verify_tool_provenance(
            self.executable,
            expected_sha256=self.expected_sha256,
            policy=self.integrity_policy,
        )
        warnings = tuple(
            ToolWarning("TOOL_PROVENANCE", warning.severity, warning.message)
            for warning in provenance.warnings
        )

        stdio_stem = ensure_relative_name(built.primary_output_path.stem, field="stdio_stem")
        stdout_path = output_dir / f"{stdio_stem}.{self.tool_name}.stdout.txt"
        stderr_path = output_dir / f"{stdio_stem}.{self.tool_name}.stderr.txt"

        started = time.perf_counter()
        limits = resource_limits_from_params(
            params,
            default_timeout_seconds=self.default_timeout_seconds,
        )
        sandbox_result = runner(
            SandboxRequest(
                command=built.command,
                cwd=session.session_root,
                limits=limits,
                stdout_output_path=built.primary_output_path if self.stdout_is_primary_output else None,
            )
        )
        duration_ms = int((time.perf_counter() - started) * 1000)

        stdout_path.write_text(sandbox_result.stdout, encoding="utf-8")
        stderr_path.write_text(sandbox_result.stderr, encoding="utf-8")
        if self.stdout_is_primary_output and not built.primary_output_path.exists():
            built.primary_output_path.write_text(sandbox_result.stdout, encoding="utf-8")
        output_hash = sha256_file(built.primary_output_path) if built.primary_output_path.exists() else None
        if sandbox_result.timed_out:
            warnings += (
                ToolWarning(
                    "TOOL_TIMEOUT",
                    "HIGH",
                    f"{self.tool_name} exceeded timeout and returned partial output",
                ),
            )

        return ToolAdapterResult(
            tool_name=self.tool_name,
            evidence_id=evidence.evidence_id,
            command=built.command,
            cwd=session.session_root,
            primary_output_path=built.primary_output_path,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            tool_version=self.tool_version,
            args_hash=hash_text(json.dumps(list(built.command), separators=(",", ":"), ensure_ascii=True)),
            output_hash=output_hash,
            stdout_hash=sandbox_result.stdout_hash,
            stderr_hash=sandbox_result.stderr_hash,
            exit_code=sandbox_result.exit_code,
            duration_ms=duration_ms,
            timed_out=sandbox_result.timed_out,
            warnings=warnings,
            provenance=provenance,
        )

    def build_command(
        self,
        *,
        session: CaseSession,
        evidence: EvidenceRecord,
        output_dir: Path,
        params: dict[str, Any],
    ) -> BuiltCommand:
        output_path = output_dir / f"{evidence.evidence_id}{self.output_suffix}"
        return BuiltCommand(
            command=(self.executable, str(evidence.path), str(output_path)),
            primary_output_path=output_path,
        )

    def _validate_evidence(self, evidence: EvidenceRecord) -> None:
        if self.allowed_evidence_types is None:
            return
        if evidence.evidence_type not in self.allowed_evidence_types:
            raise ValidationError(
                f"{self.tool_name} does not accept evidence type {evidence.evidence_type.value}"
            )

    def _output_dir(self, session: CaseSession) -> Path:
        output_dir = (session.session_root / self.output_subdir).resolve()
        self._assert_output_path_allowed(session, output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir

    def _assert_output_path_allowed(self, session: CaseSession, path: Path) -> None:
        resolved = path.resolve()
        if not _is_relative_to(resolved, session.session_root.resolve()):
            raise EvidenceSecurityError(f"tool output path escapes session root: {resolved}")
        if path.exists() and path.is_dir():
            return


def require_string_param(params: dict[str, Any], key: str) -> str:
    value = params.get(key)
    if not isinstance(value, str) or not value:
        raise ValidationError(f"missing required string parameter: {key}")
    return value


def optional_string_param(params: dict[str, Any], key: str) -> str | None:
    value = params.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValidationError(f"invalid string parameter: {key}")
    return value


def optional_int_param(
    params: dict[str, Any],
    key: str,
    *,
    minimum: int,
    maximum: int,
) -> int | None:
    value = params.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"invalid integer parameter: {key}")
    if value < minimum or value > maximum:
        raise ValidationError(f"{key} must be between {minimum} and {maximum}")
    return value


def resource_limits_from_params(
    params: dict[str, Any],
    *,
    default_timeout_seconds: int | None = None,
) -> ResourceLimits:
    timeout_seconds = optional_int_param(
        params,
        "timeout_seconds",
        minimum=1,
        maximum=7200,
    )
    return ResourceLimits(
        timeout_seconds=timeout_seconds or default_timeout_seconds or TOOL_TIMEOUT_SECONDS,
        max_captured_output_bytes=MAX_CAPTURED_OUTPUT_BYTES,
    )


def ensure_relative_name(value: str, *, field: str) -> str:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise EvidenceSecurityError(f"{field} must be a relative safe name")
    return value
