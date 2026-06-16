from __future__ import annotations

import subprocess
import tempfile
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from blitz_dfir.core.integrity import hash_text
from blitz_dfir.exceptions import EvidenceSecurityError, ValidationError
from blitz_dfir.sandbox.limits import ResourceLimits


@dataclass(frozen=True)
class SandboxRequest:
    command: tuple[str, ...]
    cwd: Path
    limits: ResourceLimits = ResourceLimits()
    env: Mapping[str, str] | None = None
    stdout_output_path: Path | None = None


@dataclass(frozen=True)
class SandboxResult:
    command: tuple[str, ...]
    cwd: Path
    exit_code: int
    stdout: str
    stderr: str
    stdout_hash: str
    stderr_hash: str
    timed_out: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False


def run_subprocess(request: SandboxRequest) -> SandboxResult:
    request.limits.validate()
    _validate_command(request.command)
    cwd = request.cwd.resolve()
    if not cwd.exists() or not cwd.is_dir():
        raise EvidenceSecurityError(f"sandbox working directory does not exist: {cwd}")

    stdout_path: Path | None = None
    stderr_path: Path | None = None
    timed_out = False
    exit_code = 1
    try:
        with tempfile.NamedTemporaryFile(prefix=".blitz-stdout-", dir=cwd, delete=False) as stdout_file:
            stdout_path = Path(stdout_file.name)
            with tempfile.NamedTemporaryFile(prefix=".blitz-stderr-", dir=cwd, delete=False) as stderr_file:
                stderr_path = Path(stderr_file.name)
                process = subprocess.Popen(
                    list(request.command),
                    stdout=stdout_file,
                    stderr=stderr_file,
                    cwd=str(cwd),
                    env=dict(request.env) if request.env is not None else None,
                    shell=False,
                    text=False,
                )
                try:
                    exit_code = process.wait(timeout=request.limits.timeout_seconds)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    process.kill()
                    exit_code = 124
                    process.wait(timeout=10)

        stdout = _read_bounded_file(stdout_path, request.limits.max_captured_output_bytes)
        stderr = _read_bounded_file(stderr_path, request.limits.max_captured_output_bytes)
        if request.stdout_output_path is not None:
            _copy_output_file(stdout_path, request.stdout_output_path, cwd=cwd)
        return SandboxResult(
            command=request.command,
            cwd=cwd,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            stdout_hash=hash_text(stdout),
            stderr_hash=hash_text(stderr),
            timed_out=timed_out,
            stdout_truncated=_file_exceeds(stdout_path, request.limits.max_captured_output_bytes),
            stderr_truncated=_file_exceeds(stderr_path, request.limits.max_captured_output_bytes),
        )
    finally:
        _unlink_if_exists(stdout_path)
        _unlink_if_exists(stderr_path)


def _validate_command(command: Sequence[str]) -> None:
    if not command:
        raise ValidationError("sandbox command cannot be empty")
    if isinstance(command, str):
        raise ValidationError("sandbox command must be an argument sequence, not a string")
    for part in command:
        if not isinstance(part, str) or not part:
            raise ValidationError("sandbox command arguments must be non-empty strings")


def _bound_output(value: str, max_bytes: int) -> str:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return value
    return encoded[:max_bytes].decode("utf-8", errors="replace")


def _read_bounded_file(path: Path, max_bytes: int) -> str:
    with path.open("rb") as handle:
        data = handle.read(max_bytes + 1)
    return _bound_output(data.decode("utf-8", errors="replace"), max_bytes)


def _file_exceeds(path: Path, max_bytes: int) -> bool:
    return path.stat().st_size > max_bytes


def _copy_output_file(source: Path, destination: Path, *, cwd: Path) -> None:
    resolved = destination.resolve()
    if not _is_relative_to(resolved, cwd):
        raise EvidenceSecurityError(f"sandbox stdout output path escapes working directory: {resolved}")
    resolved.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, resolved)


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _unlink_if_exists(path: Path | None) -> None:
    if path is None:
        return
    try:
        path.unlink()
    except FileNotFoundError:
        return
