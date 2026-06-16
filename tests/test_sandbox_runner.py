from __future__ import annotations

import sys

import pytest

from blitz_dfir.exceptions import EvidenceSecurityError, ValidationError
from blitz_dfir.sandbox.limits import ResourceLimits
from blitz_dfir.sandbox.runner import SandboxRequest, run_subprocess


def test_sandbox_runner_uses_argument_list_and_streamed_stdout(tmp_path):
    result = run_subprocess(
        SandboxRequest(
            command=(sys.executable, "-c", "print('ok')"),
            cwd=tmp_path,
        )
    )

    assert result.stdout.strip() == "ok"
    assert result.exit_code == 0
    assert list(tmp_path.glob(".blitz-stdout-*")) == []
    assert list(tmp_path.glob(".blitz-stderr-*")) == []


def test_sandbox_runner_keeps_shell_metacharacters_as_arguments(tmp_path):
    result = run_subprocess(
        SandboxRequest(
            command=(sys.executable, "-c", "import sys; print(sys.argv[1])", "evil;rm -rf /"),
            cwd=tmp_path,
        )
    )

    assert result.stdout.strip() == "evil;rm -rf /"


def test_sandbox_runner_returns_bounded_failure_result(tmp_path):
    result = run_subprocess(
        SandboxRequest(
            command=(
                sys.executable,
                "-c",
                "import sys; sys.stdout.write('stdout'); sys.stderr.write('stderr'); sys.exit(2)",
            ),
            cwd=tmp_path,
        )
    )

    assert result.exit_code == 2
    assert result.stdout == "stdout"
    assert result.stderr == "stderr"


def test_sandbox_runner_rejects_string_command(tmp_path):
    with pytest.raises(ValidationError):
        run_subprocess(SandboxRequest(command="tool --flag", cwd=tmp_path))  # type: ignore[arg-type]


def test_sandbox_runner_handles_timeout(tmp_path):
    result = run_subprocess(
        SandboxRequest(
            command=(sys.executable, "-c", "import time; time.sleep(2)"),
            cwd=tmp_path,
            limits=ResourceLimits(timeout_seconds=1),
        )
    )

    assert result.timed_out is True
    assert result.exit_code == 124


def test_sandbox_runner_preserves_full_stdout_file_while_returning_bounded_capture(tmp_path):
    output_path = tmp_path / "full-output.json"

    result = run_subprocess(
        SandboxRequest(
            command=(sys.executable, "-c", "import sys; sys.stdout.write('x' * 64)"),
            cwd=tmp_path,
            limits=ResourceLimits(timeout_seconds=5, max_captured_output_bytes=10),
            stdout_output_path=output_path,
        )
    )

    assert result.exit_code == 0
    assert result.stdout == "x" * 10
    assert result.stdout_truncated is True
    assert output_path.read_text(encoding="utf-8") == "x" * 64


def test_sandbox_runner_rejects_preserved_stdout_path_escape(tmp_path):
    with pytest.raises(EvidenceSecurityError):
        run_subprocess(
            SandboxRequest(
                command=(sys.executable, "-c", "print('no escape')"),
                cwd=tmp_path,
                stdout_output_path=tmp_path.parent / "escaped.txt",
            )
        )
