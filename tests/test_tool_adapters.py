from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from blitz_dfir.core.integrity import hash_text
from blitz_dfir.core.manifest import load_manifest
from blitz_dfir.core.session import create_session
from blitz_dfir.exceptions import EvidenceSecurityError, ValidationError
from blitz_dfir.sandbox.runner import SandboxRequest, SandboxResult
from blitz_dfir.tools.base import BuiltCommand, SafeToolAdapter
from blitz_dfir.tools.chainsaw_tool import ChainsawAdapter
from blitz_dfir.tools.disk_triage_tool import DiskTriageAdapter
from blitz_dfir.tools.log2timeline_tool import Log2TimelineAdapter
from blitz_dfir.tools.pcap_tool import PcapAdapter
from blitz_dfir.tools.psort_tool import PsortAdapter
from blitz_dfir.tools.strings_tool import StringsAdapter
from blitz_dfir.tools.volatility_tool import VolatilityAdapter
from blitz_dfir.tools.yara_tool import YaraAdapter


def _case(tmp_path, *, filename: str, evidence_type: str):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(parents=True)
    evidence = evidence_root / filename
    evidence.write_bytes(b"evidence")
    digest = hashlib.sha256(b"evidence").hexdigest()
    manifest_path = tmp_path / "case.yaml"
    manifest_path.write_text(
        f"""
case_id: case-001
evidence_root: evidence
output_root: output
evidence:
  - id: artifact
    path: {filename}
    type: {evidence_type}
    sha256: {digest}
""".strip(),
        encoding="utf-8",
    )
    manifest = load_manifest(manifest_path)
    session = create_session(manifest)
    return manifest.evidence[0], session


def _tool_executable(tmp_path, name: str = "tool") -> tuple[Path, str]:
    path = tmp_path / name
    path.write_bytes(b"tool-binary")
    return path, hashlib.sha256(b"tool-binary").hexdigest()


def _runner(stdout: str = "output", stderr: str = "", exit_code: int = 0):
    def fake_runner(request: SandboxRequest) -> SandboxResult:
        return SandboxResult(
            command=request.command,
            cwd=request.cwd,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            stdout_hash=hash_text(stdout),
            stderr_hash=hash_text(stderr),
            timed_out=False,
        )

    return fake_runner


def _capturing_runner(seen: list[SandboxRequest], stdout: str = "output"):
    def fake_runner(request: SandboxRequest) -> SandboxResult:
        seen.append(request)
        return SandboxResult(
            command=request.command,
            cwd=request.cwd,
            exit_code=0,
            stdout=stdout,
            stderr="",
            stdout_hash=hash_text(stdout),
            stderr_hash=hash_text(""),
            timed_out=False,
        )

    return fake_runner


def test_strings_adapter_success_returns_structured_metadata(tmp_path):
    evidence, session = _case(tmp_path, filename="Security.evtx", evidence_type="EVTX")
    executable, digest = _tool_executable(tmp_path)
    adapter = StringsAdapter(executable=str(executable), expected_sha256=digest)

    result = adapter.run(session=session, evidence=evidence, runner=_runner(stdout="ioc-string"))

    assert result.tool_name == "strings"
    assert result.exit_code == 0
    assert result.args_hash
    assert result.primary_output_path.read_text(encoding="utf-8") == "ioc-string"
    assert result.output_hash == hashlib.sha256(b"ioc-string").hexdigest()
    assert result.command == (str(executable), "-a", str(evidence.path))
    assert result.provenance.verified is True
    assert result.warnings == ()


def test_failed_adapter_execution_returns_structured_failure(tmp_path):
    evidence, session = _case(tmp_path, filename="Security.evtx", evidence_type="EVTX")
    executable, _ = _tool_executable(tmp_path)
    adapter = ChainsawAdapter(executable=str(executable))

    result = adapter.run(
        session=session,
        evidence=evidence,
        runner=_runner(stdout="", stderr="bad evtx", exit_code=2),
    )

    assert result.exit_code == 2
    assert result.stderr_path.read_text(encoding="utf-8") == "bad evtx"
    assert result.timed_out is False


def test_hash_mismatch_creates_critical_warning(tmp_path):
    evidence, session = _case(tmp_path, filename="Security.evtx", evidence_type="EVTX")
    executable, _ = _tool_executable(tmp_path)
    adapter = StringsAdapter(executable=str(executable), expected_sha256="0" * 64)

    result = adapter.run(session=session, evidence=evidence, runner=_runner())

    assert result.provenance.verified is False
    assert any(warning.severity == "CRITICAL" for warning in result.warnings)


def test_output_path_escape_is_rejected_before_directory_creation(tmp_path):
    evidence, session = _case(tmp_path, filename="Security.evtx", evidence_type="EVTX")
    outside = session.session_root.parent / "escape"

    class BadAdapter(SafeToolAdapter):
        tool_name = "bad"
        executable = "bad"
        output_subdir = "../escape"
        output_suffix = ".txt"

        def build_command(self, *, session, evidence, output_dir, params):
            return BuiltCommand(command=("bad",), primary_output_path=output_dir / "bad.txt")

    with pytest.raises(EvidenceSecurityError):
        BadAdapter().run(session=session, evidence=evidence, runner=_runner())

    assert not outside.exists()


def test_volatility_plugin_allowlist_is_enforced(tmp_path):
    evidence, session = _case(tmp_path, filename="memory.raw", evidence_type="MEMORY")
    executable, _ = _tool_executable(tmp_path)
    adapter = VolatilityAdapter(executable=str(executable), allowed_plugins=frozenset({"windows.pslist"}))

    with pytest.raises(ValidationError):
        adapter.run(
            session=session,
            evidence=evidence,
            params={"plugin": "windows.malfind"},
            runner=_runner(),
        )


def test_volatility_adapter_uses_writable_symbol_dirs_option(tmp_path):
    evidence, session = _case(tmp_path, filename="memory.raw", evidence_type="MEMORY")
    executable, _ = _tool_executable(tmp_path)
    symbols_dir = tmp_path / "symbols"
    requests: list[SandboxRequest] = []
    adapter = VolatilityAdapter(
        executable=str(executable),
        allowed_plugins=frozenset({"windows.pslist"}),
        symbols_dir=symbols_dir,
    )

    result = adapter.run(
        session=session,
        evidence=evidence,
        params={"plugin": "windows.pslist"},
        runner=_capturing_runner(requests, stdout="[]"),
    )

    assert "--symbol-dirs" in result.command
    assert "--symbols-path" not in result.command
    assert result.command[result.command.index("--symbol-dirs") + 1] == str(symbols_dir)
    assert symbols_dir.exists()
    assert requests[0].stdout_output_path == result.primary_output_path
    assert result.stdout_path.name == "artifact.windows_pslist.volatility.stdout.txt"
    assert result.stderr_path.name == "artifact.windows_pslist.volatility.stderr.txt"


def test_yara_rule_allowlist_is_enforced(tmp_path):
    evidence, session = _case(tmp_path, filename="disk.dd", evidence_type="DD")
    executable, _ = _tool_executable(tmp_path)
    adapter = YaraAdapter(executable=str(executable), allowed_rules=frozenset({"rules/safe.yar"}))

    with pytest.raises(ValidationError):
        adapter.run(session=session, evidence=evidence, params={"rule": "rules/unknown.yar"}, runner=_runner())


def test_each_adapter_builds_argument_array(tmp_path):
    cases = [
        (Log2TimelineAdapter, "disk.E01", "E01", {}),
        (DiskTriageAdapter, "disk.E01", "E01", {}),
        (PsortAdapter, "timeline.plaso", "PLASO", {}),
        (VolatilityAdapter, "memory.raw", "MEMORY", {"plugin": "windows.pslist"}),
        (ChainsawAdapter, "Security.evtx", "EVTX", {}),
        (PcapAdapter, "capture.pcap", "PCAP", {}),
        (YaraAdapter, "disk.dd", "DD", {"rule": "rules/safe.yar"}),
        (StringsAdapter, "disk.dd", "DD", {}),
    ]
    executable, _ = _tool_executable(tmp_path)
    for index, (adapter_cls, filename, evidence_type, params) in enumerate(cases):
        evidence, session = _case(tmp_path / f"case-{index}", filename=filename, evidence_type=evidence_type)
        if adapter_cls is YaraAdapter:
            adapter = adapter_cls(executable=str(executable), allowed_rules=frozenset({"rules/safe.yar"}))
        else:
            adapter = adapter_cls(executable=str(executable))
        result = adapter.run(session=session, evidence=evidence, params=params, runner=_runner())

        assert isinstance(result.command, tuple)
        assert result.command[0] == str(executable)
        assert all(isinstance(part, str) for part in result.command)


def test_log2timeline_e01_runs_unattended_with_partition_and_vss_defaults(tmp_path):
    evidence, session = _case(tmp_path, filename="disk.E01", evidence_type="E01")
    executable, _ = _tool_executable(tmp_path)
    requests: list[SandboxRequest] = []
    adapter = Log2TimelineAdapter(executable=str(executable))

    result = adapter.run(session=session, evidence=evidence, runner=_capturing_runner(requests))

    assert result.command[0] == str(executable)
    assert "--logfile" in result.command
    assert result.command[result.command.index("--logfile") + 1].endswith(".log2timeline.log.gz")
    assert "--storage-file" in result.command
    assert "--partitions=all" in result.command
    assert "--vss_stores=none" in result.command
    assert "--no_vss" in result.command
    assert "--unattended" in result.command
    assert result.command[-1] == str(evidence.path)


def test_disk_triage_adapter_uses_bounded_tsk_script(tmp_path):
    evidence, session = _case(tmp_path, filename="disk.E01", evidence_type="E01")
    executable, _ = _tool_executable(tmp_path, name="python3")
    adapter = DiskTriageAdapter(executable=str(executable))

    result = adapter.run(
        session=session,
        evidence=evidence,
        params={"max_partitions": 4, "max_entries": 5000, "max_seconds_per_partition": 120},
        runner=_runner(stdout="", stderr=""),
    )

    assert result.command[0] == str(executable)
    assert result.command[1].endswith("scripts\\tsk_e01_triage.py") or result.command[1].endswith("scripts/tsk_e01_triage.py")
    assert "--evidence" in result.command
    assert result.command[result.command.index("--evidence") + 1] == str(evidence.path)
    assert "--output" in result.command
    assert result.command[result.command.index("--output") + 1] == str(result.primary_output_path)
    assert "--max-partitions" in result.command
    assert result.command[result.command.index("--max-partitions") + 1] == "4"
    assert "--max-entries" in result.command
    assert result.command[result.command.index("--max-entries") + 1] == "5000"
    assert "--max-seconds-per-partition" in result.command
    assert result.command[result.command.index("--max-seconds-per-partition") + 1] == "120"


def test_log2timeline_e01_can_opt_into_vss_store_selection(tmp_path):
    evidence, session = _case(tmp_path, filename="disk.E01", evidence_type="E01")
    executable, _ = _tool_executable(tmp_path)
    adapter = Log2TimelineAdapter(executable=str(executable))

    result = adapter.run(
        session=session,
        evidence=evidence,
        params={"vss_stores": "1..2", "partitions": "1"},
        runner=_runner(),
    )

    assert "--partitions=1" in result.command
    assert "--vss_stores=1..2" in result.command
    assert "--no_vss" not in result.command


def test_log2timeline_accepts_targeted_parser_profile(tmp_path):
    evidence, session = _case(tmp_path, filename="disk.E01", evidence_type="E01")
    executable, _ = _tool_executable(tmp_path)
    adapter = Log2TimelineAdapter(executable=str(executable))

    result = adapter.run(
        session=session,
        evidence=evidence,
        params={"parsers": "winevtx,prefetch,winreg/amcache"},
        runner=_runner(),
    )

    assert "--parsers" in result.command
    assert result.command[result.command.index("--parsers") + 1] == "winevtx,prefetch,winreg/amcache"


def test_psort_defaults_to_dynamic_triage_profile_and_configurable_timeout(tmp_path):
    evidence, session = _case(tmp_path, filename="timeline.plaso", evidence_type="PLASO")
    executable, _ = _tool_executable(tmp_path)
    requests: list[SandboxRequest] = []
    adapter = PsortAdapter(executable=str(executable), default_timeout_seconds=900)

    result = adapter.run(session=session, evidence=evidence, runner=_capturing_runner(requests))

    assert result.command[:5] == (str(executable), "-q", "-o", "dynamic", "-w")
    assert "--fields" in result.command
    assert "--additional_fields" in result.command
    assert "data_type" in result.command
    assert result.command[-1].startswith("(")
    assert "data_type contains 'windows:evtx'" in result.command[-1]
    assert "LIMIT" not in result.command[-1]
    assert requests[0].limits.timeout_seconds == 900


def test_psort_full_profile_can_override_timeout(tmp_path):
    evidence, session = _case(tmp_path, filename="timeline.plaso", evidence_type="PLASO")
    executable, _ = _tool_executable(tmp_path)
    requests: list[SandboxRequest] = []
    adapter = PsortAdapter(executable=str(executable), default_timeout_seconds=900)

    result = adapter.run(
        session=session,
        evidence=evidence,
        params={"profile": "full", "timeout_seconds": 1800},
        runner=_capturing_runner(requests),
    )

    assert result.command[-1] == str(evidence.path)
    assert "data_type contains" not in " ".join(result.command)
    assert requests[0].limits.timeout_seconds == 1800


def test_psort_slice_uses_slice_size_without_slicer_flag(tmp_path):
    evidence, session = _case(tmp_path, filename="timeline.plaso", evidence_type="PLASO")
    executable, _ = _tool_executable(tmp_path)
    adapter = PsortAdapter(executable=str(executable), default_timeout_seconds=900)

    result = adapter.run(
        session=session,
        evidence=evidence,
        params={"profile": "full", "slice": "2026-05-20 07:10:00", "slice_size": 60},
        runner=_runner(),
    )

    assert "--slice" in result.command
    assert "2026-05-20 07:10:00" in result.command
    assert "--slice_size" in result.command
    assert "60" in result.command
    assert "--slicer" not in result.command
