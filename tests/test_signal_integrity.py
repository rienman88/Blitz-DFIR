from __future__ import annotations

from pathlib import Path

import pytest

from blitz_dfir.core.integrity import hash_text
from blitz_dfir.signal.coverage import (
    MVP_ARTIFACT_TYPES,
    build_coverage_report,
    coverage_report_from_expected_artifacts,
    memory_region_coverage,
    timeline_source_coverage,
)
from blitz_dfir.signal.integrity import (
    confidence_penalty_from_warnings,
    decode_with_signal,
    event_density_warning,
    parser_exit_warning,
    retry_limit_warning,
    summarize_signal_integrity,
    truncation_warning,
)
from blitz_dfir.signal.warnings import (
    abnormal_event_density_warning,
    encoding_corruption_warning,
    event_truncation_warning,
    hash_mismatch_warning,
    missing_artifact_warning,
    parser_crash_warning,
    parser_degradation_warning,
    partial_extraction_warning,
    retry_exhaustion_warning,
    tool_timeout_warning,
)
from blitz_dfir.tools.base import ToolAdapterResult, ToolWarning
from blitz_dfir.tools.provenance import ToolProvenance


def test_required_signal_warnings_are_structured_with_confidence_penalties():
    warnings = [
        tool_timeout_warning(artifact="memory.raw", tool="volatility", timeout_seconds=300),
        event_truncation_warning(
            artifact="Timeline",
            processed_events=5000,
            estimated_total=7200,
            tool="psort",
        ),
        parser_degradation_warning(artifact="Security.evtx", parser="evtx", reason="malformed row"),
        encoding_corruption_warning(artifact="Security.evtx", source="evtx", errors=2),
        missing_artifact_warning(artifact="Timeline", missing_source="Registry"),
        partial_extraction_warning(artifact="Memory", processed=2, expected=4, source="volatility"),
        hash_mismatch_warning(
            artifact="tshark",
            expected="0" * 64,
            actual="1" * 64,
            tool="tshark",
        ),
        retry_exhaustion_warning(artifact="Timeline", attempts=2),
        parser_crash_warning(artifact="capture.pcap", parser="tshark-json", exit_code=1),
        abnormal_event_density_warning(artifact="EVTX", observed=3, expected_minimum=100),
    ]

    assert {warning.warning_type for warning in warnings} == {
        "TOOL_TIMEOUT",
        "EVENT_TRUNCATION",
        "PARSER_DEGRADATION",
        "ENCODING_CORRUPTION",
        "MISSING_ARTIFACT",
        "PARTIAL_EXTRACTION",
        "HASH_MISMATCH",
        "RETRY_EXHAUSTION",
        "PARSER_CRASH",
        "ABNORMAL_EVENT_DENSITY",
    }
    assert all(warning.artifact for warning in warnings)
    assert all(warning.impact for warning in warnings)
    assert all(warning.confidence_penalty > 0 for warning in warnings)


def test_partial_memory_extraction_creates_analysis_gap_and_reduces_coverage():
    coverage = memory_region_coverage(processed_regions=2, total_regions=4)
    report = build_coverage_report([coverage])
    signal = summarize_signal_integrity(coverage_report=report)

    assert coverage.coverage == 0.5
    assert any(gap.source == "Memory" for gap in coverage.analysis_gaps)
    assert signal.analysis_gaps == report.analysis_gaps
    assert signal.confidence_penalty > 0


def test_event_cap_creates_truncation_warning():
    warning = truncation_warning(artifact="Timeline", processed=5000, total=6000, tool="psort")

    assert warning.warning_type == "EVENT_TRUNCATION"
    assert warning.tool == "psort"
    assert warning.confidence_penalty > 0


def test_missing_source_in_plaso_reduces_timeline_coverage():
    coverage = timeline_source_coverage(
        artifact="Timeline",
        present_sources={"EVTX"},
        expected_sources={"EVTX", "Registry", "Prefetch"},
    )

    assert coverage.coverage == pytest.approx(1 / 3)
    assert coverage.missing_sources == ("Prefetch", "Registry")
    assert any(warning.warning_type == "MISSING_ARTIFACT" for warning in coverage.warnings)


def test_timeout_warning_reduces_confidence():
    warning = tool_timeout_warning(artifact="memory.raw", tool="volatility", timeout_seconds=300)

    assert confidence_penalty_from_warnings([warning]) == pytest.approx(warning.confidence_penalty)


def test_encoding_corruption_creates_warning_object():
    decoded, warnings = decode_with_signal(b"valid-prefix\xffbad", artifact="EVTX", source="parser")

    assert "\ufffd" in decoded
    assert warnings[0].warning_type == "ENCODING_CORRUPTION"
    assert warnings[0].confidence_penalty > 0


def test_no_signal_degradation_is_silently_dropped():
    warnings = [
        parser_degradation_warning(artifact="EVTX", parser="evtx", reason="invalid timestamp"),
        retry_limit_warning(artifact="Timeline", attempts=2, max_attempts=2),
        parser_exit_warning(artifact="Memory", parser="volatility-json", exit_code=2),
        event_density_warning(artifact="PCAP", observed=1, expected_minimum=10),
    ]
    present = [warning for warning in warnings if warning is not None]
    signal = summarize_signal_integrity(extra_warnings=present)

    assert {warning.warning_type for warning in signal.warnings} == {
        "PARSER_DEGRADATION",
        "RETRY_EXHAUSTION",
        "PARSER_CRASH",
        "ABNORMAL_EVENT_DENSITY",
    }
    assert signal.high_count == 2
    assert signal.critical_count == 1
    assert signal.confidence_penalty > 0


def test_mvp_artifact_coverage_tracks_required_artifact_types():
    report = coverage_report_from_expected_artifacts(
        observed_counts={"EVTX": 10, "Registry": 1, "Memory": 2, "Timeline": 50, "PCAP": 4},
        expected_counts={"EVTX": 10, "Registry": 1, "Memory": 2, "Timeline": 100, "PCAP": 4},
    )

    assert tuple(report.per_artifact) == MVP_ARTIFACT_TYPES
    assert report.per_artifact["Timeline"].coverage == 0.5
    assert report.per_artifact["Browser Artifacts"].coverage == 0.0
    assert any(gap.source == "Browser Artifacts" for gap in report.analysis_gaps)
    assert report.overall_case_coverage < 1.0


def test_tool_result_timeout_and_hash_mismatch_feed_signal_report(tmp_path):
    tool_result = ToolAdapterResult(
        tool_name="tshark",
        evidence_id="capture",
        command=("tshark", "-r", "capture.pcap"),
        cwd=tmp_path,
        primary_output_path=tmp_path / "capture.json",
        stdout_path=tmp_path / "stdout.txt",
        stderr_path=tmp_path / "stderr.txt",
        tool_version="test",
        args_hash=hash_text("args"),
        output_hash=None,
        stdout_hash=hash_text("stdout"),
        stderr_hash=hash_text("stderr"),
        exit_code=124,
        duration_ms=300000,
        timed_out=True,
        warnings=(
            ToolWarning("TOOL_PROVENANCE", "CRITICAL", "tool hash mismatch"),
            ToolWarning("TOOL_TIMEOUT", "HIGH", "timeout"),
        ),
        provenance=ToolProvenance(
            executable="tshark",
            resolved_path=str(Path(tmp_path) / "tshark"),
            expected_sha256="0" * 64,
            actual_sha256="1" * 64,
            verified=False,
            warnings=(),
        ),
    )

    signal = summarize_signal_integrity(tool_results=[tool_result])
    warning_types = [warning.warning_type for warning in signal.warnings]

    assert warning_types.count("TOOL_TIMEOUT") == 1
    assert "HASH_MISMATCH" in warning_types
    assert signal.confidence_penalty >= 0.55
