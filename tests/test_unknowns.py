from __future__ import annotations

from blitz_dfir.accounting.models import AccountingArtifact, FullAccountingSummary
from blitz_dfir.signal.integrity import summarize_signal_integrity
from blitz_dfir.signal.warnings import event_truncation_warning, tool_timeout_warning
from blitz_dfir.unknowns.engine import build_unknowns_report


def test_unknowns_report_labels_partial_and_truncated_outputs():
    signal = summarize_signal_integrity(
        extra_warnings=[
            tool_timeout_warning(artifact="rd01-plaso", tool="psort", timeout_seconds=1800),
            event_truncation_warning(
                artifact="rd01-plaso",
                processed_events=5000,
                estimated_total=431644,
                tool="psort",
            ),
        ]
    )
    accounting = FullAccountingSummary(
        event_store_path="findings/event_store.sqlite",
        artifact_count=1,
        total_rows=431644,
        artifacts=(
            AccountingArtifact(
                artifact_id="rd01-plaso-psort-1",
                evidence_id="rd01-plaso",
                source_tool="psort",
                parser="plaso",
                source_path="timelines/rd01-plaso.csv",
                source_size_bytes=478856146,
                row_count=431644,
                malformed_count=0,
                partial=True,
                timed_out=True,
                table_name="event_rows",
            ),
        ),
    )

    report = build_unknowns_report(signal_report=signal, full_accounting=accounting)

    assert report.unknown_count >= 3
    assert any(record.status == "NEEDS_REVIEW" for record in report.records)
    assert any(record.category == "partial_accounting_artifact" for record in report.records)
