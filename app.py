from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="blitz-dfir")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="Start a bounded DFIR analysis session.")
    analyze.add_argument("--manifest", required=True, help="Path to case manifest YAML.")
    analyze.add_argument(
        "--case-objective",
        default=None,
        help=(
            "Evidence-first investigation objective. The objective guides planning but cannot create findings."
        ),
    )
    analyze.add_argument("--mode", default="timeline", choices=["timeline"], help="Analysis mode.")
    analyze.add_argument(
        "--tool-config",
        default="config/tools.yaml",
        help="Path to Blitz tool configuration YAML.",
    )
    analyze.add_argument(
        "--enable-reasoning",
        action="store_true",
        help="Run bounded LLM reasoning over validated normalized summaries only.",
    )
    analyze.add_argument(
        "--psort-profile",
        default="triage",
        choices=["triage", "full"],
        help="PLASO export profile. triage uses bounded high-signal filters; full exports every event.",
    )
    analyze.add_argument(
        "--tool-timeout",
        type=int,
        default=None,
        help="Optional per-tool timeout in seconds, capped at 7200 by typed tool validation.",
    )
    analyze.add_argument(
        "--psort-filter",
        default=None,
        help="Optional Plaso event filter expression for focused timeline export.",
    )
    analyze.add_argument(
        "--psort-slice",
        default=None,
        help="Optional psort --slice timestamp. Use with --psort-slice-size for surrounding context.",
    )
    analyze.add_argument(
        "--psort-slice-size",
        type=int,
        default=None,
        help="Optional psort --slice_size in minutes, defaulting to psort adapter policy when omitted.",
    )
    analyze.add_argument(
        "--windows-artifact-profile",
        default=None,
        choices=["none", "windows-light"],
        help=(
            "Optional Windows artifact profile. windows-light targets EVTX, Prefetch, Amcache, LNK, "
            "SetupAPI, USBStor, BAM, Windows Timeline, and SRUM without enabling MFT/USNJrnl by default."
        ),
    )
    analyze.add_argument(
        "--max-normalized-events",
        type=int,
        default=None,
        help=(
            "Optional normalized/report event cap for stress testing. "
            "Default is 5000; maximum is 5000000. Full accounting still preserves all exported rows."
        ),
    )
    analyze.add_argument(
        "--max-analysis-events",
        type=int,
        default=None,
        help=(
            "Optional cap for downstream correlation/validation/report analysis. "
            "Full accounting and normalized output remain controlled separately."
        ),
    )
    analyze.add_argument(
        "--report-event-limit",
        type=int,
        default=None,
        help="Optional cap for timeline/confirmed-evidence rows embedded in JSON/Markdown/HTML reports.",
    )
    analyze.add_argument(
        "--report-finding-limit",
        type=int,
        default=None,
        help="Optional cap for findings embedded in JSON/Markdown/HTML reports.",
    )
    analyze.add_argument(
        "--normalized-export-limit",
        type=int,
        default=None,
        help=(
            "Cap for records written to findings/normalized_events.json. "
            "Default is 10000; use 0 for summary-only."
        ),
    )
    analyze.add_argument(
        "--parser-record-export-limit",
        type=int,
        default=None,
        help=(
            "Cap for records written to findings/parser_results.json. "
            "Default is 1000 per parser result; use 0 for summary-only."
        ),
    )
    analyze.add_argument(
        "--resume-session",
        default=None,
        help=(
            "Existing Blitz session directory to resume from. "
            "Reuses prior typed tool outputs and reruns downstream normalization/report phases."
        ),
    )
    analyze.add_argument(
        "--full-sql-correlation",
        action="store_true",
        help=(
            "Run full-dataset SQLite-backed correlation over normalized_events. "
            "Reports remain bounded, but SQL scans the full normalized store."
        ),
    )

    mcp_serve = subparsers.add_parser(
        "mcp-serve",
        help="Run the Blitz typed MCP stdio server for Protocol SIFT or Claude Code.",
    )
    mcp_serve.add_argument("--manifest", required=True, help="Path to case manifest YAML.")
    mcp_serve.add_argument(
        "--tool-config",
        default="config/tools.yaml",
        help="Path to Blitz tool configuration YAML.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "analyze":
        if args.max_normalized_events is not None:
            if args.max_normalized_events < 1 or args.max_normalized_events > 5_000_000:
                raise ValueError("--max-normalized-events must be between 1 and 5000000")
            os.environ["BLITZ_MAX_EVENTS"] = str(args.max_normalized_events)
            from blitz_dfir.sanitization.sanitizer import configure_max_events

            configure_max_events(args.max_normalized_events)
        if args.max_analysis_events is not None:
            if args.max_analysis_events < 1 or args.max_analysis_events > 2_000_000:
                raise ValueError("--max-analysis-events must be between 1 and 2000000")
            os.environ["BLITZ_ANALYSIS_EVENT_LIMIT"] = str(args.max_analysis_events)
        if args.report_event_limit is not None:
            if args.report_event_limit < 0 or args.report_event_limit > 2_000_000:
                raise ValueError("--report-event-limit must be between 0 and 2000000")
            os.environ["BLITZ_REPORT_EVENT_LIMIT"] = str(args.report_event_limit)
        if args.report_finding_limit is not None:
            if args.report_finding_limit < 0 or args.report_finding_limit > 2_000_000:
                raise ValueError("--report-finding-limit must be between 0 and 2000000")
            os.environ["BLITZ_REPORT_FINDING_LIMIT"] = str(args.report_finding_limit)
        if args.normalized_export_limit is not None:
            if args.normalized_export_limit < 0 or args.normalized_export_limit > 2_000_000:
                raise ValueError("--normalized-export-limit must be between 0 and 2000000")
            os.environ["BLITZ_NORMALIZED_EXPORT_LIMIT"] = str(args.normalized_export_limit)
        if args.parser_record_export_limit is not None:
            if args.parser_record_export_limit < 0 or args.parser_record_export_limit > 2_000_000:
                raise ValueError("--parser-record-export-limit must be between 0 and 2000000")
            os.environ["BLITZ_PARSER_RECORD_EXPORT_LIMIT"] = str(args.parser_record_export_limit)
        if args.windows_artifact_profile is not None:
            os.environ["BLITZ_WINDOWS_ARTIFACT_PROFILE"] = args.windows_artifact_profile
        if args.full_sql_correlation:
            os.environ["BLITZ_SQLITE_NORMALIZATION"] = "1"
            os.environ["BLITZ_FULL_SQL_CORRELATION"] = "1"
        from blitz_dfir.pipeline.analyze import run_analysis

        result = run_analysis(
            manifest_path=Path(args.manifest),
            mode=args.mode,
            tool_config_path=Path(args.tool_config),
            enable_reasoning=args.enable_reasoning,
            psort_profile=args.psort_profile,
            tool_timeout_seconds=args.tool_timeout,
            psort_filter=args.psort_filter,
            psort_slice=args.psort_slice,
            psort_slice_size=args.psort_slice_size,
            resume_session_path=Path(args.resume_session) if args.resume_session else None,
            full_sql_correlation=args.full_sql_correlation,
            case_objective=args.case_objective,
            progress=_print_progress,
        )
        print(f"[+] Analysis completed for case: {result.case_id}")
        print("[+] Read-only scope enforced through manifest-registered evidence IDs")
        print(f"[+] Session created: {result.session_id}")
        print(f"[+] Normalized events: {result.event_count}")
        print(f"[+] Findings: {result.finding_count}")
        print(f"[+] Signal warnings: {result.warning_count}")
        print(f"[+] Validation passed: {result.validation_passed}")
        print(f"[+] Reasoning enabled: {result.reasoning_enabled}")
        print(f"[+] Audit chain written: {result.audit_log_path}")
        print(f"[+] Session state written: {result.session_state_path}")
        print(f"[+] Progress state written: {result.progress_state_path}")
        print(f"[+] Artifact manifest written: {result.artifact_manifest_path}")
        print(f"[+] Case objective written: {result.case_objective_path}")
        print(f"[+] Case objective Markdown written: {result.case_objective_markdown_path}")
        print(f"[+] Investigation plan written: {result.investigation_plan_path}")
        print(f"[+] Investigation plan Markdown written: {result.investigation_plan_markdown_path}")
        print(f"[+] Evidence triage written: {result.evidence_triage_path}")
        print(f"[+] Evidence triage Markdown written: {result.evidence_triage_markdown_path}")
        print(f"[+] Batch plan written: {result.batch_plan_path}")
        print(f"[+] Tool discovery written: {result.tool_discovery_path}")
        print(f"[+] Evidence inventory written: {result.evidence_inventory_path}")
        print(f"[+] Recovery plan written: {result.recovery_plan_path}")
        print(f"[+] Object inventory written: {result.object_inventory_path}")
        print(f"[+] Full accounting written: {result.full_accounting_path}")
        print(f"[+] Event store written: {result.event_store_path}")
        print(f"[+] Unknowns written: {result.unknowns_path}")
        print(f"[+] Stress report written: {result.stress_report_path}")
        print(f"[+] Evidentiary weighting JSON written: {result.evidentiary_weighting_path}")
        print(f"[+] Investigation guidance JSON written: {result.investigation_guidance_path}")
        print(f"[+] Temporal gap analysis JSON written: {result.temporal_gap_analysis_path}")
        print(f"[+] Attack-stage timeline JSON written: {result.attack_stage_timeline_path}")
        print(f"[+] LLM report verification JSON written: {result.llm_report_verification_path}")
        print(f"[+] Evidence contradiction analysis JSON written: {result.contradiction_analysis_path}")
        print(f"[+] Evidentiary weighting Markdown written: {result.evidentiary_weighting_markdown_path}")
        print(f"[+] Temporal gap analysis Markdown written: {result.temporal_gap_analysis_markdown_path}")
        print(f"[+] Attack-stage timeline Markdown written: {result.attack_stage_timeline_markdown_path}")
        print(f"[+] LLM report verification Markdown written: {result.llm_report_verification_markdown_path}")
        print(f"[+] Evidence contradiction analysis Markdown written: {result.contradiction_analysis_markdown_path}")
        print(f"[+] Evidence maturity JSON written: {result.evidence_maturity_path}")
        print(f"[+] Evidence maturity Markdown written: {result.evidence_maturity_markdown_path}")
        print(f"[+] Finding provenance Markdown written: {result.finding_provenance_markdown_path}")
        print(f"[+] Agent trace JSON written: {result.agent_trace_path}")
        print(f"[+] Agent journal Markdown written: {result.agent_journal_path}")
        print(f"[+] Overall findings written: {result.overall_findings_path}")
        print(f"[+] Overall reports written: {result.overall_reports_path}")
        print(f"[+] Collated audit written: {result.collated_audit_path}")
        print(f"[+] JSON report written: {result.report_json_path}")
        print(f"[+] Markdown report written: {result.report_markdown_path}")
        print(f"[+] HTML report written: {result.report_html_path}")
        return 0
    if args.command == "mcp-serve":
        from blitz_dfir.mcp.stdio_server import run_mcp_stdio_server

        return run_mcp_stdio_server(
            manifest_path=Path(args.manifest),
            tool_config_path=Path(args.tool_config),
        )
    return 2


def _print_progress(message: str, data: dict[str, Any] | None = None) -> None:
    if data:
        detail = " ".join(f"{key}={value}" for key, value in data.items())
        print(f"[+] {message}: {detail}", flush=True)
        return
    print(f"[+] {message}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
