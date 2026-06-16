sansforensics@siftworkstation: ~/src/Blitz_DFIR
$ cd /home/sansforensics/src/Blitz_DFIR

CASE=BLITZ-ROCBA-MEMORY
CASE_ROOT=/cases/$CASE
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)_rocba_memory_no_llm"
RUN_ROOT="$CASE_ROOT/analysis/runs/$RUN_ID"

mkdir -p "$RUN_ROOT"

df -h "$CASE_ROOT" /
free -h

PYTHONUNBUFFERED=1 \
MALLOC_ARENA_MAX=2 \
nice -n 10 .venv/bin/python app.py analyze \
  --manifest "$CASE_ROOT/case.yaml" \
  --case-objective "Analyze the Rocba memory image for evidence-backed suspicious processes, execution artifacts, persistence indicators, credential activity, and unknowns while avoiding unsupported conclusions." \
  --mode timeline \
  --tool-config config/tools.yaml \
  --tool-timeout 7200 \
  --max-normalized-events 5000000 \
  --max-analysis-events 2000000 \
  --report-event-limit 2000000 \
  --report-finding-limit 2000000 \
  --normalized-export-limit 2000000 \
  --parser-record-export-limit 2000000 \
  2>&1 | tee "$RUN_ROOT/launcher.log"

echo "analysis_exit=${PIPESTATUS[0]}" | tee "$RUN_ROOT/run_exit.txt"

CASE=BLITZ-ROCBA-MEMORY bash scripts/blitz_status.sh
Filesystem                         Size  Used Avail Use% Mounted on
/dev/mapper/ubuntu--vg-ubuntu--lv   98G   59G   35G  63% /
/dev/mapper/ubuntu--vg-ubuntu--lv   98G   59G   35G  63% /
               total        used        free      shared  buff/cache   available
Mem:           5.8Gi       1.5Gi       173Mi        13Mi       4.5Gi       4.3Gi
Swap:          3.8Gi       426Mi       3.4Gi
[+] Manifest loaded: case_id=BLITZ-ROCBA-MEMORY evidence_count=1 session_id=sess-20260603T163809Z-0c0caadd
[+] Protocol SIFT workflow context recorded: workflow=protocol_sift_compatible_direct_analysis agent_framework=supervised_sift_launcher case_root=None run_root=None control_path=Protocol SIFT / SIFT launcher -> Blitz typed evidence pipeline -> SIFT forensic tools generic_shell_exposed=False raw_evidence_to_llm=False raw_tool_output_to_llm=False claim_boundary=This layer records Protocol SIFT-compatible workflow context. Findings still require manifest evidence, typed tool output, parser validation, normalization, correlation, and audit traceability.
[+] Case objective defined: source=cli evidence_count=1
[+] Investigation plan completed: families=memory phases=3
[+] Batch plan created: batches=1 tasks=1
[+] Evidence triage completed: evidence=1 critical=0 high=1
[+] Batch started: batch_id=batch-01-memory family=memory tasks=1
[+] Evidence queued: evidence_id=rocba-memory type=MEMORY
[+] Typed tool started: tool=memory evidence_id=rocba-memory
[+] Typed tool completed: tool=memory exit_code=1 duration_ms=7259 timed_out=False
[+] Batch completed: batch_id=batch-01-memory tool_results=1 parser_results=1
[+] Normalization completed: events=0 warnings=2 analysis_events_loaded=0
[+] Object inventory completed: source=in_memory_normalized_events objects=0 normalized_events=0
[+] Correlation completed: findings=0 stages=0
[+] Validation completed: passed=False issues=4
[+] Validation artifacts written: validation=/cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/validation.json unknowns=/cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/unknowns.json
[+] Reports written: report_html=/cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/report.html
[+] Analysis completed for case: BLITZ-ROCBA-MEMORY
[+] Read-only scope enforced through manifest-registered evidence IDs
[+] Session created: sess-20260603T163809Z-0c0caadd
[+] Normalized events: 0
[+] Findings: 0
[+] Signal warnings: 4
[+] Validation passed: False
[+] Reasoning enabled: False
[+] Audit chain written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/audit/sess-20260603T163809Z-0c0caadd.ndjson
[+] Session state written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/audit/session_state.json
[+] Progress state written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/audit/progress.json
[+] Artifact manifest written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/artifact_manifest.json
[+] Case objective written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/case_objective.json
[+] Case objective Markdown written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/case_objective.md
[+] Investigation plan written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/investigation_plan.json
[+] Investigation plan Markdown written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/investigation_plan.md
[+] Evidence triage written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/evidence_triage.json
[+] Evidence triage Markdown written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/evidence_triage.md
[+] Batch plan written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/batch_plan.json
[+] Tool discovery written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/tool_discovery.json
[+] Evidence inventory written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/evidence_inventory.json
[+] Recovery plan written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/recovery_plan.json
[+] Object inventory written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/object_inventory.json
[+] Full accounting written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/full_accounting.json
[+] Event store written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/event_store.sqlite
[+] Unknowns written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/unknowns.json
[+] Stress report written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/stress_report.json
[+] Evidentiary weighting JSON written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/evidentiary_weighting.json
[+] Evidence contradiction analysis JSON written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/contradiction_analysis.json
[+] Evidentiary weighting Markdown written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/evidentiary_weighting.md
[+] Evidence contradiction analysis Markdown written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/contradiction_analysis.md
[+] Evidence maturity JSON written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/evidence_maturity.json
[+] Evidence maturity Markdown written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/evidence_maturity.md
[+] Finding provenance Markdown written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/finding_provenance.md
[+] JSON report written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/report.json
[+] Markdown report written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/report.md
[+] HTML report written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/report.html
analysis_exit=0
[time]
Wed Jun  3 16:46:07 UTC 2026

[active Blitz/SIFT processes]
no active Blitz/SIFT analysis process matched

[latest run bundle]
/cases/BLITZ-ROCBA-MEMORY/analysis/runs/20260603T162407Z_rocba_memory_no_llm
session_path=not_created_yet
launcher_tail:
[+] Unknowns written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/unknowns.json
[+] Stress report written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/stress_report.json
[+] Evidentiary weighting JSON written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/evidentiary_weighting.json
[+] Evidence contradiction analysis JSON written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/contradiction_analysis.json
[+] Evidentiary weighting Markdown written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/evidentiary_weighting.md
[+] Evidence contradiction analysis Markdown written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/contradiction_analysis.md
[+] Evidence maturity JSON written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/evidence_maturity.json
[+] Evidence maturity Markdown written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/evidence_maturity.md
[+] Finding provenance Markdown written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/finding_provenance.md
[+] JSON report written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/report.json
[+] Markdown report written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/report.md
[+] HTML report written: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/report.html

[session]
/cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd
selection=auto_latest_session_no_active_process
note=latest_run_bundle_has_no_session; below is historical latest session, not a new E2E result

[run operator status]
run_root: not_found_for_selected_session
source: reconstructed; run_status.json not found
operator_status: UNKNOWN
operator_phase: unknown
analysis_process_active: no
analysis_exit_code: pending
postrun_checks: UNKNOWN
supervisor_pid: unknown alive=no
prompt_returned_or_returning: no
pending_after_session_100: supervised launcher still active or final status not written; analysis process exit code; postrun checks; shell prompt return/final launcher exit

[progress]
source: audit/progress.json
status: COMPLETED
effective_status: COMPLETED
live_process: no
writer_pid: 5897 alive=no
current_layer: Audit finalization and artifact hashes (audit_finalization)
overall: [##################################] 100.0%
elapsed: 7m 49s
eta: unknown  eta_utc=None
updated_utc: 2026-06-03T16:45:59.337091Z

[x] [##################################] 100.00% Manifest and evidence integrity
[x] [##################################] 100.00% Protocol SIFT workflow context
[x] [##################################] 100.00% Case objective definition
[x] [##################################] 100.00% Tool discovery
[x] [##################################] 100.00% Investigation planning
[x] [##################################] 100.00% Batch planning
[x] [##################################] 100.00% Evidence inventory
[x] [##################################] 100.00% Recovery planning
[x] [##################################] 100.00% Evidence triage
[x] [##################################] 100.00% Typed SIFT tool execution (1/1)
[x] [##################################] 100.00% Parser result extraction (1/1)
[x] [##################################] 100.00% SQLite-backed normalization (normalized_rows=0, cap=1)
[x] [##################################] 100.00% Object inventory
[x] [##################################] 100.00% Full accounting
[x] [##################################] 100.00% SQLite event store
[x] [##################################] 100.00% Correlation and suspicion scoring
[x] [##################################] 100.00% Evidentiary weighting
[x] [##################################] 100.00% Evidence contradiction analysis
[x] [##################################] 100.00% Validation
[x] [##################################] 100.00% Unknowns and coverage
[-] [##################################] 100.00% Bounded LLM reasoning over validated summaries
[x] [##################################] 100.00% Report generation (4/4)
[x] [##################################] 100.00% Evidence maturity traceability
[x] [##################################] 100.00% Audit finalization and artifact hashes

[artifact readiness]
reports_ready: ready
report_generation_layer: COMPLETED
case_objective_ready: ready source=cli
investigation_priorities_ready: ready count=1
evidence_triage_ready: ready count=1
bounded_llm_reasoning_layer: SKIPPED
bounded_llm_reasoning_ready: skipped_by_policy
bounded_llm_reasoning_evidence_type: none
bounded_llm_reasoning_evidence_type_expected_values: INFERRED, none
llm_hypothesis_count: 0
safety_interpretation_ready: ready
trust_artifacts_ready: ready
audit_finalization_layer: COMPLETED
artifact_manifest_ready: ready
audit_attribution_ready: pending
postrun_checks_ready: pending status=UNKNOWN
judge_review_bundle_ready: pending
pending_or_missing:
  - audit_attribution: postrun audit attribution check artifact missing
  - postrun_checks: supervised postrun checks not complete

[evidence category proof]
manifest_registered_evidence:
Evidence ID              Evidence Type    Category   Pipeline   Trust Tier             Verified
------------------------ ---------------- ---------- ---------- ---------------------- --------
rocba-memory             MEMORY           RAW        raw        TIER_1_HIGH            True

normalized_event_category_counts:
  pending: normalized_events table not found

bounded_llm_reasoning_category:
  none or skipped

[review map]
session_root: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd
Layer / Review Target              Path
---------------------------------- --------------------------------------------------------------------------------
Final report HTML                  /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/report.html [ready]
Final report Markdown              /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/report.md [ready]
Final report JSON                  /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/report.json [ready]
LLM reasoning                      /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/report.json (reports/report.json -> inferred_analyst_reasoning)
Case objective                     /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/case_objective.md [ready]
Investigation plan                 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/investigation_plan.md [ready]
Evidence triage                    /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/evidence_triage.md [ready]
Correlation findings and scoring   /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/report.json (reports/report.json -> findings)
Evidentiary weighting              /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/evidentiary_weighting.md [ready]
Contradiction analysis             /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/contradiction_analysis.md [ready]
Evidence traceability              /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/evidence_maturity.md [ready]
Finding provenance visualization   /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/finding_provenance.md [ready]
Audit progress                     /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/audit/progress.json [ready]
Session state                      /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/audit/session_state.json [ready]
Audit event log                    /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/audit/audit.ndjson [missing]
Artifact hashes                    /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/artifact_manifest.json [ready]
Normalized event sample            /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/normalized_events.json [ready]
SQLite normalized event store      /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/event_store.sqlite [ready]
Parser results                     /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/parser_results.json [ready]
Tool results                       /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/tool_results.json [ready]
Coverage and unknowns              /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/coverage.json (findings/coverage.json + findings/unknowns.json)
Validation and signal integrity    /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/validation.json (findings/validation.json + findings/signal_integrity.json)

[session state]
status: COMPLETED
phase: analysis_completed
timestamp_utc: 2026-06-03T16:45:59.336722Z
session_id: sess-20260603T163809Z-0c0caadd
details:
  artifact_manifest: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/artifact_manifest.json
  audit_log: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/audit/sess-20260603T163809Z-0c0caadd.ndjson
  validation_passed: False

[recent audit checkpoints]
23: 2026-06-03T16:38:19.316459Z evidentiary_weighting_completed (Blitz DFIR; component=pipeline_orchestrator) finding_count=0 boundary=Blitz deterministic control plane
24: 2026-06-03T16:38:19.334234Z contradiction_analysis_completed (Blitz DFIR; component=pipeline_orchestrator)  boundary=Blitz deterministic control plane
25: 2026-06-03T16:38:19.353799Z correction_attempt (Blitz bounded self-correction engine; component=self_correction_layer)  behavior=self_correction_or_recovery boundary=Blitz deterministic control plane
26: 2026-06-03T16:38:19.354078Z correction_attempt (Blitz bounded self-correction engine; component=self_correction_layer)  behavior=self_correction_or_recovery boundary=Blitz deterministic control plane
27: 2026-06-03T16:38:19.358477Z correction_history (Blitz bounded self-correction engine; component=self_correction_layer)  behavior=self_correction_or_recovery boundary=Blitz deterministic control plane
28: 2026-06-03T16:38:19.358766Z validation_completed (Blitz validation engine; component=validation_unknowns_layer) passed=False issue_count=4 trigger_count=4 behavior=validation_issues_detected boundary=Blitz deterministic control plane
29: 2026-06-03T16:38:19.397101Z unknowns_completed (Blitz unknowns and coverage engine; component=validation_unknowns_layer) unknown_count=10 critical_count=2 high_count=4 behavior=analyst_review_required boundary=Blitz deterministic control plane
30: 2026-06-03T16:38:19.428441Z reasoning_skipped (Blitz DFIR policy: bounded LLM reasoning disabled for this run; component=bounded_llm_reasoning_layer) reason=not_enabled behavior=expected_skip_or_disabled boundary=Blitz deterministic control plane
31: 2026-06-03T16:38:20.121494Z report_generation_completed (Blitz reporting/audit finalizer; component=reporting_audit_layer)  boundary=Blitz deterministic control plane
32: 2026-06-03T16:45:59.062408Z evidence_maturity_written (Blitz evidence maturity traceability layer; component=reporting_audit_layer) finding_count=0 traceable_finding_count=0 evidence_hashes_preserved=True boundary=Blitz deterministic control plane
33: 2026-06-03T16:45:59.200747Z event_store_checkpointed (Blitz DFIR; component=pipeline_orchestrator)  boundary=Blitz deterministic control plane
34: 2026-06-03T16:45:59.321008Z artifact_manifest_written (Blitz reporting/audit finalizer; component=reporting_audit_layer)  boundary=Blitz deterministic control plane
35: 2026-06-03T16:45:59.321236Z reports_written (Blitz reporting/audit finalizer; component=reporting_audit_layer)  boundary=Blitz deterministic control plane
36: 2026-06-03T16:45:59.336629Z analysis_completed (Blitz DFIR orchestrator; component=pipeline_orchestrator) event_count=0 finding_count=0 boundary=Blitz deterministic control plane

[key output sizes]
2026-06-03 16:38:11.3332453400          668 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/evidence_triage.md
2026-06-03 16:38:18.8933950590          381 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/rocba-memory.volatility.stdout.txt
2026-06-03 16:38:18.8953944180         7011 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/rocba-memory.volatility.stderr.txt
2026-06-03 16:38:18.8973937780          381 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/rocba-memory.windows_pslist.json
2026-06-03 16:38:18.9803671990         1221 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/tool_results.json
2026-06-03 16:38:18.9993611140          543 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/parser_results.json
2026-06-03 16:38:19.0783961490          600 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/object_inventory.json
2026-06-03 16:38:19.2524757210        28672 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/event_store.sqlite
2026-06-03 16:38:19.2704839540          159 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/full_accounting.json
2026-06-03 16:38:19.3095017880          178 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/evidentiary_weighting.json
2026-06-03 16:38:19.3155045330          318 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/evidentiary_weighting.md
2026-06-03 16:38:19.3245086480          246 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/contradiction_analysis.json
2026-06-03 16:38:19.3325123070          116 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/contradiction_analysis.md
2026-06-03 16:38:19.4005434030         4998 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/unknowns.json
2026-06-03 16:38:19.4035447750         1459 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/validation.json
2026-06-03 16:38:19.4045452320         2028 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/coverage.json
2026-06-03 16:38:19.4185516340         3629 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/signal_integrity.json
2026-06-03 16:38:19.4235539210         2555 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/correction_history.json
2026-06-03 16:38:19.4655731280            3 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/normalized_events.json
2026-06-03 16:38:19.5536133730         3123 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/stress_report.json
2026-06-03 16:38:19.5656188600        10846 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/report.json
2026-06-03 16:38:19.5666193180         3582 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/report.md
2026-06-03 16:38:20.1209540190         8139 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/report.html
2026-06-03 16:45:58.9891294680         2625 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/evidence_maturity.json
2026-06-03 16:45:59.0062355880          679 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/evidence_maturity.md
2026-06-03 16:45:59.0303859860          383 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/reports/finding_provenance.md
2026-06-03 16:45:59.3191844890         6800 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/findings/artifact_manifest.json
2026-06-03 16:45:59.3352847530        33592 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/audit/sess-20260603T163809Z-0c0caadd.ndjson
2026-06-03 16:45:59.3362910200          623 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/audit/session_state.json
2026-06-03 16:45:59.3383035530        15109 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260603T163809Z-0c0caadd/audit/progress.json

[resources]
               total        used        free      shared  buff/cache   available
Mem:           5.8Gi       1.5Gi       140Mi        13Mi       4.5Gi       4.3Gi
Swap:          3.8Gi       426Mi       3.4Gi
Filesystem                         Size  Used Avail Use% Mounted on
/dev/mapper/ubuntu--vg-ubuntu--lv   98G   59G   35G  63% /

[operator result]
Traceback (most recent call last):
  File "<stdin>", line 26, in <module>
  File "<stdin>", line 15, in load_json
AttributeError: 'NoneType' object has no attribute 'exists'
sansforensics@siftworkstation: ~/src/Blitz_DFIR
$ 

++++++++++++++++++++++++++++++++++++++++++++++++
rocba-memory.volatility.stderr.txt

Progress:   31.82		Updating caches for 110 files...

Progress:   32.73		Updating caches for 110 files...

Progress:   33.64		Updating caches for 110 files...

Progress:   34.55		Updating caches for 110 files...

Progress:   35.45		Updating caches for 110 files...

Progress:   36.36		Updating caches for 110 files...

Progress:   37.27		Updating caches for 110 files...

Progress:   38.18		Updating caches for 110 files...

Progress:   39.09		Updating caches for 110 files...

Progress:   40.00		Updating caches for 110 files...

Progress:   40.91		Updating caches for 110 files...

Progress:   41.82		Updating caches for 110 files...

Progress:   42.73		Updating caches for 110 files...

Progress:   43.64		Updating caches for 110 files...

Progress:   44.55		Updating caches for 110 files...

Progress:   45.45		Updating caches for 110 files...

Progress:   46.36		Updating caches for 110 files...

Progress:   47.27		Updating caches for 110 files...

Progress:   48.18		Updating caches for 110 files...

Progress:   49.09		Updating caches for 110 files...

Progress:   50.00		Updating caches for 110 files...

Progress:   50.91		Updating caches for 110 files...

Progress:   51.82		Updating caches for 110 files...

Progress:   52.73		Updating caches for 110 files...

Progress:   53.64		Updating caches for 110 files...

Progress:   54.55		Updating caches for 110 files...

Progress:   55.45		Updating caches for 110 files...

Progress:   56.36		Updating caches for 110 files...

Progress:   57.27		Updating caches for 110 files...

Progress:   58.18		Updating caches for 110 files...

Progress:   59.09		Updating caches for 110 files...

Progress:   60.00		Updating caches for 110 files...

Progress:   60.91		Updating caches for 110 files...

Progress:   61.82		Updating caches for 110 files...

Progress:   62.73		Updating caches for 110 files...

Progress:   63.64		Updating caches for 110 files...

Progress:   64.55		Updating caches for 110 files...

Progress:   65.45		Updating caches for 110 files...

Progress:   66.36		Updating caches for 110 files...

Progress:   67.27		Updating caches for 110 files...

Progress:   68.18		Updating caches for 110 files...

Progress:   69.09		Updating caches for 110 files...

Progress:   70.00		Updating caches for 110 files...

Progress:   70.91		Updating caches for 110 files...

Progress:   71.82		Updating caches for 110 files...

Progress:   72.73		Updating caches for 110 files...

Progress:   73.64		Updating caches for 110 files...

Progress:   74.55		Updating caches for 110 files...

Progress:   75.45		Updating caches for 110 files...

Progress:   76.36		Updating caches for 110 files...

Progress:   77.27		Updating caches for 110 files...

Progress:   78.18		Updating caches for 110 files...

Progress:   79.09		Updating caches for 110 files...

Progress:   80.00		Updating caches for 110 files...

Progress:   80.91		Updating caches for 110 files...

Progress:   81.82		Updating caches for 110 files...

Progress:   82.73		Updating caches for 110 files...

Progress:   83.64		Updating caches for 110 files...

Progress:   84.55		Updating caches for 110 files...

Progress:   85.45		Updating caches for 110 files...

Progress:   86.36		Updating caches for 110 files...

Progress:   87.27		Updating caches for 110 files...

Progress:   88.18		Updating caches for 110 files...

Progress:   89.09		Updating caches for 110 files...

Progress:   90.00		Updating caches for 110 files...

Progress:   90.91		Updating caches for 110 files...

Progress:   91.82		Updating caches for 110 files...

Progress:   92.73		Updating caches for 110 files...

Progress:   93.64		Updating caches for 110 files...

Progress:   94.55		Updating caches for 110 files...

Progress:   95.45		Updating caches for 110 files...

Progress:   96.36		Updating caches for 110 files...

Progress:   97.27		Updating caches for 110 files...

Progress:   98.18		Updating caches for 110 files...

Progress:   99.09		Updating caches for 110 files...

Progress:    0.00		Scanning FileLayer using PageMapScanner

Progress:   23.33		Scanning FileLayer using PageMapScanner

Progress:  100.00		Stacking attempts finished             

Progress:    0.00		Scanning layer_name using PdbSignatureScanner

Progress:    0.00		Scanning layer_name using PdbSignatureScanner
WARNING  volatility3.framework.symbols.windows.pdbutil: Cannot write necessary symbol file, please check permissions on /opt/volatility3/lib/python3.12/site-packages/volatility3/symbols/windows/ntkrnlmp.pdb/15B12C74F0E177581B6B27DD4C5022C2-1.json.xz
WARNING  volatility3.framework.symbols.windows.pdbutil: Cannot write necessary symbol file, please check permissions on /opt/volatility3/lib/python3.12/site-packages/volatility3/framework/symbols/windows/ntkrnlmp.pdb/15B12C74F0E177581B6B27DD4C5022C2-1.json.xz
WARNING  volatility3.framework.symbols.windows.pdbutil: Cannot write downloaded symbols, please add the appropriate symbols or add/modify a symbols directory that is writable

Progress:  100.00		PDB scanning finished                        
Unable to validate the plugin requirements: ['plugins.PsList.kernel.symbol_table_name']