ansforensics@siftworkstation: ~
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
BLITZ_SQLITE_NORMALIZATION=1 \
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
  --normalized-export-limit 10000 \
  --parser-record-export-limit 10000 \
  --full-sql-correlation \
  2>&1 | tee "$RUN_ROOT/launcher.log"

echo "analysis_exit=${PIPESTATUS[0]}" | tee "$RUN_ROOT/run_exit.txt"

CASE=BLITZ-ROCBA-MEMORY bash scripts/blitz_status.sh
Filesystem                         Size  Used Avail Use% Mounted on
/dev/mapper/ubuntu--vg-ubuntu--lv   98G   59G   35G  63% /
/dev/mapper/ubuntu--vg-ubuntu--lv   98G   59G   35G  63% /
               total        used        free      shared  buff/cache   available
Mem:           5.8Gi       1.5Gi       3.4Gi        35Mi       1.3Gi       4.4Gi
Swap:          3.8Gi          0B       3.8Gi
[+] Manifest loaded: case_id=BLITZ-ROCBA-MEMORY evidence_count=1 session_id=sess-20260604T025315Z-58e93ddd
[+] Protocol SIFT workflow context recorded: workflow=protocol_sift_compatible_direct_analysis agent_framework=supervised_sift_launcher case_root=None run_root=None control_path=Protocol SIFT / SIFT launcher -> Blitz typed evidence pipeline -> SIFT forensic tools generic_shell_exposed=False raw_evidence_to_llm=False raw_tool_output_to_llm=False claim_boundary=This layer records Protocol SIFT-compatible workflow context. Findings still require manifest evidence, typed tool output, parser validation, normalization, correlation, and audit traceability.
[+] Case objective defined: source=cli evidence_count=1
[+] Investigation plan completed: families=memory phases=3
[+] Batch plan created: batches=1 tasks=1
[+] Evidence triage completed: evidence=1 critical=0 high=1
[+] Batch started: batch_id=batch-01-memory family=memory tasks=1
[+] Evidence queued: evidence_id=rocba-memory type=MEMORY
[+] Typed tool started: tool=memory evidence_id=rocba-memory
[+] Typed tool completed: tool=memory exit_code=2 duration_ms=1821 timed_out=False
[+] Batch completed: batch_id=batch-01-memory tool_results=1 parser_results=1
[+] Normalization completed: events=0 warnings=2 analysis_events_loaded=0
[+] Object inventory completed: source=in_memory_normalized_events objects=0 normalized_events=0
Traceback (most recent call last):
  File "/home/sansforensics/src/Blitz_DFIR/app.py", line 246, in <module>
    raise SystemExit(main())
                     ^^^^^^
  File "/home/sansforensics/src/Blitz_DFIR/app.py", line 174, in main
    result = run_analysis(
             ^^^^^^^^^^^^^
  File "/home/sansforensics/src/Blitz_DFIR/blitz_dfir/pipeline/analyze.py", line 1232, in run_analysis
    sql_correlation = correlate_normalized_events_sqlite(
                      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/sansforensics/src/Blitz_DFIR/blitz_dfir/correlation/sqlite_backend.py", line 88, in correlate_normalized_events_sqlite
    _require_normalized_events(connection)
  File "/home/sansforensics/src/Blitz_DFIR/blitz_dfir/correlation/sqlite_backend.py", line 120, in _require_normalized_events
    raise ValueError("full SQL correlation requires normalized_events table")
ValueError: full SQL correlation requires normalized_events table
analysis_exit=1
[time]
Thu Jun  4 02:53:26 UTC 2026

[active Blitz/SIFT processes]
no active Blitz/SIFT analysis process matched

[latest run bundle]
/cases/BLITZ-ROCBA-MEMORY/analysis/runs/20260604T023724Z_rocba_memory_no_llm
session_path=not_created_yet
launcher_tail:
                     ^^^^^^
  File "/home/sansforensics/src/Blitz_DFIR/app.py", line 174, in main
    result = run_analysis(
             ^^^^^^^^^^^^^
  File "/home/sansforensics/src/Blitz_DFIR/blitz_dfir/pipeline/analyze.py", line 1232, in run_analysis
    sql_correlation = correlate_normalized_events_sqlite(
                      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/sansforensics/src/Blitz_DFIR/blitz_dfir/correlation/sqlite_backend.py", line 88, in correlate_normalized_events_sqlite
    _require_normalized_events(connection)
  File "/home/sansforensics/src/Blitz_DFIR/blitz_dfir/correlation/sqlite_backend.py", line 120, in _require_normalized_events
    raise ValueError("full SQL correlation requires normalized_events table")
ValueError: full SQL correlation requires normalized_events table

[session]
/cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd
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
status: RUNNING
effective_status: ABANDONED_OR_PARTIAL
live_process: no
writer_pid: 3771 alive=no
message: Blitz DFIR process interrupted due to no live process updating this RUNNING session.
operator_action: preserve hashes and logs, then resume from the latest complete checkpoint or rerun. If you want to continue processing, reinitiate the process after fixing the cause.
current_layer: Correlation and suspicion scoring (correlation)
overall: [##########################........] 75.97%
elapsed: 2s
eta: 0s  eta_utc=2026-06-04T02:53:18.458027Z
updated_utc: 2026-06-04T02:53:18.458027Z

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
[>] [###...............................]  10.00% Correlation and suspicion scoring
        analysis_event_count=0, backend=sqlite, normalized_event_count=0
[ ] [..................................]   0.00% Evidentiary weighting
[ ] [..................................]   0.00% Evidence contradiction analysis
[ ] [..................................]   0.00% Validation
[ ] [..................................]   0.00% Unknowns and coverage
[ ] [..................................]   0.00% Bounded LLM reasoning over validated summaries
[ ] [..................................]   0.00% Report generation
[ ] [..................................]   0.00% Evidence maturity traceability
[ ] [..................................]   0.00% Audit finalization and artifact hashes

[artifact readiness]
reports_ready: pending
report_generation_layer: PENDING
case_objective_ready: ready source=cli
investigation_priorities_ready: ready count=1
evidence_triage_ready: ready count=1
bounded_llm_reasoning_layer: PENDING
bounded_llm_reasoning_ready: pending
bounded_llm_reasoning_evidence_type: none
bounded_llm_reasoning_evidence_type_expected_values: INFERRED, none
llm_hypothesis_count: 0
safety_interpretation_ready: pending
trust_artifacts_ready: pending
audit_finalization_layer: PENDING
artifact_manifest_ready: pending
audit_attribution_ready: pending
postrun_checks_ready: pending status=UNKNOWN
judge_review_bundle_ready: pending
pending_or_missing:
  - report_json: reports/report.json
  - report_markdown: reports/report.md
  - report_html: reports/report.html
  - validation: findings/validation.json
  - unknowns: findings/unknowns.json
  - signal_integrity: findings/signal_integrity.json
  - coverage: findings/coverage.json
  - evidentiary_weighting: findings/evidentiary_weighting.json
  - contradiction_analysis: findings/contradiction_analysis.json
  - evidence_maturity: findings/evidence_maturity.json
  - evidence_maturity_markdown: reports/evidence_maturity.md
  - finding_provenance: reports/finding_provenance.md
  - artifact_manifest: findings/artifact_manifest.json
  - llm_reasoning: reports/report.json inferred_analyst_reasoning not ready
  - safety_interpretation: validation/unknowns/signal/coverage/contradiction bundle incomplete
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
session_root: /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd
Layer / Review Target              Path
---------------------------------- --------------------------------------------------------------------------------
Final report HTML                  /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/reports/report.html [missing]
Final report Markdown              /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/reports/report.md [missing]
Final report JSON                  /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/reports/report.json [missing]
LLM reasoning                      /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/reports/report.json (reports/report.json -> inferred_analyst_reasoning)
Case objective                     /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/reports/case_objective.md [ready]
Investigation plan                 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/reports/investigation_plan.md [ready]
Evidence triage                    /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/reports/evidence_triage.md [ready]
Correlation findings and scoring   /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/reports/report.json (reports/report.json -> findings)
Evidentiary weighting              /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/reports/evidentiary_weighting.md [missing]
Contradiction analysis             /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/reports/contradiction_analysis.md [missing]
Evidence traceability              /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/reports/evidence_maturity.md [missing]
Finding provenance visualization   /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/reports/finding_provenance.md [missing]
Audit progress                     /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/audit/progress.json [ready]
Session state                      /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/audit/session_state.json [ready]
Audit event log                    /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/audit/audit.ndjson [missing]
Artifact hashes                    /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/findings/artifact_manifest.json [missing]
Normalized event sample            /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/findings/normalized_events.json [missing]
SQLite normalized event store      /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/findings/event_store.sqlite [ready]
Parser results                     /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/findings/parser_results.json [ready]
Tool results                       /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/findings/tool_results.json [ready]
Coverage and unknowns              /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/findings/coverage.json (findings/coverage.json + findings/unknowns.json)
Validation and signal integrity    /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/findings/validation.json (findings/validation.json + findings/signal_integrity.json)

[session state]
status: RUNNING
phase: full_accounting_completed
timestamp_utc: 2026-06-04T02:53:18.455283Z
session_id: sess-20260604T025315Z-58e93ddd
details:
  artifact_count: 0
  total_rows: 0

[recent audit checkpoints]
8: 2026-06-04T02:53:16.255703Z batch_plan_created (Blitz DFIR batch planner; component=batch_planning_layer) batch_count=1 task_count=1 boundary=Blitz deterministic control plane
9: 2026-06-04T02:53:16.285995Z evidence_inventory_completed (Blitz evidence inventory layer; component=inventory_layer) evidence_count=1 behavior=analyst_review_required boundary=Blitz deterministic control plane
10: 2026-06-04T02:53:16.301177Z recovery_plan_created (Blitz recovery planner; component=planning_layer) evidence_count=1 candidate_count=3 boundary=Blitz deterministic control plane
11: 2026-06-04T02:53:16.326013Z evidence_triage_completed (Blitz evidence triage layer; component=evidence_triage_layer) evidence_count=1 critical_count=0 high_count=1 boundary=Blitz deterministic control plane
12: 2026-06-04T02:53:16.328691Z batch_started (Blitz DFIR batch planner; component=batch_planning_layer) task_count=1 boundary=Blitz deterministic control plane
13: 2026-06-04T02:53:16.411902Z tool_request_validated (Blitz MCP dispatcher -> memory; component=typed_tool_boundary) evidence_id=rocba-memory tool=memory boundary=MCP typed allowlist
14: 2026-06-04T02:53:18.263290Z tool_request_completed (Blitz MCP dispatcher -> memory; component=typed_tool_boundary) evidence_id=rocba-memory tool=memory boundary=MCP typed allowlist
15: 2026-06-04T02:53:18.267190Z analysis_tool_result (SIFT tool adapter: memory; component=typed_tool_boundary) evidence_id=rocba-memory typed_tool=memory tool_name=volatility exit_code=2 timed_out=False behavior=degraded_nonzero_exit boundary=SIFT tool subprocess sandbox
16: 2026-06-04T02:53:18.298296Z parser_completed (Blitz parser: volatility; component=parser_layer) evidence_id=rocba-memory parser=volatility boundary=Blitz deterministic control plane
17: 2026-06-04T02:53:18.300913Z batch_completed (Blitz DFIR batch planner; component=batch_planning_layer)  boundary=Blitz deterministic control plane
18: 2026-06-04T02:53:18.321221Z normalization_completed (Blitz normalization engine; component=normalization_layer) event_count=0 boundary=Blitz deterministic control plane
19: 2026-06-04T02:53:18.340527Z object_inventory_completed (Blitz object inventory layer; component=inventory_layer) normalized_event_count=0 object_count=0 boundary=Blitz deterministic control plane
20: 2026-06-04T02:53:18.380945Z correlation_scope_recorded (Blitz DFIR; component=correlation_layer) normalized_event_count=0 analysis_event_count=0 boundary=Blitz deterministic control plane
21: 2026-06-04T02:53:18.455129Z full_accounting_completed (Blitz full accounting layer; component=full_accounting_layer) total_rows=0 artifact_count=0 boundary=Blitz deterministic control plane

[key output sizes]
2026-06-04 02:53:15.8949870960         1119 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/findings/case_objective.json
2026-06-04 02:53:15.8989210860          985 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/reports/case_objective.md
2026-06-04 02:53:16.1953222450         3025 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/findings/tool_discovery.json
2026-06-04 02:53:16.2061613470         1721 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/findings/investigation_plan.json
2026-06-04 02:53:16.2120735840         1220 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/reports/investigation_plan.md
2026-06-04 02:53:16.2544446180         1079 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/findings/batch_plan.json
2026-06-04 02:53:16.2820350580         1168 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/findings/evidence_inventory.json
2026-06-04 02:53:16.2997717700         2545 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/findings/recovery_plan.json
2026-06-04 02:53:16.3204646000         1217 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/findings/evidence_triage.json
2026-06-04 02:53:16.3253914640          668 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/reports/evidence_triage.md
2026-06-04 02:53:18.2582004620            0 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/findings/rocba-memory.volatility.stdout.txt
2026-06-04 02:53:18.2582004620            0 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/findings/rocba-memory.windows_pslist.json
2026-06-04 02:53:18.2582004620         6472 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/findings/rocba-memory.volatility.stderr.txt
2026-06-04 02:53:18.3007037890         1221 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/findings/tool_results.json
2026-06-04 02:53:18.3076229370          543 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/findings/parser_results.json
2026-06-04 02:53:18.3382648710          600 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/findings/object_inventory.json
2026-06-04 02:53:18.4460058710        28672 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/findings/event_store.sqlite
2026-06-04 02:53:18.4519365680          159 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/findings/full_accounting.json
2026-06-04 02:53:18.4549019170          390 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/audit/session_state.json
2026-06-04 02:53:18.4549019170        15737 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/audit/sess-20260604T025315Z-58e93ddd.ndjson
2026-06-04 02:53:18.4578672650        12647 /cases/BLITZ-ROCBA-MEMORY/output/sess-20260604T025315Z-58e93ddd/audit/progress.json

[resources]
               total        used        free      shared  buff/cache   available
Mem:           5.8Gi       1.5Gi       145Mi        35Mi       4.5Gi       4.3Gi
Swap:          3.8Gi       524Ki       3.8Gi
Filesystem                         Size  Used Avail Use% Mounted on
/dev/mapper/ubuntu--vg-ubuntu--lv   98G   59G   35G  63% /

[operator result]
Traceback (most recent call last):
  File "<stdin>", line 26, in <module>
  File "<stdin>", line 15, in load_json
AttributeError: 'NoneType' object has no attribute 'exists'
sansforensics@siftworkstation: ~/src/Blitz_DFIR
