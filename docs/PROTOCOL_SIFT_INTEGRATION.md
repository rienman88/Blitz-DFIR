# Protocol SIFT Integration

Blitz DFIR operates as a Protocol SIFT-compatible controlled forensic reasoning layer. It does not replace SIFT or Protocol SIFT. The judge-facing path is:

```text
OpenClaw / Protocol SIFT case
  -> Blitz DFIR stdio MCP server
  -> Blitz typed dispatcher and allowlist
  -> SIFT forensic tools
  -> parsed, hashed, session-scoped outputs
```

The MCP server exposes typed tools only. It does not expose shell execution, dynamic script generation, file deletion, remediation, or arbitrary command execution.

## Deployment Boundary

Deploying Blitz means deploying the Blitz orchestration, typed MCP, accounting, validation, unknowns, and reporting code. It does not mean deploying a separate forensic toolchain.

SIFT remains the forensic workstation. Protocol SIFT remains the agent-oriented workflow. Blitz calls SIFT-installed utilities through controlled wrappers and records what happened. Do not package or advertise Blitz as a replacement for SIFT tools such as Plaso, psort, Volatility, tshark, Chainsaw, YARA, or strings.

The intended production posture is:

```text
Analyst / Protocol SIFT / OpenClaw / Claude Code
  requests a bounded forensic action
Blitz MCP
  validates evidence ID, tool name, params, timeout, output scope
SIFT tool
  performs deterministic extraction
Blitz
  parses, accounts, validates, labels unknowns, and reports
```

This gives the judges a clear story: Protocol SIFT gives the AI a SIFT-native workflow; Blitz adds typed safety controls, batch execution, evidence accounting, and conservative validation.

## What Protocol SIFT Resolves

Protocol SIFT provides the AI-assisted SIFT workflow and research environment. In the hackathon context it helps by:

- Anchoring work inside the SIFT Workstation.
- Giving an AI agent a path to coordinate forensic tasks.
- Encouraging command/action logging tied to case artifacts.
- Providing a familiar reference workflow for judges and mentors.

Protocol SIFT is experimental and does not by itself prove that every tool call is safe, complete, or forensically sufficient. Blitz is designed to add those missing controls without weakening Protocol SIFT.

## What Blitz Adds To Protocol SIFT

Blitz adds a constrained layer underneath the agent:

- Typed MCP actions instead of generic shell access.
- Evidence-ID based access instead of arbitrary file paths.
- Tool allowlists and schema validation.
- Session-scoped output directories.
- Hash verification and hash-chained audit logging.
- Batch planning so heavy artifact families run step by step.
- Full accounting/event-store preservation for large exports.
- Unknowns and needs-review reporting instead of false certainty.
- Bounded LLM reasoning over summaries only when enabled.

The agent should not directly decide to run every SIFT tool at once. It should request a Blitz batch plan, run one batch, inspect validation/unknowns, then proceed to the next batch.

## Batch Plan As The Agent Contract

The batch plan is how Blitz maximizes Protocol SIFT safely. It turns broad intent such as "analyze this case" into ordered, resource-aware work:

```text
Evidence inventory
  -> artifact-family classification
  -> ordered batches
  -> one specialized SIFT tool family at a time
  -> full accounting and validation after each batch
  -> final cross-correlation and report
```

Current batch families include direct processed inputs, EVTX, PLASO, registry, memory, PCAP, disk timeline, filesystem, and unsupported/manual-review evidence. Future MCP controls should expose:

- `create_batch_plan`
- `get_batch_status`
- `run_next_batch`
- `summarize_unknowns`

This is the safer alternative to letting an agent perform continuous autonomous full-case execution on a constrained VM.

## Raw Versus Normalized Inputs

Blitz should maximize SIFT by routing raw evidence to SIFT tools, then letting Blitz reason over normalized outputs plus full accounting summaries.

Use raw evidence for extraction:

- EVTX, registry hives, memory images, PCAPs, disk images, browser stores, MFT/USN, SRUM, Amcache, Shimcache, Prefetch, and deleted-artifact recovery candidates.
- SIFT-native tools are better suited for parsing, carving, timeline generation, and memory/network extraction than an LLM or generic text workflow.

Use normalized events for reasoning:

- Correlation, confidence, contradiction analysis, evidentiary weighting, unknown-zone reporting, and final narrative should consume normalized events, accounting totals, source metadata, warnings, and provenance links.
- Raw evidence and unbounded raw tool output should remain available for trace-back, but should not be sent directly to an LLM.

The defensible judge-facing claim is not "nothing can be missed." The defensible claim is:

> Blitz inventories expected evidence, routes supported artifact families through typed SIFT tools, preserves full accounting, and explicitly reports unsupported, missing, deleted, degraded, or unprocessed areas as coverage gaps.

This keeps the architecture realistic. Deleted files and hidden artifacts require artifact-family-specific extraction and coverage accounting; they cannot be proven by simply asking an agent to inspect everything.

## Tested SIFT State

The current SIFT validation used:

```text
SIFT user: sansforensics
Blitz repo: /home/sansforensics/src/Blitz_DFIR
Case root: /cases/BLITZ-SMOKE-001
OpenClaw: primary judge-facing agent path
Claude Code: secondary compatibility path, account-gated
Windows-hosted Ollama: http://192.168.88.1:11434
Local smoke model: llama3.2:1b
Python: 3.12.3
Protocol SIFT files: ~/.claude/
```

Validated SIFT tools:

```text
log2timeline.py
psort.py
vol
chainsaw
tshark
yara
strings
```

Blitz quality gates passed on SIFT after Protocol SIFT installation:

```bash
python -m pytest -q
python -m compileall -q app.py blitz_dfir tests
python -m mypy app.py blitz_dfir tests
python -m ruff check app.py blitz_dfir tests
pip-audit -r requirements.txt -r requirements-dev.txt
```

## Windows-Hosted Ollama Communication

The tested free/local model path keeps Ollama on the Windows host and lets the SIFT VM call it across the VMware host-only/NAT network. This is expected: `ollama` does not need to be installed inside SIFT for this topology.

From SIFT, verify model reachability:

```bash
curl -s http://192.168.88.1:11434/api/tags | python -m json.tool
```

Verify native Ollama generation:

```bash
curl -s http://192.168.88.1:11434/api/generate \
  -H "Content-Type: application/json" \
  -d '{"model":"llama3.2:1b","prompt":"Reply with exactly: pong","stream":false,"keep_alive":"30m"}' \
  | python -m json.tool
```

Verify the OpenAI-compatible endpoint used by Blitz bounded LLM reasoning:

```bash
curl -s http://192.168.88.1:11434/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ollama" \
  -d '{"model":"llama3.2:1b","messages":[{"role":"user","content":"Return a JSON object with key status and value pong."}],"temperature":0,"max_tokens":16,"response_format":{"type":"json_object"}}' \
  | python -m json.tool
```

If SIFT cannot reach Ollama, start Ollama on Windows with a network listener and allow inbound TCP 11434 from the VMware subnet:

```powershell
$env:OLLAMA_HOST="0.0.0.0:11434"
ollama serve
```

For Blitz bounded LLM reasoning, set:

```bash
export LLM_PROVIDER=ollama
export LLM_BASE_URL=http://192.168.88.1:11434/v1
export LLM_API_KEY=ollama
export LLM_MODEL=llama3.2:1b
export LLM_TIMEOUT_SECONDS=600
export LLM_MAX_TOKENS=800
export LLM_RESPONSE_FORMAT_JSON=1
```

OpenClaw may use the native Ollama base URL without `/v1` if its Ollama provider expects the native API:

```text
http://192.168.88.1:11434
```

## Full E2E Ollama Reasoning Run

Use this runner after the deterministic no-LLM pipeline has passed. It tests SIFT tool execution, SQLite normalization, object inventory, full accounting, full SQL correlation, validation, reports, artifact hashes, and bounded Blitz reasoning through Windows-hosted Ollama. Reports remain bounded; raw evidence and raw tool output are not sent to the model.

```bash
cd /home/sansforensics/src/Blitz_DFIR
source .venv/bin/activate

CASE=BLITZ-RD01-PLASO \
OLLAMA_BASE_URL=http://192.168.88.1:11434 \
LLM_MODEL=llama3.2:1b \
LLM_TIMEOUT_SECONDS=600 \
LLM_MAX_TOKENS=800 \
LLM_RESPONSE_FORMAT_JSON=1 \
OLLAMA_KEEP_ALIVE=30m \
ENABLE_REASONING=1 \
MAX_NORMALIZED_EVENTS=2000000 \
MAX_ANALYSIS_EVENTS=100000 \
bash scripts/sift_e2e_ollama_run.sh
```

The runner writes a per-run bundle under:

```text
/cases/<CASE>/analysis/runs/<RUN_ID>/
```

That folder contains the launcher log, PID file, preflight output, run scope, and after the analysis exits, `session_path.txt`, a `session` symlink to the generated `output/sess-*` directory, and final copies of `session_state.json` and `progress.json`. The large authoritative artifacts remain inside the session directory to avoid duplicating multi-gigabyte SQLite and timeline files.

Each launcher execution creates a run bundle:

```text
/cases/<CASE>/analysis/runs/<RUN_ID>/
  launcher.log
  blitz.pid
  session_path.txt              # written after the analyze process exits
  session -> /cases/<CASE>/output/sess-...
  session_state.final.json      # copied at process exit when available
  progress.final.json           # copied at process exit when available
```

The heavy artifacts are not duplicated into the run bundle because `event_store.sqlite` and timelines can be many GB. The `session` symlink points to the canonical session output folder containing all generated normalization, accounting, correlation, report, audit, and artifact-hash files.

Monitor the run in one terminal and automatically return to the prompt when the run completes:

```bash
CASE=BLITZ-RD01-PLASO bash /home/sansforensics/src/Blitz_DFIR/scripts/blitz_monitor_until_done.sh
```

For a one-time status snapshot, run:

```bash
CASE=BLITZ-RD01-PLASO bash /home/sansforensics/src/Blitz_DFIR/scripts/blitz_status.sh
```

The status screen shows both the latest per-run bundle and the selected Blitz session. If a preflight fails before `app.py analyze` starts, no new `output/sess-*` session exists yet; the status screen will say `session_path=not_created_yet` under `[latest run bundle]` and will explicitly warn that any displayed session below is historical. `scripts/blitz_monitor_until_done.sh` is the preferred long-run monitor because it prints `Blitz DFIR Process completed` and exits when the run is complete; unlike `watch`, it does not keep the terminal occupied forever.

### Safe Resume

Resume is allowed only from a session that already has completed typed tool results. In that case Blitz reruns the downstream deterministic layers: parsing, normalization, object inventory, full accounting, SQLite event store, correlation, validation, unknowns, bounded LLM reasoning, reports, and audit finalization. It does not skip those downstream layers.

Use resume when `psort` or another typed SIFT tool already completed and the interruption happened later:

```bash
SESSION=/cases/BLITZ-RD01-PLASO/output/sess-20260530T234654Z-6510c41c

CASE=BLITZ-RD01-PLASO \
RESUME_SESSION="$SESSION" \
OLLAMA_BASE_URL=http://192.168.88.1:11434 \
LLM_MODEL=llama3.2:1b \
LLM_TIMEOUT_SECONDS=600 \
LLM_MAX_TOKENS=800 \
LLM_RESPONSE_FORMAT_JSON=1 \
OLLAMA_KEEP_ALIVE=30m \
ENABLE_REASONING=1 \
MAX_NORMALIZED_EVENTS=2000000 \
MAX_ANALYSIS_EVENTS=100000 \
bash /home/sansforensics/src/Blitz_DFIR/scripts/sift_e2e_ollama_run.sh

CASE=BLITZ-RD01-PLASO bash /home/sansforensics/src/Blitz_DFIR/scripts/blitz_monitor_until_done.sh "$SESSION"
```

Do not resume from a session if the typed tool layer did not finish or if `findings/tool_results.json` and recoverable `analysis_tool_result` audit entries are missing. Rerun from the beginning instead, because Blitz cannot honestly claim complete processing from normalization onward without a complete upstream extraction artifact.

If you need a deterministic comparison run without LLM reasoning, set `ENABLE_REASONING=0`. Keep all other limits the same so runtime and output differences are attributable to the reasoning layer only.

If the Ollama preflight times out, Blitz has not started yet. First terminate any leftover processes, then either restart Windows Ollama or increase the preflight timeouts:

```bash
bash /home/sansforensics/src/Blitz_DFIR/scripts/blitz_stop_processes.sh

CASE=BLITZ-RD01-PLASO \
OLLAMA_BASE_URL=http://192.168.88.1:11434 \
OLLAMA_GENERATE_TIMEOUT=600 \
OLLAMA_CHAT_TIMEOUT=600 \
ENABLE_REASONING=1 \
bash /home/sansforensics/src/Blitz_DFIR/scripts/sift_e2e_ollama_run.sh
```

## Beginner LLM Evaluation Steps

Use these steps after a completed E2E Ollama run. This evaluates the bounded LLM reasoning layer only. The deterministic Blitz artifacts remain the evidence source of truth.

1. Set the successful session path.

```bash
SESSION=/cases/BLITZ-RD01-PLASO/output/sess-20260530T234654Z-6510c41c
```

2. Run the E2E completion checker.

```bash
CASE=BLITZ-RD01-PLASO bash /home/sansforensics/src/Blitz_DFIR/scripts/blitz_e2e_ollama_check.sh "$SESSION"
```

Expected result:

```text
status=COMPLETED phase=analysis_completed
llm_layer_status=COMPLETED
normalized_events=<count>
accounting_rows=<count>
e2e_ollama_check=passed
```

3. Inspect the LLM reasoning summary.

```bash
CASE=BLITZ-RD01-PLASO bash /home/sansforensics/src/Blitz_DFIR/scripts/blitz_llm_reasoning_summary.sh "$SESSION"
```

Review these fields:

- `provider` and `model`: proves which model produced the explanation.
- `prompt_hash`: proves which bounded prompt was used.
- `token_usage`: records prompt/completion/total token usage when the provider reports it.
- `hypothesis_count` and `decision_count`: shows whether the model generated useful analyst reasoning.
- `raw_evidence_sent=false` and `raw_tool_output_sent=false`: confirms the safety boundary.

4. Judge the local model honestly.

`llama3.2:1b` is acceptable for proving free/local integration and safety plumbing. It is not strong enough to carry professional DFIR conclusions. The submission should say:

```text
Blitz deterministic analysis produces the findings. Ollama explains bounded summaries only. LLM output is labeled INFERRED and is not the evidence source of truth.
```

5. Move to agent orchestration evaluation.

The next layer is not another deterministic scale test. The next layer is proving that OpenClaw can act as the judge-facing agent while Blitz remains the typed forensic safety boundary:

- OpenClaw talks to Windows-hosted Ollama.
- OpenClaw calls the Blitz stdio MCP server.
- OpenClaw requests a typed Blitz tool such as `strings`.
- Blitz rejects anything outside the allowlist, especially generic shell-style requests.
- Logs capture timestamps, model name, provider, tool-call summaries, output hashes, and the rejection of unsafe tool requests.

Run the preflight first:

```bash
cd /home/sansforensics/src/Blitz_DFIR
source .venv/bin/activate

CASE=BLITZ-RD01-PLASO \
OLLAMA_BASE_URL=http://192.168.88.1:11434 \
LLM_MODEL=llama3.2:1b \
bash scripts/blitz_agent_stack_preflight.sh
```

Only after that passes should the same MCP command be registered in OpenClaw for a live agent-driven smoke test.

## Case Layout

Use Protocol SIFT's `/cases` layout, but keep evidence, output, and analysis products separated:

```text
/cases/<CASE>/
  CLAUDE.md
  case.yaml
  evidence/
  processed/
  output/
  analysis/
  exports/
  reports/
```

Evidence should be copied into `evidence/`, hashed, declared in `case.yaml`, and made read-only before analysis.

## Start A Case

```bash
CASE=BLITZ-SMOKE-001

sudo mkdir -p /cases
sudo chown "$USER:$USER" /cases

mkdir -p /cases/${CASE}/{analysis,exports,reports,evidence,processed,output}
cp ~/.claude/case-templates/CLAUDE.md /cases/${CASE}/CLAUDE.md
```

Create a small smoke artifact:

```bash
printf "Blitz manifest smoke evidence\n" > /cases/${CASE}/evidence/smoke.evtx
HASH="$(sha256sum /cases/${CASE}/evidence/smoke.evtx | awk '{print $1}')"

cat > /cases/${CASE}/case.yaml <<EOF
case_id: ${CASE}
evidence_root: evidence
output_root: output
evidence:
  - id: smoke-evtx
    path: smoke.evtx
    type: EVTX
    sha256: ${HASH}
    description: Protocol SIFT case smoke artifact for manifest and audit validation only.
EOF

chmod -R a-w /cases/${CASE}/evidence
```

Run Blitz manifest and audit smoke:

```bash
cd /home/sansforensics/src/Blitz_DFIR
source .venv/bin/activate

python app.py analyze \
  --manifest /cases/BLITZ-SMOKE-001/case.yaml \
  --mode timeline \
  --tool-config /home/sansforensics/src/Blitz_DFIR/config/tools.yaml
```

This runs the full deterministic pipeline. For fake smoke evidence, parser warnings and zero events are acceptable. For real or processed evidence, the command writes reports under the session `reports/` directory.

## Processed PLASO Test

Processed `.plaso` files can be tested without running `log2timeline.py` again. Put the `.plaso` file in the case `processed/` directory, declare it as `type: PLASO`, and let Blitz run the typed `psort` path.

Large PLASO stores should start with the default triage profile. Blitz uses `psort.py -o dynamic`, explicit dynamic output fields, and a high-signal Plaso expression filter such as `data_type contains 'windows:evtx'` for the first pass, rather than exporting every timeline event. Plaso psort filters are not SQL queries, so do not use `SELECT ... LIMIT ...`. Use the full profile only when you deliberately want the slower full export.

```bash
CASE=BLITZ-PLASO-001
PLASO_NAME=your-timeline.plaso

sudo mkdir -p /cases
sudo chown "$USER:$USER" /cases
mkdir -p /cases/${CASE}/{analysis,exports,reports,evidence,processed,output}

cp /path/to/${PLASO_NAME} /cases/${CASE}/processed/${PLASO_NAME}
HASH="$(sha256sum /cases/${CASE}/processed/${PLASO_NAME} | awk '{print $1}')"

cat > /cases/${CASE}/case.yaml <<EOF
case_id: ${CASE}
evidence_root: processed
output_root: output
evidence:
  - id: plaso-timeline
    path: ${PLASO_NAME}
    type: PLASO
    sha256: ${HASH}
    internally_generated: true
    description: Processed PLASO timeline for Blitz deterministic pipeline testing.
EOF

chmod -R a-w /cases/${CASE}/processed

cd /home/sansforensics/src/Blitz_DFIR
source .venv/bin/activate

python app.py analyze \
  --manifest /cases/${CASE}/case.yaml \
  --mode timeline \
  --tool-config /home/sansforensics/src/Blitz_DFIR/config/tools.yaml \
  --psort-profile triage
```

For a deliberate full export, increase the timeout explicitly:

```bash
python app.py analyze \
  --manifest /cases/${CASE}/case.yaml \
  --mode timeline \
  --tool-config /home/sansforensics/src/Blitz_DFIR/config/tools.yaml \
  --psort-profile full \
  --tool-timeout 1800
```

For a focused time window or indicator-driven rerun, keep the triage profile and pass a Plaso filter or slice:

```bash
python app.py analyze \
  --manifest /cases/${CASE}/case.yaml \
  --mode timeline \
  --tool-config /home/sansforensics/src/Blitz_DFIR/config/tools.yaml \
  --psort-profile triage \
  --psort-filter "data_type contains 'windows:evtx'" \
  --tool-timeout 900
```

```bash
python app.py analyze \
  --manifest /cases/${CASE}/case.yaml \
  --mode timeline \
  --tool-config /home/sansforensics/src/Blitz_DFIR/config/tools.yaml \
  --psort-slice "2026-05-20 07:10:00" \
  --psort-slice-size 60 \
  --tool-timeout 900
```

Open the latest HTML report:

```bash
LATEST="$(ls -td /cases/${CASE}/output/sess-* | head -n 1)"
echo "${LATEST}/reports/report.html"
```

If the SIFT desktop has a browser, open that file path in the browser. Otherwise copy `report.html`, `report.json`, and the audit `.ndjson` back to the host for review.

## Register Blitz With Claude Code

Register Blitz as a project-scoped stdio MCP server from the Protocol SIFT case directory. The command uses absolute paths so Claude can launch Blitz from `/cases/<CASE>` without needing the repo installed globally.

```bash
CASE=BLITZ-SMOKE-001
cd /cases/${CASE}

claude mcp add --scope project --transport stdio blitz-dfir -- \
  /home/sansforensics/src/Blitz_DFIR/.venv/bin/python \
  /home/sansforensics/src/Blitz_DFIR/app.py \
  mcp-serve \
  --manifest /cases/${CASE}/case.yaml \
  --tool-config /home/sansforensics/src/Blitz_DFIR/config/tools.yaml

claude mcp list
```

The server creates a new Blitz session each time Claude starts it. Outputs and audit logs are written under the manifest `output_root`, not under `evidence/`.

## Direct MCP Smoke Before Opening Claude

This checks that the stdio MCP server answers `tools/list` and can run a typed `strings` tool call. It does not use Claude yet.

```bash
CASE=BLITZ-SMOKE-001
cd /home/sansforensics/src/Blitz_DFIR
source .venv/bin/activate

printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"strings","arguments":{"evidence_id":"smoke-evtx"}}}' \
  | python app.py mcp-serve \
      --manifest /cases/${CASE}/case.yaml \
      --tool-config /home/sansforensics/src/Blitz_DFIR/config/tools.yaml
```

Expected properties in the third response:

```text
"typed_tool": "strings"
"raw_output_returned": false
"primary_output": "findings/smoke-evtx.strings.txt"
"command_args_hash": "<sha256>"
```

Raw tool stdout is written to the controlled session output directory and is not returned to the model.

## Claude Smoke Prompt

After `claude mcp add` succeeds:

```bash
cd /cases/BLITZ-SMOKE-001
claude
```

Inside Claude Code, run `/mcp` and confirm `blitz-dfir` is connected. Then use this bounded prompt:

```text
Use only the blitz-dfir MCP server. Call the Blitz strings typed tool on evidence_id smoke-evtx. Do not run shell commands. Report only the typed tool result summary, session id, output hashes, and whether raw output was returned.
```

Expected result:

```text
Claude calls the Blitz MCP strings tool.
Claude does not call shell.
The result says raw_output_returned is false.
The result includes session id, hashes, and relative output paths.
The audit log records tool_request_validated and tool_request_completed.
```

## Safety Rules

- Do not copy `~/.claude/.credentials.json` into the repo or any case folder.
- Do not edit Protocol SIFT global files without making a backup.
- Do not broaden Protocol SIFT write permissions into `evidence/`.
- Do not run `pip install --break-system-packages`.
- Do not ask Claude to run generic shell commands for Blitz evidence analysis.
- Do not send raw evidence, raw tool stdout, memory strings, packet dumps, or raw parser exports to any cloud model.

## Interrupted Run Handling

Long forensic jobs must run under `tmux`, `screen`, `nohup`, or another session-preserving wrapper. The `script` command records terminal output, but it does not protect the process if the terminal is closed.

For every long run, verify:

```bash
LATEST="$(ls -td /cases/${CASE}/output/sess-* | head -n 1)"
cat "$LATEST/audit/session_state.json"
test -f "$LATEST/findings/artifact_manifest.json" && python -m json.tool "$LATEST/findings/artifact_manifest.json" | head -n 80
tail -n 20 "$LATEST/audit"/*.ndjson
```

A run is complete only when all of these are true:

- `audit/session_state.json` has `status` set to `COMPLETED`.
- The audit log contains `analysis_completed`.
- `findings/artifact_manifest.json` exists.
- Evidence hashes before and after the run match the case manifest.
- Full-accounting/event-store row counts match exported CSV rows where applicable.

If the process stops before those conditions are true, treat the session as partial. Do not use partial reports as final accuracy evidence.

Hashes and audit chains make tampering visible, but they do not prevent a user with write access from rewriting local files. For judge-grade preservation, copy the final audit log, artifact manifest, report, and evidence hash output off the VM after each completed run.

## Current Gap

The typed MCP boundary, deterministic `app.py analyze` pipeline, full-accounting layer, unknowns layer, and batch-plan artifact are launchable and testable. The remaining judge-facing gaps are:

- Prove a live OpenClaw or Claude Code agent run against Blitz typed tools.
- Record agent execution logs with timestamps, model/provider, token usage, and tool-call summaries.
- Add MCP batch-control endpoints so Protocol SIFT/OpenClaw can call `create_batch_plan`, `get_batch_status`, `run_next_batch`, and `summarize_unknowns` directly instead of invoking a full CLI run.
- Add SIFT tool discovery that marks missing tools as `UNSUPPORTED` instead of failing late.
