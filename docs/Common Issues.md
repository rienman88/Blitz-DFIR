## Common Issues

Manifest not found:

```text
manifest not found: /case.yaml
```

Fix: set `CASE` and use `/cases/<CASE>/case.yaml`.

```bash
CASE=BLITZ-MY-CASE bash scripts/blitz_status.sh
```

Output root inside evidence root:

Use this for external files:

```yaml
evidence_root: external
output_root: /cases/<CASE>/output
```

Do not use `evidence_root: /`.

Validation says `passed=false`:

- This is report/signal validation, not evidence hash validation.
- Evidence hash validation happens at the manifest layer.
- Open `findings/validation.json` to see the issue list.

E01 `log2timeline.py` exits with code `1`:

- Review `findings/tool_results.json`.
- Review `timelines/<evidence>.log2timeline.stderr.txt`.
- Blitz can fall back to `disk_triage` using Sleuth Kit for accessible filesystem metadata.
- Treat fallback output as partial coverage, not full Plaso/VSS coverage.

LLM timeout:

- Check Ollama or provider reachability.
- Run no-LLM first if the LLM is unstable.
- Review `findings/llm_report_verification.json`.

Terminal closes:

- Check active processes.
- Run `CASE=<CASE> bash scripts/blitz_status.sh`.
- If no process is alive, review `audit/progress.json`, `audit/session_state.json`, and the latest launcher log under `/cases/<CASE>/analysis/runs`.

## Cleanup For A Clean Retest

This removes generated run outputs for one case. It does not delete user evidence files referenced from external paths.

Preview:

```bash
cd /home/sansforensics/src/Blitz-DFIR
CASE=BLITZ-MY-CASE bash scripts/sift_clean_generated_for_rerun.sh
```

Apply:

```bash
APPLY=1 CASE=BLITZ-MY-CASE bash scripts/sift_clean_generated_for_rerun.sh
```

Spoliation safety demo:

```bash
.venv/bin/python scripts/blitz_spoliation_demo.py --work-dir /tmp/blitz-spoliation-demo
```


## Developer Quality Gates

Use before packaging or submitting code:

```bash
cd /home/sansforensics/src/Blitz-DFIR
.venv/bin/python -m compileall -q app.py blitz_dfir tests
.venv/bin/python -m pytest -q
```

Optional stricter local checks:

```bash
.venv/bin/python -m ruff check app.py blitz_dfir tests
.venv/bin/python -m mypy app.py blitz_dfir tests
pip-audit -r requirements.txt -r requirements-dev.txt
```
