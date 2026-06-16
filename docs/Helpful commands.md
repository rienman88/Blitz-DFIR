## Check Status

By script:

```bash
cd /home/sansforensics/src/Blitz-DFIR
CASE=BLITZ-MY-MEMORY-E01 bash scripts/blitz_status.sh
```

Monitor until done:

```bash
CASE=BLITZ-MY-MEMORY-E01 bash scripts/blitz_monitor_until_done.sh
```

Manual checks:

```bash
CASE=BLITZ-MY-MEMORY-E01
ls -td "/cases/${CASE}/output"/sess-* 2>/dev/null | head -n 1
ls -td "/cases/${CASE}/analysis/runs"/* 2>/dev/null | head -n 1
tail -n 80 "$(ls -td "/cases/${CASE}/analysis/runs"/*/launcher.log 2>/dev/null | head -n 1)"
cat "$(ls -td "/cases/${CASE}/output"/sess-*/audit/progress.json 2>/dev/null | head -n 1)"
```

Check active Blitz/SIFT processes:

```bash
ps -eo pid,ppid,stat,etime,%mem,%cpu,rss,vsz,cmd \
| egrep 'app.py analyze|log2timeline.py|psort.py|tsk_e01_triage.py|(^|[[:space:]/])vol([[:space:]]|$)|(^|[[:space:]/])mmls([[:space:]]|$)|(^|[[:space:]/])fls([[:space:]]|$)|ollama' \
| grep -v grep || true
```

Stop one process only after confirming it is safe:

```bash
kill <PID>
```

Force stop only if normal stop fails:

```bash
kill -9 <PID>
```

Stop known Blitz/SIFT analysis helpers:

```bash
bash scripts/blitz_stop_processes.sh
```

## Continue After A Failed Or Interrupted Run

Use resume only when a session exists and you want Blitz to reuse completed tool/parser work. For a fresh investigation, start a new clean run instead.

Find the latest session:

```bash
CASE=BLITZ-MY-MEMORY-E01
RESUME_SESSION="$(ls -td "/cases/${CASE}/output"/sess-* 2>/dev/null | head -n 1)"
echo "${RESUME_SESSION}"
```

Resume manually:

```bash
cd /home/sansforensics/src/Blitz-DFIR

CASE=BLITZ-MY-MEMORY-E01
RESUME_SESSION="$(ls -td "/cases/${CASE}/output"/sess-* 2>/dev/null | head -n 1)"

.venv/bin/python app.py analyze \
  --manifest "/cases/${CASE}/case.yaml" \
  --resume-session "${RESUME_SESSION}" \
  --mode timeline \
  --tool-config /home/sansforensics/src/Blitz-DFIR/config/tools.yaml \
  --case-objective "Resume analysis of the selected evidence using existing completed tool and parser outputs where available." \
  --enable-reasoning \
  --psort-profile triage \
  --windows-artifact-profile windows-light \
  --tool-timeout 7200 \
  --max-normalized-events 5000000 \
  --max-analysis-events 2000000 \
  --report-event-limit 2000000 \
  --report-finding-limit 2000000 \
  --normalized-export-limit 10000 \
  --parser-record-export-limit 10000 \
  --full-sql-correlation

CASE="${CASE}" bash scripts/blitz_status.sh
```

The public generic helper scripts are clean-run wrappers. For generic resume, use the manual `--resume-session` command above.
