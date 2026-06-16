# Dataset Documentation

## Dataset

Blitz DFIR was tested against SANS Find Evil / Fred Rocba evidence staged on a SIFT workstation.

The tested case combined:

- One Windows memory image.
- One Windows C-drive E01 disk image.

The raw evidence is not redistributed in this submission packet. The run artifacts preserve the evidence paths, sizes, and SHA-256 hashes for reproducibility.

## Evidence Records

| Evidence ID | Type | Size | SHA-256 | SIFT Path |
| --- | --- | ---: | --- | --- |
| `rocba-memory` | `MEMORY` | `19,050,528,768` bytes | `eb33bdf63730858a805463d171245b233335dd6d89ed458bc681f7d282e10563` | `/cases/BLITZ-ROCBA-MEMORY/raw/Rocba-Memory.raw` |
| `rocba-cdrive-e01` | `E01` | `23,678,691,658` bytes | `f2eb856d6fb48e3928e6b6d388b2f116a57b735137354a7eaddca951d81b5c67` | `/cases/Rocba-E01/rocba-cdrive.e01` |

Both evidence records were manifest-registered and verified before tool execution.

## Run Objective

The run objective was:

`Analyze Rocba memory and C-drive E01 together for evidence-backed suspicious processes, execution artifacts, persistence indicators, credential activity, user activity, temporal gaps, cross-source correlation, and unknowns while avoiding unsupported conclusions.`

## Tools Used

Memory:

- Volatility `windows.pslist`
- Volatility `windows.pstree`
- Volatility `windows.cmdline`
- Volatility `windows.psscan`
- Volatility `windows.netscan`
- Volatility `windows.malfind`

Disk:

- Plaso `log2timeline.py` attempted full E01 timeline extraction.
- Sleuth Kit fallback disk triage ran after Plaso/dfVFS failed.

## What The Agent Found

Blitz produced:

- `1,124,391` normalized events.
- `22,293` evidence-backed findings selected for analyst review.
- `16` defense-evasion or memory-injection findings.
- `143` persistence-stage findings.
- `61` privilege or credential-use-stage findings.
- `13` initial access or lateral movement-stage findings.
- `21,496` execution-stage findings, mostly disk-derived candidates from fallback disk triage.

The high finding count should be interpreted as triage volume, not as a claim that every item is malicious.

## Key Evidence Themes

- Volatility `malfind` identified suspicious executable memory regions, including `PAGE_EXECUTE_READWRITE` regions in `MsMpEng.exe`.
- Disk fallback surfaced execution and persistence review candidates from filesystem metadata.
- Investigation guidance recommended follow-up with events, memory, strings, timeline, and YARA review.

## Known Dataset Coverage Limits

The run did not have clean full timeline coverage because Plaso/dfVFS failed on the E01 VSS parsing path. Blitz preserved this in validation and unknowns instead of suppressing it.

Expected artifact families not fully observed in this run included EVTX, Registry, SRUM, USB artifacts, Windows Timeline, and full Plaso timeline coverage.

