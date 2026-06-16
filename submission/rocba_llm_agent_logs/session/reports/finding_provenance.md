# Finding Provenance Visualization

- Case: `BLITZ-ROCBA-MEMORY-E01`
- Session: `sess-20260615T073626Z-5118ee34`
- Traceable findings: `22293/22293`
- Evidence hashes preserved: `True`
- Displayed findings: `10`

This file is generated from `findings/evidence_maturity.json`. It is a visualization of existing provenance, not a separate source of truth.

## Finding 1: `FIND-B5A9D77A3145`

- Title: Long-horizon authentication activity
- Confidence: `0.70`
- Triage score: `0.75`
- Confidence modifiers: `SINGLE_SOURCE_PENALTY`
- Attack stages: `initial_access_or_lateral_movement`
- Trace complete: `True`
- Gaps: none

```mermaid
flowchart LR
  finding_1["Finding<br/>FIND-B5A9D77A3145<br/>confidence 0.70"]
  f1_1_event["Normalized Event<br/>EVT-001AE142328C<br/>disk_file_entry"]
  f1_1_parser["Parser<br/>disk_triage<br/>processed 1117303, malformed 0"]
  f1_1_tool["Tool<br/>disk_triage<br/>exit 0"]
  f1_1_evidence["Evidence<br/>rocba-cdrive-e01<br/>status complete"]
  f1_1_audit["Audit refs<br/>5<br/>gaps none"]
  finding_1 --> f1_1_event
  f1_1_event --> f1_1_parser
  f1_1_parser --> f1_1_tool
  f1_1_tool --> f1_1_evidence
  f1_1_event --> f1_1_audit
```

Why flagged:

- long-horizon activity pattern detected by SQL aggregation across the normalized event store

## Finding 2: `FIND-8EB4A69995FF`

- Title: Long-horizon credential activity
- Confidence: `0.70`
- Triage score: `0.75`
- Confidence modifiers: `SINGLE_SOURCE_PENALTY`
- Attack stages: `privilege_or_credential_use`
- Trace complete: `True`
- Gaps: none

```mermaid
flowchart LR
  finding_2["Finding<br/>FIND-8EB4A69995FF<br/>confidence 0.70"]
  f2_1_event["Normalized Event<br/>EVT-000E8E322781<br/>disk_file_entry"]
  f2_1_parser["Parser<br/>disk_triage<br/>processed 1117303, malformed 0"]
  f2_1_tool["Tool<br/>disk_triage<br/>exit 0"]
  f2_1_evidence["Evidence<br/>rocba-cdrive-e01<br/>status complete"]
  f2_1_audit["Audit refs<br/>5<br/>gaps none"]
  finding_2 --> f2_1_event
  f2_1_event --> f2_1_parser
  f2_1_parser --> f2_1_tool
  f2_1_tool --> f2_1_evidence
  f2_1_event --> f2_1_audit
```

Why flagged:

- long-horizon activity pattern detected by SQL aggregation across the normalized event store

## Finding 3: `FIND-5341587A88A9`

- Title: Long-horizon persistence activity
- Confidence: `0.70`
- Triage score: `0.75`
- Confidence modifiers: `SINGLE_SOURCE_PENALTY`
- Attack stages: `persistence`
- Trace complete: `True`
- Gaps: none

```mermaid
flowchart LR
  finding_3["Finding<br/>FIND-5341587A88A9<br/>confidence 0.70"]
  f3_1_event["Normalized Event<br/>EVT-00108F0043F4<br/>disk_file_entry"]
  f3_1_parser["Parser<br/>disk_triage<br/>processed 1117303, malformed 0"]
  f3_1_tool["Tool<br/>disk_triage<br/>exit 0"]
  f3_1_evidence["Evidence<br/>rocba-cdrive-e01<br/>status complete"]
  f3_1_audit["Audit refs<br/>5<br/>gaps none"]
  finding_3 --> f3_1_event
  f3_1_event --> f3_1_parser
  f3_1_parser --> f3_1_tool
  f3_1_tool --> f3_1_evidence
  f3_1_event --> f3_1_audit
```

Why flagged:

- long-horizon activity pattern detected by SQL aggregation across the normalized event store

## Finding 4: `FIND-B29A4C304CE1`

- Title: MEMORY_INJECTION_CANDIDATE event with memory-process indicators
- Confidence: `0.70`
- Triage score: `1.00`
- Confidence modifiers: `SINGLE_SOURCE_PENALTY`
- Attack stages: `execution, defense_evasion_or_injection`
- Trace complete: `True`
- Gaps: none

```mermaid
flowchart LR
  finding_4["Finding<br/>FIND-B29A4C304CE1<br/>confidence 0.70"]
  f4_1_event["Normalized Event<br/>EVT-0E749282B929<br/>memory_injection_candidate"]
  f4_1_parser["Parser<br/>volatility<br/>processed 16, malformed 0"]
  f4_1_tool["Tool<br/>memory<br/>exit 0"]
  f4_1_evidence["Evidence<br/>rocba-memory<br/>status complete"]
  f4_1_audit["Audit refs<br/>15<br/>gaps none"]
  finding_4 --> f4_1_event
  f4_1_event --> f4_1_parser
  f4_1_parser --> f4_1_tool
  f4_1_tool --> f4_1_evidence
  f4_1_event --> f4_1_audit
```

Why flagged:

- high-signal command or credential-analysis token observed
- memory plugin output indicates possible injected or suspicious memory region
- source event carried parser or signal warnings requiring analyst review

## Finding 5: `FIND-AD63D6A0FB9B`

- Title: MEMORY_INJECTION_CANDIDATE event with memory-process indicators
- Confidence: `0.70`
- Triage score: `1.00`
- Confidence modifiers: `SINGLE_SOURCE_PENALTY`
- Attack stages: `execution, defense_evasion_or_injection`
- Trace complete: `True`
- Gaps: none

```mermaid
flowchart LR
  finding_5["Finding<br/>FIND-AD63D6A0FB9B<br/>confidence 0.70"]
  f5_1_event["Normalized Event<br/>EVT-267C4A910D94<br/>memory_injection_candidate"]
  f5_1_parser["Parser<br/>volatility<br/>processed 16, malformed 0"]
  f5_1_tool["Tool<br/>memory<br/>exit 0"]
  f5_1_evidence["Evidence<br/>rocba-memory<br/>status complete"]
  f5_1_audit["Audit refs<br/>15<br/>gaps none"]
  finding_5 --> f5_1_event
  f5_1_event --> f5_1_parser
  f5_1_parser --> f5_1_tool
  f5_1_tool --> f5_1_evidence
  f5_1_event --> f5_1_audit
```

Why flagged:

- high-signal command or credential-analysis token observed
- memory plugin output indicates possible injected or suspicious memory region
- source event carried parser or signal warnings requiring analyst review

## Finding 6: `FIND-138D1048D1CC`

- Title: MEMORY_INJECTION_CANDIDATE event with memory-process indicators
- Confidence: `0.70`
- Triage score: `1.00`
- Confidence modifiers: `SINGLE_SOURCE_PENALTY`
- Attack stages: `execution, defense_evasion_or_injection`
- Trace complete: `True`
- Gaps: none

```mermaid
flowchart LR
  finding_6["Finding<br/>FIND-138D1048D1CC<br/>confidence 0.70"]
  f6_1_event["Normalized Event<br/>EVT-2821BF5BB5A3<br/>memory_injection_candidate"]
  f6_1_parser["Parser<br/>volatility<br/>processed 16, malformed 0"]
  f6_1_tool["Tool<br/>memory<br/>exit 0"]
  f6_1_evidence["Evidence<br/>rocba-memory<br/>status complete"]
  f6_1_audit["Audit refs<br/>15<br/>gaps none"]
  finding_6 --> f6_1_event
  f6_1_event --> f6_1_parser
  f6_1_parser --> f6_1_tool
  f6_1_tool --> f6_1_evidence
  f6_1_event --> f6_1_audit
```

Why flagged:

- high-signal command or credential-analysis token observed
- memory plugin output indicates possible injected or suspicious memory region
- source event carried parser or signal warnings requiring analyst review

## Finding 7: `FIND-EFAD092B4EF3`

- Title: MEMORY_INJECTION_CANDIDATE event with memory-process indicators
- Confidence: `0.70`
- Triage score: `1.00`
- Confidence modifiers: `SINGLE_SOURCE_PENALTY`
- Attack stages: `execution, defense_evasion_or_injection`
- Trace complete: `True`
- Gaps: none

```mermaid
flowchart LR
  finding_7["Finding<br/>FIND-EFAD092B4EF3<br/>confidence 0.70"]
  f7_1_event["Normalized Event<br/>EVT-31F168B6C43F<br/>memory_injection_candidate"]
  f7_1_parser["Parser<br/>volatility<br/>processed 16, malformed 0"]
  f7_1_tool["Tool<br/>memory<br/>exit 0"]
  f7_1_evidence["Evidence<br/>rocba-memory<br/>status complete"]
  f7_1_audit["Audit refs<br/>15<br/>gaps none"]
  finding_7 --> f7_1_event
  f7_1_event --> f7_1_parser
  f7_1_parser --> f7_1_tool
  f7_1_tool --> f7_1_evidence
  f7_1_event --> f7_1_audit
```

Why flagged:

- high-signal command or credential-analysis token observed
- memory plugin output indicates possible injected or suspicious memory region
- source event carried parser or signal warnings requiring analyst review

## Finding 8: `FIND-E5ADF4155DF5`

- Title: MEMORY_INJECTION_CANDIDATE event with memory-process indicators
- Confidence: `0.70`
- Triage score: `1.00`
- Confidence modifiers: `SINGLE_SOURCE_PENALTY`
- Attack stages: `execution, defense_evasion_or_injection`
- Trace complete: `True`
- Gaps: none

```mermaid
flowchart LR
  finding_8["Finding<br/>FIND-E5ADF4155DF5<br/>confidence 0.70"]
  f8_1_event["Normalized Event<br/>EVT-342A2B3209AE<br/>memory_injection_candidate"]
  f8_1_parser["Parser<br/>volatility<br/>processed 16, malformed 0"]
  f8_1_tool["Tool<br/>memory<br/>exit 0"]
  f8_1_evidence["Evidence<br/>rocba-memory<br/>status complete"]
  f8_1_audit["Audit refs<br/>15<br/>gaps none"]
  finding_8 --> f8_1_event
  f8_1_event --> f8_1_parser
  f8_1_parser --> f8_1_tool
  f8_1_tool --> f8_1_evidence
  f8_1_event --> f8_1_audit
```

Why flagged:

- high-signal command or credential-analysis token observed
- memory plugin output indicates possible injected or suspicious memory region
- source event carried parser or signal warnings requiring analyst review

## Finding 9: `FIND-6265AFED966F`

- Title: MEMORY_INJECTION_CANDIDATE event with memory-process indicators
- Confidence: `0.70`
- Triage score: `1.00`
- Confidence modifiers: `SINGLE_SOURCE_PENALTY`
- Attack stages: `execution, defense_evasion_or_injection`
- Trace complete: `True`
- Gaps: none

```mermaid
flowchart LR
  finding_9["Finding<br/>FIND-6265AFED966F<br/>confidence 0.70"]
  f9_1_event["Normalized Event<br/>EVT-3B1099250470<br/>memory_injection_candidate"]
  f9_1_parser["Parser<br/>volatility<br/>processed 16, malformed 0"]
  f9_1_tool["Tool<br/>memory<br/>exit 0"]
  f9_1_evidence["Evidence<br/>rocba-memory<br/>status complete"]
  f9_1_audit["Audit refs<br/>15<br/>gaps none"]
  finding_9 --> f9_1_event
  f9_1_event --> f9_1_parser
  f9_1_parser --> f9_1_tool
  f9_1_tool --> f9_1_evidence
  f9_1_event --> f9_1_audit
```

Why flagged:

- high-signal command or credential-analysis token observed
- memory plugin output indicates possible injected or suspicious memory region
- source event carried parser or signal warnings requiring analyst review

## Finding 10: `FIND-430D570E3736`

- Title: MEMORY_INJECTION_CANDIDATE event with memory-process indicators
- Confidence: `0.70`
- Triage score: `1.00`
- Confidence modifiers: `SINGLE_SOURCE_PENALTY`
- Attack stages: `execution, defense_evasion_or_injection`
- Trace complete: `True`
- Gaps: none

```mermaid
flowchart LR
  finding_10["Finding<br/>FIND-430D570E3736<br/>confidence 0.70"]
  f10_1_event["Normalized Event<br/>EVT-3BED07E76A40<br/>memory_injection_candidate"]
  f10_1_parser["Parser<br/>volatility<br/>processed 16, malformed 0"]
  f10_1_tool["Tool<br/>memory<br/>exit 0"]
  f10_1_evidence["Evidence<br/>rocba-memory<br/>status complete"]
  f10_1_audit["Audit refs<br/>15<br/>gaps none"]
  finding_10 --> f10_1_event
  f10_1_event --> f10_1_parser
  f10_1_parser --> f10_1_tool
  f10_1_tool --> f10_1_evidence
  f10_1_event --> f10_1_audit
```

Why flagged:

- high-signal command or credential-analysis token observed
- memory plugin output indicates possible injected or suspicious memory region
- source event carried parser or signal warnings requiring analyst review
