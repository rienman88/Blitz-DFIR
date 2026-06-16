## Architecture And MCP Commands

### Full Architecture Illustration

```mermaid
flowchart TD
    U["Analyst, judge, or MCP client"] --> E["Blitz entrypoint<br/>CLI analyze or MCP server"]

    subgraph B["Blitz control boundary"]
        E --> M["Manifest loading<br/>case_id, evidence_root, output_root, evidence list"]
        M --> H["Evidence integrity check<br/>path validation, type validation, SHA256 verification"]
        H --> S["Case session creation<br/>audit chain, progress state, session state"]
        S --> P["Investigation planning<br/>case objective, batch plan, evidence triage"]
        P --> A["SafeToolAdapter routing<br/>typed tools only, allowlisted commands, controlled output paths"]
    end

    subgraph R["Read-only evidence boundary"]
        EV["User-selected raw evidence<br/>external absolute paths, no raw copy required"]
    end

    subgraph T["SIFT tool execution boundary"]
        V["Volatility<br/>memory plugins"]
        L["log2timeline and psort<br/>E01, DD, Plaso, Windows artifacts"]
        D["disk_triage fallback<br/>Sleuth Kit mmls and fls"]
        O["Optional tools<br/>chainsaw, tshark, yara, strings"]
    end

    A --> EV
    A --> V
    A --> L
    A --> D
    A --> O
    EV -. "read-only input" .-> V
    EV -. "read-only input" .-> L
    EV -. "read-only input" .-> D
    EV -. "read-only input" .-> O

    V --> X["Parser result extraction"]
    L --> X
    D --> X
    O --> X

    subgraph N["Analysis and evidence reasoning boundary"]
        X --> Q["SQLite-backed normalization<br/>batch import, checkpointing, event store"]
        Q --> I["Object inventory and full accounting"]
        I --> C["Correlation and suspicion scoring"]
        C --> G["Investigation guidance<br/>temporal gaps, attack-stage timeline"]
        G --> W["Evidentiary weighting<br/>contradiction analysis, evidence maturity"]
        W --> Y["Validation, unknowns, and coverage"]
    end

    subgraph LLM["Optional LLM explanation boundary"]
        Y --> BR["Bounded evidence summaries only"]
        BR --> LM["OpenAI-compatible LLM<br/>Ollama or provider endpoint"]
        LM --> LV["LLM report verification<br/>unsupported-claim checks"]
    end

    Y --> REP["Report generation"]
    LV --> REP

    subgraph OUT["Output and audit boundary"]
        REP --> RF["reports/<br/>HTML, Markdown, JSON, overall reports, agent journal"]
        REP --> FF["findings/<br/>overall findings, event_store.sqlite, validation, coverage, unknowns"]
        REP --> AU["audit/<br/>progress.json, session_state.json, ndjson audit log, collated audit"]
        REP --> AM["artifact_manifest.json<br/>output hashes and artifact inventory"]
    end

    RF --> J["Judge or analyst review"]
    FF --> J
    AU --> J
    AM --> J

    style R fill:#f7f7f7,stroke:#555,stroke-width:1px
    style B fill:#eef6ff,stroke:#246,stroke-width:1px
    style T fill:#fff7e6,stroke:#864,stroke-width:1px
    style N fill:#eefbf0,stroke:#275,stroke-width:1px
    style LLM fill:#f6efff,stroke:#626,stroke-width:1px
    style OUT fill:#f4f4f4,stroke:#333,stroke-width:1px
```

Architectural guardrails:

- Raw evidence is read through typed tool routes and is not copied by the generic external-evidence runner.
- `evidence_root: external` allows user-selected absolute paths while keeping Blitz output under `/cases/<CASE>/output`.
- Tool execution is routed through `SafeToolAdapter` and `config/tools.yaml`.
- Volatility plugins are explicitly allowlisted.
- Outputs are written to controlled session folders, not back into evidence folders.
- Audit, progress, session state, and artifact hashes are generated as part of the run.

Prompt-based guardrails:

- `CASE_OBJECTIVE` tells Blitz what to investigate and what unsupported conclusions to avoid.
- The LLM receives bounded summaries after deterministic parsing, normalization, correlation, and validation.
- The LLM does not create raw findings by itself; `llm_report_verification` checks whether explanation text stays evidence-backed.

Direct CLI run:

```bash
.venv/bin/python app.py analyze --manifest /cases/<CASE>/case.yaml --tool-config config/tools.yaml --mode timeline
```

MCP server launch:

```bash
.venv/bin/python app.py mcp-serve \
  --manifest /cases/<CASE>/case.yaml \
  --tool-config /home/sansforensics/src/Blitz-DFIR/config/tools.yaml
```

Short architecture flow:

```text
User or MCP client
  -> Blitz CLI/MCP boundary
  -> manifest validation and evidence hash verification
  -> typed SafeToolAdapter allowlist
  -> SIFT tools
  -> parser extraction
  -> SQLite-backed normalization
  -> correlation and suspicion scoring
  -> validation, unknowns, and coverage
  -> optional bounded LLM explanation
  -> report, findings, audit, artifact hashes
```

Security boundaries:

- Raw evidence is read-only input.
- Output must be outside raw evidence folders.
- `evidence_root: external` references user-selected files without copying them.
- Typed tools are selected from `config/tools.yaml`.
- Volatility plugins are allowlisted.
- LLM receives bounded summaries, not raw evidence or raw tool output.
- Audit events, progress state, session state, and artifact hashes are written for traceability.
