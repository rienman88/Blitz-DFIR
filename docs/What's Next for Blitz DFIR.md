# What's Next for Blitz DFIR

Blitz DFIR currently runs on a small SIFT VM with limited resources, so investigations
are processed one step at a time. That's not because the architecture only supports
sequential execution. It's simply a practical choice for **stability and reliability**
on modest hardware.

Tool outputs are parsed and normalized first, then committed into the SQLite event store
for correlation, validation, and reporting. The pipeline itself doesn't depend on any
particular tool. As forensic capabilities evolve, the underlying investigation
architecture remains the same.

---

## How Blitz Thinks About Evidence

One thing I find interesting is that Blitz doesn't treat evidence as just a pile of files.

**Some evidence belongs together, and some doesn't.**

If memory and disk images come from the same incident, they should be investigated
together because they tell different parts of the same story. But evidence from
unrelated cases shouldn't contaminate each other.

That's where things move beyond simple triage. Individual artifacts tell part of the
story. Correlating related evidence helps investigators see the **bigger picture**.

---

## Seeing the Entire Incident

Imagine several systems involved in the same compromise.

Memory artifacts can be correlated with disk artifacts. Activity observed on one
endpoint can be compared against another. Timelines from multiple systems can be
reconstructed to understand how the incident unfolded.

Instead of examining isolated machines, investigators can start seeing the
**incident as a whole**.

---

## Growing Without Rebuilding

As hardware improves, the same architecture can scale with it.

The goal isn't just faster processing. The goal is **handling larger investigations
without redesigning the platform**.

Future work includes:

- Supporting additional evidence types and forensic capabilities
- Improving cross-source correlation
- Strengthening validation and traceability
- Expanding investigative guidance and evidence maturity analysis
- Enhancing bounded AI-assisted reasoning while preserving evidence-first principles
- Introducing greater parallelism as hardware resources allow
- Supporting larger investigations involving multiple systems and related datasets

Blitz DFIR is designed so that forensic capabilities can evolve over time while the
investigation pipeline remains consistent.

> [!IMPORTANT]
> **Blitz DFIR is built around investigative architecture, not around any specific
> tool. As forensic capabilities evolve, the investigation pipeline remains unchanged.**

---

## Long-Term Vision

The long-term goal is for Blitz DFIR to evolve from a collection of automated forensic
workflows into an **evidence-driven investigation platform**.

Technology will change. Tools will change. AI models will change.

But the foundation remains the same:

> ### Evidence remains the source of truth. Humans remain the final authority.
