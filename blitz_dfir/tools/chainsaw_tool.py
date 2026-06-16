from __future__ import annotations

from pathlib import Path
from typing import Any

from blitz_dfir.core.models import EvidenceRecord, EvidenceType
from blitz_dfir.core.session import CaseSession
from blitz_dfir.tools.base import BuiltCommand, SafeToolAdapter


class ChainsawAdapter(SafeToolAdapter):
    tool_name = "chainsaw"
    executable = "chainsaw"
    output_subdir = "findings"
    output_suffix = ".json"
    allowed_evidence_types = frozenset({EvidenceType.EVTX})

    def build_command(
        self,
        *,
        session: CaseSession,
        evidence: EvidenceRecord,
        output_dir: Path,
        params: dict[str, Any],
    ) -> BuiltCommand:
        output_path = output_dir / f"{evidence.evidence_id}.chainsaw.json"
        return BuiltCommand(
            command=(self.executable, "hunt", str(evidence.path), "--json", "--output", str(output_path)),
            primary_output_path=output_path,
        )

