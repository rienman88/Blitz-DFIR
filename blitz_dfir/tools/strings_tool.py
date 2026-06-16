from __future__ import annotations

from pathlib import Path
from typing import Any

from blitz_dfir.core.models import EvidenceRecord
from blitz_dfir.core.session import CaseSession
from blitz_dfir.tools.base import BuiltCommand, SafeToolAdapter


class StringsAdapter(SafeToolAdapter):
    tool_name = "strings"
    executable = "strings"
    output_subdir = "findings"
    output_suffix = ".txt"
    stdout_is_primary_output = True
    allowed_evidence_types = None

    def build_command(
        self,
        *,
        session: CaseSession,
        evidence: EvidenceRecord,
        output_dir: Path,
        params: dict[str, Any],
    ) -> BuiltCommand:
        output_path = output_dir / f"{evidence.evidence_id}.strings.txt"
        return BuiltCommand(
            command=(self.executable, "-a", str(evidence.path)),
            primary_output_path=output_path,
        )
