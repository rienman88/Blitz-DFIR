from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from blitz_dfir.core.models import EvidenceRecord, EvidenceType
from blitz_dfir.core.session import CaseSession
from blitz_dfir.tools.base import BuiltCommand, SafeToolAdapter, optional_int_param


class DiskTriageAdapter(SafeToolAdapter):
    tool_name = "disk_triage"
    executable = "python3"
    output_subdir = "findings"
    output_suffix = ".disk_triage.json"
    allowed_evidence_types = frozenset({EvidenceType.E01, EvidenceType.DD})

    def build_command(
        self,
        *,
        session: CaseSession,
        evidence: EvidenceRecord,
        output_dir: Path,
        params: dict[str, Any],
    ) -> BuiltCommand:
        output_path = output_dir / f"{evidence.evidence_id}.disk_triage.json"
        script_path = Path(__file__).resolve().parents[2] / "scripts" / "tsk_e01_triage.py"
        max_partitions = optional_int_param(params, "max_partitions", minimum=1, maximum=64) or _env_int(
            "BLITZ_DISK_TRIAGE_MAX_PARTITIONS", 8
        )
        max_entries = optional_int_param(params, "max_entries", minimum=100, maximum=20_000_000) or _env_int(
            "BLITZ_DISK_TRIAGE_MAX_ENTRIES", 3_000_000
        )
        max_seconds = optional_int_param(params, "max_seconds_per_partition", minimum=30, maximum=7200) or _env_int(
            "BLITZ_DISK_TRIAGE_SECONDS_PER_PARTITION", 1800
        )
        return BuiltCommand(
            command=(
                self.executable,
                str(script_path),
                "--evidence",
                str(evidence.path),
                "--output",
                str(output_path),
                "--max-partitions",
                str(max_partitions),
                "--max-entries",
                str(max_entries),
                "--max-seconds-per-partition",
                str(max_seconds),
            ),
            primary_output_path=output_path,
        )


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, ""))
    except ValueError:
        return default
