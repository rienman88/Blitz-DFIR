from __future__ import annotations

from pathlib import Path
from typing import Any

from blitz_dfir.core.models import EvidenceRecord, EvidenceType
from blitz_dfir.core.session import CaseSession
from blitz_dfir.exceptions import ValidationError
from blitz_dfir.tools.base import BuiltCommand, SafeToolAdapter, optional_string_param


class Log2TimelineAdapter(SafeToolAdapter):
    tool_name = "log2timeline"
    executable = "log2timeline.py"
    output_subdir = "timelines"
    output_suffix = ".plaso"
    allowed_evidence_types = frozenset(
        {
            EvidenceType.E01,
            EvidenceType.DD,
            EvidenceType.EVTX,
            EvidenceType.REGISTRY_HIVE,
            EvidenceType.FILESYSTEM_ARTIFACT,
        }
    )

    def build_command(
        self,
        *,
        session: CaseSession,
        evidence: EvidenceRecord,
        output_dir: Path,
        params: dict[str, Any],
    ) -> BuiltCommand:
        output_path = output_dir / f"{evidence.evidence_id}.plaso"
        logfile_path = output_dir / f"{evidence.evidence_id}.log2timeline.log.gz"
        command = [self.executable, "--logfile", str(logfile_path), "--storage-file", str(output_path)]
        if evidence.evidence_type in {EvidenceType.E01, EvidenceType.DD}:
            command.append(f"--partitions={_safe_option_value(params, 'partitions', default='all')}")
            vss_stores = _safe_option_value(params, "vss_stores", default="none")
            command.append(f"--vss_stores={vss_stores}")
            if vss_stores == "none":
                command.append("--no_vss")
            command.append("--unattended")
        parser_filter = _safe_option_value(params, "parsers", default="")
        if parser_filter:
            command.extend(["--parsers", parser_filter])
        command.append(str(evidence.path))
        return BuiltCommand(
            command=tuple(command),
            primary_output_path=output_path,
        )


def _safe_option_value(params: dict[str, Any], key: str, *, default: str) -> str:
    value = optional_string_param(params, key) or default
    if "\n" in value or "\r" in value:
        raise ValidationError(f"{key} cannot contain line breaks")
    if len(value) > 256:
        raise ValidationError(f"{key} must be 256 characters or less")
    return value
