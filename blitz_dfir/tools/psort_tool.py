from __future__ import annotations

from pathlib import Path
from typing import Any

from blitz_dfir.core.models import EvidenceRecord, EvidenceType
from blitz_dfir.core.session import CaseSession
from blitz_dfir.exceptions import ValidationError
from blitz_dfir.tools.base import BuiltCommand, SafeToolAdapter, optional_int_param, optional_string_param

DEFAULT_DYNAMIC_FIELDS = (
    "datetime",
    "timestamp_desc",
    "source",
    "source_long",
    "message",
    "parser",
    "display_name",
    "tag",
)
DEFAULT_DYNAMIC_FIELD_LIST = ",".join(DEFAULT_DYNAMIC_FIELDS)
DEFAULT_ADDITIONAL_FIELDS = ("data_type",)
DEFAULT_ADDITIONAL_FIELD_LIST = ",".join(DEFAULT_ADDITIONAL_FIELDS)

TRIAGE_WHERE = (
    "data_type contains 'windows:evtx' or "
    "data_type contains 'windows:prefetch' or "
    "data_type contains 'windows:registry' or "
    "data_type contains 'windows:lnk' or "
    "data_type contains 'windows:tasks' or "
    "data_type contains 'firefox' or "
    "data_type contains 'chrome' or "
    "data_type contains 'msiecf'"
)
TRIAGE_FILTER = f"({TRIAGE_WHERE})"


class PsortAdapter(SafeToolAdapter):
    tool_name = "psort"
    executable = "psort.py"
    output_subdir = "timelines"
    output_suffix = ".csv"
    allowed_evidence_types = frozenset({EvidenceType.PLASO})

    def build_command(
        self,
        *,
        session: CaseSession,
        evidence: EvidenceRecord,
        output_dir: Path,
        params: dict[str, Any],
    ) -> BuiltCommand:
        output_path = output_dir / f"{evidence.evidence_id}.csv"
        output_format = _output_format(params)
        filter_expression = _filter_expression(params)
        command = [self.executable, "-q", "-o", output_format, "-w", str(output_path)]
        if output_format == "dynamic":
            command.extend(["--fields", DEFAULT_DYNAMIC_FIELD_LIST])
            command.extend(["--additional_fields", DEFAULT_ADDITIONAL_FIELD_LIST])

        slice_time = _bounded_string_param(params, "slice", max_length=64)
        if slice_time:
            command.extend(["--slice", slice_time])
            slice_size = optional_int_param(params, "slice_size", minimum=1, maximum=1440) or 15
            command.extend(["--slice_size", str(slice_size)])

        command.append(str(evidence.path))
        if filter_expression:
            command.append(filter_expression)
        return BuiltCommand(
            command=tuple(command),
            primary_output_path=output_path,
        )


def _output_format(params: dict[str, Any]) -> str:
    output_format = optional_string_param(params, "output_format") or "dynamic"
    if output_format not in {"dynamic", "l2tcsv"}:
        raise ValidationError("psort output_format must be dynamic or l2tcsv")
    return output_format


def _filter_expression(params: dict[str, Any]) -> str | None:
    explicit = _bounded_string_param(params, "filter", max_length=2048)
    if explicit:
        return explicit
    profile = optional_string_param(params, "profile") or "triage"
    if profile == "full":
        return None
    if profile == "triage":
        return TRIAGE_FILTER
    raise ValidationError("psort profile must be triage or full")


def _bounded_string_param(params: dict[str, Any], key: str, *, max_length: int) -> str | None:
    value = optional_string_param(params, key)
    if value is None:
        return None
    if "\n" in value or "\r" in value:
        raise ValidationError(f"{key} cannot contain line breaks")
    if len(value) > max_length:
        raise ValidationError(f"{key} must be {max_length} characters or less")
    return value
