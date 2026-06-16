from __future__ import annotations

from pathlib import Path
from typing import Any

from blitz_dfir.core.models import EvidenceRecord
from blitz_dfir.core.session import CaseSession
from blitz_dfir.exceptions import ValidationError
from blitz_dfir.tools.base import BuiltCommand, SafeToolAdapter, require_string_param


class YaraAdapter(SafeToolAdapter):
    tool_name = "yara"
    executable = "yara"
    output_subdir = "findings"
    output_suffix = ".txt"
    stdout_is_primary_output = True
    allowed_evidence_types = None

    def __init__(
        self,
        *,
        allowed_rules: frozenset[str] | None = None,
        executable: str | None = None,
        expected_sha256: str | None = None,
        integrity_policy: str = "warn",
        default_timeout_seconds: int | None = None,
    ) -> None:
        super().__init__(
            executable=executable,
            expected_sha256=expected_sha256,
            integrity_policy=integrity_policy,
            default_timeout_seconds=default_timeout_seconds,
        )
        self.allowed_rules = allowed_rules or frozenset()

    def build_command(
        self,
        *,
        session: CaseSession,
        evidence: EvidenceRecord,
        output_dir: Path,
        params: dict[str, Any],
    ) -> BuiltCommand:
        rule = require_string_param(params, "rule")
        if rule not in self.allowed_rules:
            raise ValidationError(f"YARA rule is not allowlisted: {rule}")
        output_path = output_dir / f"{evidence.evidence_id}.yara.txt"
        return BuiltCommand(
            command=(self.executable, rule, str(evidence.path)),
            primary_output_path=output_path,
        )
