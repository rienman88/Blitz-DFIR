from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from blitz_dfir.core.models import EvidenceRecord, EvidenceType
from blitz_dfir.core.session import CaseSession
from blitz_dfir.exceptions import ValidationError
from blitz_dfir.tools.base import BuiltCommand, SafeToolAdapter, ensure_relative_name, require_string_param

DEFAULT_ALLOWED_PLUGINS = frozenset(
    {
        "windows.pslist",
        "windows.pstree",
        "windows.cmdline",
        "windows.psscan",
        "windows.netscan",
        "windows.malfind",
    }
)


def _resolve_symbols_dir(
    *,
    configured: str | Path | None,
    session: CaseSession,
) -> Path:
    candidates = [
        configured,
        os.environ.get("VOLATILITY_SYMBOLS"),
        os.environ.get("BLITZ_SYMBOLS_DIR"),
        *_sift_symbol_dir_candidates(),
        session.session_root.parent.parent / "volatility_symbols",
        session.session_root / "volatility_symbols",
        Path.home() / ".volatility3" / "symbols",
    ]
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        try:
            path.mkdir(parents=True, exist_ok=True)
            probe = path / ".blitz_write_probe"
            probe.touch()
            probe.unlink()
        except OSError:
            continue
        return path
    raise ValidationError("no writable Volatility symbols directory is available")


def _sift_symbol_dir_candidates() -> tuple[str, ...]:
    if os.name == "nt":
        return ()
    return ("/cases/volatility_symbols",)


class VolatilityAdapter(SafeToolAdapter):
    tool_name = "volatility"
    executable = "vol"
    output_subdir = "findings"
    output_suffix = ".json"
    stdout_is_primary_output = True
    allowed_evidence_types = frozenset({EvidenceType.MEMORY})

    def __init__(
        self,
        *,
        allowed_plugins: frozenset[str] | None = None,
        executable: str | None = None,
        expected_sha256: str | None = None,
        integrity_policy: str = "warn",
        default_timeout_seconds: int | None = None,
        symbols_dir: str | Path | None = None,
    ) -> None:
        super().__init__(
            executable=executable,
            expected_sha256=expected_sha256,
            integrity_policy=integrity_policy,
            default_timeout_seconds=default_timeout_seconds,
        )
        self.allowed_plugins = allowed_plugins or DEFAULT_ALLOWED_PLUGINS
        self.symbols_dir = symbols_dir

    def build_command(
        self,
        *,
        session: CaseSession,
        evidence: EvidenceRecord,
        output_dir: Path,
        params: dict[str, Any],
    ) -> BuiltCommand:
        plugin = require_string_param(params, "plugin")
        if plugin not in self.allowed_plugins:
            raise ValidationError(f"volatility plugin is not allowlisted: {plugin}")
        safe_plugin = ensure_relative_name(plugin.replace(".", "_"), field="plugin")
        output_path = output_dir / f"{evidence.evidence_id}.{safe_plugin}.json"
        symbols_dir = _resolve_symbols_dir(configured=self.symbols_dir, session=session)
        return BuiltCommand(
            command=(
                self.executable,
                "-q",
                "--symbol-dirs",
                str(symbols_dir),
                "-f",
                str(evidence.path),
                "-r",
                "json",
                plugin,
            ),
            primary_output_path=output_path,
        )
