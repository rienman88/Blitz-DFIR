from __future__ import annotations

import pytest

from blitz_dfir.exceptions import ValidationError
from blitz_dfir.tools.config import load_tool_config


def test_load_tool_config_reads_expected_hashes_and_allowlists(tmp_path):
    config = tmp_path / "tools.yaml"
    config.write_text(
        """
tools:
  volatility:
    allowed: true
    executable: vol
    version: "3.0"
    expected_sha256: null
    timeout_seconds: 120
    symbols_dir: /cases/volatility_symbols
    allowed_plugins:
      - windows.pslist
  yara:
    allowed: true
    executable: yara
    version: null
    expected_sha256: null
    allowed_rules:
      - rules/safe.yar
""".strip(),
        encoding="utf-8",
    )

    loaded = load_tool_config(config)

    assert loaded.require("volatility").version == "3.0"
    assert loaded.require("volatility").timeout_seconds == 120
    assert loaded.require("volatility").symbols_dir == "/cases/volatility_symbols"
    assert loaded.require("volatility").allowed_plugins == ("windows.pslist",)
    assert loaded.require("yara").allowed_rules == ("rules/safe.yar",)


def test_tool_config_rejects_disabled_tool(tmp_path):
    config = tmp_path / "tools.yaml"
    config.write_text(
        """
tools:
  strings:
    allowed: false
    executable: strings
""".strip(),
        encoding="utf-8",
    )
    loaded = load_tool_config(config)

    with pytest.raises(ValidationError):
        loaded.require("strings")
