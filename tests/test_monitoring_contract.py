from __future__ import annotations

import ast
import re
from pathlib import Path

from blitz_dfir.audit.progress import PROGRESS_LAYERS


def test_status_monitor_layer_contract_matches_progress_layers() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    status_script = repo_root / "scripts" / "blitz_status.sh"
    text = status_script.read_text(encoding="utf-8")

    match = re.search(r"LAYERS = \(\n(?P<body>.*?)\n\)", text, re.DOTALL)
    assert match, "scripts/blitz_status.sh must define a Python LAYERS tuple"

    monitor_layers = ast.literal_eval("(" + match.group("body") + ")")
    assert monitor_layers == PROGRESS_LAYERS
