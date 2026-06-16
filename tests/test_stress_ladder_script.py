from __future__ import annotations

from pathlib import Path


def test_high_volume_stress_ladder_uses_valid_tool_timeout_and_preserves_failure_rc() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    script = (repo_root / "scripts" / "sift_high_volume_stress_ladder.sh").read_text(encoding="utf-8")

    assert 'STRESS_TARGETS="${STRESS_TARGETS:-1000000 2000000 3000000 4000000 5000000}"' in script
    assert 'MAX_SUPPORTED_STRESS_TARGET="${MAX_SUPPORTED_STRESS_TARGET:-5000000}"' in script
    assert "unsupported stress target: target=${target} max_supported=${MAX_SUPPORTED_STRESS_TARGET}" in script
    assert 'TOOL_TIMEOUT="${TOOL_TIMEOUT:-7200}"' in script
    assert "stage=${stage} launcher.log tail:" in script
    assert 'run_stage "${target}"' in script
    assert 'rc="$?"' in script
    assert 'log "target=${target} failed rc=${rc}"' in script
