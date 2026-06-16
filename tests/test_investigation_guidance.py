from __future__ import annotations

from blitz_dfir.correlation.models import AttackStage, CorrelatedFinding
from blitz_dfir.investigation.findings_guidance import build_investigation_guidance


def _finding(
    *,
    category: str,
    attack_stages: tuple[str, ...],
    source_tool: str = "volatility",
) -> CorrelatedFinding:
    return CorrelatedFinding(
        finding_id=f"FIND-{category}",
        finding_type="test",
        title="test finding",
        summary="test summary",
        category=category,
        supporting_event_ids=("EVT-1",),
        evidence=(),
        confidence=0.55,
        triage_score=0.75,
        suspicion_reasons=("test reason",),
        attack_stages=attack_stages,
    )


def test_investigation_guidance_accepts_blitz_stage_vocabulary() -> None:
    guidance = build_investigation_guidance(
        findings=(
            _finding(category="memory_injection_candidate", attack_stages=("defense_evasion_or_injection",)),
            _finding(category="credential_activity", attack_stages=("credential_access",)),
        ),
        stages=(
            AttackStage(
                stage_id="STAGE-1",
                stage="command_and_control_or_discovery",
                reason="network activity appears",
                supporting_event_ids=(),
                evidence=(),
                confidence=0.35,
            ),
        ),
    )

    assert "defense_evasion_or_injection" in guidance.attack_stages
    assert "privilege_or_credential_use" in guidance.attack_stages
    assert "command_and_control_or_discovery" in guidance.attack_stages
    assert {"memory", "pcap", "strings", "timeline", "yara"}.issubset(set(guidance.recommended_tools))
    assert any("injected memory" in item.lower() for item in guidance.recommendations)
