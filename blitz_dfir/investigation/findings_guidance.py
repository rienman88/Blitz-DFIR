from __future__ import annotations

from blitz_dfir.correlation.models import AttackStage, CorrelatedFinding
from blitz_dfir.investigation.models import InvestigationGuidanceReport
from blitz_dfir.investigation.tool_graph import recommended_next_tools
from blitz_dfir.investigation.tool_recommendations import TOOL_RECOMMENDATIONS

STAGE_ALIASES = {
    "credential_access": "privilege_or_credential_use",
    "command_and_control": "command_and_control_or_discovery",
    "defense_evasion": "defense_evasion_or_injection",
}


def build_investigation_guidance(
    *,
    findings: tuple[CorrelatedFinding, ...],
    stages: tuple[AttackStage, ...] = (),
) -> InvestigationGuidanceReport:
    recommendations = recommendations_for_findings(findings=findings, stages=stages)
    stage_names = _stage_names(findings=findings, stages=stages)
    recommended_tools = recommended_tools_for_findings(findings=findings, stages=stages)
    categories = tuple(sorted({finding.category.lower() for finding in findings if finding.category}))
    return InvestigationGuidanceReport(
        finding_count=len(findings),
        attack_stage_count=len(stage_names),
        recommendation_count=len(recommendations),
        recommendations=recommendations,
        recommended_tools=recommended_tools,
        attack_stages=stage_names,
        finding_categories=categories,
    )


def recommendations_for_findings(
    *,
    findings: tuple[CorrelatedFinding, ...],
    stages: tuple[AttackStage, ...] = (),
) -> tuple[str, ...]:
    recommendations: set[str] = set()

    for finding in findings:
        category = finding.category.lower()
        if "memory" in category:
            recommendations.add("Review Volatility output, then run or review strings and YARA coverage.")
        if "injection" in category:
            recommendations.add("Review malfind memory regions and correlate injected process context.")
        if "persistence" in category:
            recommendations.add("Review registry, services, startup folders, and scheduled task artifacts.")
        if "network" in category:
            recommendations.add("Correlate network activity with process lineage and command-line evidence.")
        if "credential" in category or "privilege" in category:
            recommendations.add("Review authentication events, privileged logons, and credential-use chains.")

    stage_names = set(_stage_names(findings=findings, stages=stages))
    if "execution" in stage_names:
        recommendations.add("Validate process lineage and parent-child process relationships.")
    if "persistence" in stage_names:
        recommendations.add("Review persistence mechanisms across registry, startup folders, services, and scheduled tasks.")
    if "privilege_or_credential_use" in stage_names:
        recommendations.add("Investigate credential-use activity and related authentication artifacts.")
    if "command_and_control_or_discovery" in stage_names:
        recommendations.add("Review outbound communications and correlate network activity with process execution.")
    if "initial_access_or_lateral_movement" in stage_names:
        recommendations.add("Review logon sources, remote access paths, and lateral-movement indicators.")
    if "defense_evasion_or_injection" in stage_names:
        recommendations.add("Review injected memory regions, unsigned code indicators, and process hollowing candidates.")

    return tuple(sorted(recommendations))


def recommended_tools_for_findings(
    *,
    findings: tuple[CorrelatedFinding, ...],
    stages: tuple[AttackStage, ...] = (),
) -> tuple[str, ...]:

    tools: set[str] = set()

    #
    # Stage-based recommendations
    #
    for stage in _stage_names(
        findings=findings,
        stages=stages,
    ):
        tools.update(
            TOOL_RECOMMENDATIONS.get(
                stage,
                (),
            )
        )

    #
    # Finding-based recommendations
    #
    for finding in findings:

        category = finding.category.lower()

        if "memory" in category:
            tools.update(
                (
                    "memory",
                    "strings",
                    "yara",
                )
            )

        if "injection" in category:
            tools.update(
                (
                    "memory",
                    "strings",
                    "yara",
                )
            )

        if "network" in category:
            tools.update(
                (
                    "pcap",
                    "timeline",
                )
            )

        if "credential" in category:
            tools.update(
                (
                    "events",
                    "timeline",
                )
            )

        if "privilege" in category:
            tools.update(
                (
                    "events",
                    "timeline",
                )
            )

    #
    # Evidence-chain recommendations
    #
    for finding in findings:
        for anchor in finding.evidence:
            tools.update(
                recommended_next_tools(
                    anchor.source_tool
                )
            )

    return tuple(sorted(tools))


def _stage_names(
    *,
    findings: tuple[CorrelatedFinding, ...],
    stages: tuple[AttackStage, ...],
) -> tuple[str, ...]:
    names: set[str] = set()
    for stage in stages:
        names.add(_canonical_stage(stage.stage))
    for finding in findings:
        for stage in finding.attack_stages:
            names.add(_canonical_stage(stage))
    return tuple(sorted(name for name in names if name))


def _canonical_stage(stage: str) -> str:
    value = stage.strip().lower()
    return STAGE_ALIASES.get(value, value)
