from __future__ import annotations

from collections.abc import Mapping
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from blitz_dfir.core.models import EvidenceType, SignalWarning
from blitz_dfir.signal.warnings import low_coverage_warning, missing_artifact_warning, partial_extraction_warning

MVP_ARTIFACT_TYPES = ("EVTX", "Registry", "Memory", "Browser Artifacts", "Timeline", "PCAP")


class AnalysisGap(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    reason: str
    impact: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"
    metadata: dict[str, object] = Field(default_factory=dict)


class ArtifactCoverage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact_type: str
    observed: int = Field(ge=0)
    expected: int | None = Field(default=None, ge=0)
    coverage: float = Field(ge=0.0, le=1.0)
    missing_sources: tuple[str, ...] = ()
    warnings: tuple[SignalWarning, ...] = ()
    analysis_gaps: tuple[AnalysisGap, ...] = ()


class CoverageReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    per_artifact: dict[str, ArtifactCoverage]
    overall_case_coverage: float = Field(ge=0.0, le=1.0)
    warnings: tuple[SignalWarning, ...] = ()
    analysis_gaps: tuple[AnalysisGap, ...] = ()


def coverage_from_counts(
    *,
    artifact_type: str,
    observed: int,
    expected: int | None,
    low_threshold: float = 0.75,
) -> ArtifactCoverage:
    if expected is None:
        coverage = 1.0 if observed > 0 else 0.0
    elif expected == 0:
        coverage = 1.0
    else:
        coverage = min(observed / expected, 1.0)
    warnings: list[SignalWarning] = []
    gaps: list[AnalysisGap] = []
    if expected and observed < expected:
        warnings.append(
            partial_extraction_warning(
                artifact=artifact_type,
                processed=observed,
                expected=expected,
                source=artifact_type,
            )
        )
        gaps.append(
            AnalysisGap(
                source=artifact_type,
                reason="partial extraction",
                impact=f"{expected - observed} expected units were not observed",
                metadata={"observed": observed, "expected": expected},
            )
        )
    if coverage < low_threshold:
        warnings.append(low_coverage_warning(artifact=artifact_type, coverage=coverage))
    return ArtifactCoverage(
        artifact_type=artifact_type,
        observed=observed,
        expected=expected,
        coverage=coverage,
        warnings=tuple(warnings),
        analysis_gaps=tuple(gaps),
    )


def timeline_source_coverage(
    *,
    artifact: str,
    present_sources: set[str],
    expected_sources: set[str],
) -> ArtifactCoverage:
    missing = tuple(sorted(expected_sources - present_sources))
    observed = len(present_sources & expected_sources)
    expected = len(expected_sources)
    base = coverage_from_counts(artifact_type=artifact, observed=observed, expected=expected)
    warnings = list(base.warnings)
    gaps = list(base.analysis_gaps)
    for source in missing:
        warnings.append(missing_artifact_warning(artifact=artifact, missing_source=source))
        gaps.append(
            AnalysisGap(
                source=source,
                reason="missing expected timeline source",
                impact=f"{source} data unavailable in processed timeline",
            )
        )
    return ArtifactCoverage(
        artifact_type=artifact,
        observed=observed,
        expected=expected,
        coverage=base.coverage,
        missing_sources=missing,
        warnings=tuple(warnings),
        analysis_gaps=tuple(gaps),
    )


def memory_region_coverage(*, processed_regions: int, total_regions: int) -> ArtifactCoverage:
    return coverage_from_counts(
        artifact_type="Memory",
        observed=processed_regions,
        expected=total_regions,
    )


def missing_artifact_coverage(*, artifact_type: str, expected_source: str | None = None) -> ArtifactCoverage:
    source = expected_source or artifact_type
    warning = missing_artifact_warning(artifact=artifact_type, missing_source=source)
    gap = AnalysisGap(
        source=source,
        reason="missing expected artifact",
        impact=f"{artifact_type} data was expected but not observed",
    )
    low_warning = low_coverage_warning(artifact=artifact_type, coverage=0.0)
    return ArtifactCoverage(
        artifact_type=artifact_type,
        observed=0,
        expected=1,
        coverage=0.0,
        missing_sources=(source,),
        warnings=(warning, low_warning),
        analysis_gaps=(gap,),
    )


def coverage_report_from_expected_artifacts(
    *,
    observed_counts: Mapping[str, int],
    expected_counts: Mapping[str, int | None],
    artifact_types: tuple[str, ...] = MVP_ARTIFACT_TYPES,
) -> CoverageReport:
    coverages: list[ArtifactCoverage] = []
    for artifact_type in artifact_types:
        if artifact_type not in observed_counts and artifact_type not in expected_counts:
            coverages.append(missing_artifact_coverage(artifact_type=artifact_type))
            continue
        coverages.append(
            coverage_from_counts(
                artifact_type=artifact_type,
                observed=observed_counts.get(artifact_type, 0),
                expected=expected_counts.get(artifact_type),
            )
        )
    return build_coverage_report(coverages)


def expected_artifact_key(evidence_type: EvidenceType) -> str:
    mapping = {
        EvidenceType.EVTX: "EVTX",
        EvidenceType.REGISTRY_HIVE: "Registry",
        EvidenceType.MEMORY: "Memory",
        EvidenceType.PLASO: "Timeline",
        EvidenceType.CSV_TIMELINE: "Timeline",
        EvidenceType.VOLATILITY_JSON: "Memory",
        EvidenceType.YARA_MATCHES: "YARA",
        EvidenceType.STRINGS_OUTPUT: "Strings",
        EvidenceType.PCAP: "PCAP",
        EvidenceType.FILESYSTEM_ARTIFACT: "Filesystem",
        EvidenceType.E01: "Disk Image",
        EvidenceType.DD: "Disk Image",
    }
    return mapping.get(evidence_type, evidence_type.value)


def build_coverage_report(coverages: list[ArtifactCoverage]) -> CoverageReport:
    per_artifact = {coverage.artifact_type: coverage for coverage in coverages}
    if coverages:
        overall = sum(coverage.coverage for coverage in coverages) / len(coverages)
    else:
        overall = 0.0
    warnings = tuple(warning for coverage in coverages for warning in coverage.warnings)
    gaps = tuple(gap for coverage in coverages for gap in coverage.analysis_gaps)
    return CoverageReport(
        per_artifact=per_artifact,
        overall_case_coverage=overall,
        warnings=warnings,
        analysis_gaps=gaps,
    )
