from __future__ import annotations

from blitz_dfir.core.models import EvidenceCategory, EvidenceRecord, Pipeline, TrustTier


def provenance_summary(evidence: EvidenceRecord) -> dict[str, str | bool]:
    return {
        "evidence_id": evidence.evidence_id,
        "evidence_type": evidence.evidence_type.value,
        "category": evidence.category.value,
        "pipeline": evidence.pipeline.value,
        "trust_tier": evidence.trust_tier.value,
        "internally_generated": evidence.internally_generated,
        "sanitized": "true",
    }


def is_external_processed(evidence: EvidenceRecord) -> bool:
    return (
        evidence.category is EvidenceCategory.DERIVED
        and evidence.pipeline is Pipeline.PROCESSED
        and evidence.trust_tier is TrustTier.TIER_3_LOW
    )

