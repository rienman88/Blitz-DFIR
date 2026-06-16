from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError as PydanticValidationError

from blitz_dfir.core.evidence import ensure_existing_file, resolve_path_under_root
from blitz_dfir.core.integrity import sha256_file, verify_sha256
from blitz_dfir.core.models import (
    EvidenceManifest,
    EvidenceRecord,
    EvidenceType,
    MAX_MANIFEST_EVIDENCE_INPUTS,
    category_for_evidence_type,
    pipeline_for_evidence_type,
    trust_for_evidence_type,
)
from blitz_dfir.core.validation import validate_detected_type
from blitz_dfir.exceptions import ManifestError


class ManifestEvidenceInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    path: str = Field(min_length=1)
    type: EvidenceType
    sha256: str | None = None
    internally_generated: bool = False
    description: str | None = None


class ManifestInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(min_length=1)
    evidence_root: str = Field(min_length=1)
    output_root: str = "output"
    evidence: list[ManifestEvidenceInput] = Field(min_length=1, max_length=MAX_MANIFEST_EVIDENCE_INPUTS)


def load_manifest(path: Path | str) -> EvidenceManifest:
    source_path = Path(path).resolve()
    try:
        raw = yaml.safe_load(source_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ManifestError(f"manifest not found: {source_path}") from exc
    except yaml.YAMLError as exc:
        raise ManifestError(f"invalid YAML manifest: {source_path}") from exc

    if not isinstance(raw, dict):
        raise ManifestError("manifest must be a YAML mapping")

    try:
        manifest_input = ManifestInput.model_validate(raw)
    except PydanticValidationError as exc:
        raise ManifestError(str(exc)) from exc

    base_dir = source_path.parent
    external_evidence = _is_external_evidence_root(manifest_input.evidence_root)
    evidence_root = base_dir if external_evidence else _resolve_root(base_dir, manifest_input.evidence_root)
    output_root = _resolve_output_root(base_dir, manifest_input.output_root)

    seen_ids: set[str] = set()
    records: list[EvidenceRecord] = []
    for item in manifest_input.evidence:
        if item.id in seen_ids:
            raise ManifestError(f"duplicate evidence id: {item.id}")
        seen_ids.add(item.id)
        if external_evidence:
            resolved_path = _resolve_external_evidence_path(base_dir, item.path)
        else:
            resolved_path = ensure_existing_file(resolve_path_under_root(item.path, evidence_root))
        validate_detected_type(resolved_path, item.type)
        if item.sha256:
            actual_hash = verify_sha256(resolved_path, item.sha256)
        else:
            actual_hash = sha256_file(resolved_path)
        records.append(
            EvidenceRecord(
                evidence_id=item.id,
                path=resolved_path,
                evidence_type=item.type,
                category=category_for_evidence_type(item.type),
                pipeline=pipeline_for_evidence_type(item.type),
                trust_tier=trust_for_evidence_type(item.type, item.internally_generated),
                sha256=actual_hash,
                verified=True,
                size_bytes=resolved_path.stat().st_size,
                internally_generated=item.internally_generated,
                description=item.description,
            )
        )

    return EvidenceManifest(
        case_id=manifest_input.case_id,
        evidence_root=evidence_root,
        output_root=output_root,
        source_path=source_path,
        evidence=tuple(records),
        external_evidence=external_evidence,
    )


def dump_manifest_summary(manifest: EvidenceManifest) -> dict[str, Any]:
    return {
        "case_id": manifest.case_id,
        "source_path": str(manifest.source_path),
        "evidence_root": str(manifest.evidence_root),
        "output_root": str(manifest.output_root),
        "external_evidence": manifest.external_evidence,
        "evidence": [
            {
                "evidence_id": record.evidence_id,
                "path": str(record.path),
                "evidence_type": record.evidence_type.value,
                "category": record.category.value,
                "pipeline": record.pipeline.value,
                "trust_tier": record.trust_tier.value,
                "sha256": record.sha256,
                "verified": record.verified,
                "size_bytes": record.size_bytes,
            }
            for record in manifest.evidence
        ],
    }


def _resolve_root(base_dir: Path, value: str) -> Path:
    root = Path(value)
    if not root.is_absolute():
        root = base_dir / root
    return root.resolve()


def _resolve_output_root(base_dir: Path, value: str) -> Path:
    root = Path(value)
    if not root.is_absolute():
        root = base_dir / root
    return root.resolve()


def _is_external_evidence_root(value: str) -> bool:
    return value.strip().lower() in {"external", "absolute", "external_paths"}


def _resolve_external_evidence_path(base_dir: Path, value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = base_dir / path
    return ensure_existing_file(path.resolve())
