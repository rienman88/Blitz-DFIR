from __future__ import annotations

import hashlib

import pytest

from blitz_dfir.core.manifest import load_manifest
from blitz_dfir.core.models import EvidenceCategory, EvidenceType, Pipeline, TrustTier
from blitz_dfir.exceptions import EvidenceSecurityError, IntegrityError, ManifestError, ValidationError


def test_load_manifest_registers_and_verifies_evidence(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    evtx = evidence_root / "Security.evtx"
    evtx.write_bytes(b"evtx")
    digest = hashlib.sha256(b"evtx").hexdigest()
    manifest = tmp_path / "case.yaml"
    manifest.write_text(
        f"""
case_id: case-001
evidence_root: evidence
output_root: output
evidence:
  - id: security
    path: Security.evtx
    type: EVTX
    sha256: {digest}
""".strip(),
        encoding="utf-8",
    )

    loaded = load_manifest(manifest)

    assert loaded.case_id == "case-001"
    assert len(loaded.evidence) == 1
    record = loaded.evidence[0]
    assert record.evidence_id == "security"
    assert record.evidence_type is EvidenceType.EVTX
    assert record.category is EvidenceCategory.RAW
    assert record.pipeline is Pipeline.RAW
    assert record.trust_tier is TrustTier.TIER_1_HIGH
    assert record.verified is True
    assert record.sha256 == digest


def test_load_manifest_accepts_external_absolute_evidence_paths(tmp_path):
    external_root = tmp_path / "uploaded" / "case-data"
    external_root.mkdir(parents=True)
    evtx = external_root / "Security.evtx"
    evtx.write_bytes(b"evtx")
    digest = hashlib.sha256(b"evtx").hexdigest()
    manifest = tmp_path / "case.yaml"
    manifest.write_text(
        f"""
case_id: case-external-001
evidence_root: external
output_root: output
evidence:
  - id: security
    path: "{evtx.as_posix()}"
    type: EVTX
    sha256: {digest}
""".strip(),
        encoding="utf-8",
    )

    loaded = load_manifest(manifest)

    assert loaded.external_evidence is True
    assert loaded.evidence[0].path == evtx.resolve()
    assert loaded.evidence[0].sha256 == digest


def test_load_manifest_classifies_plaso_as_derived_processed_evidence(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    plaso = evidence_root / "case.plaso"
    plaso.write_bytes(b"plaso")
    digest = hashlib.sha256(b"plaso").hexdigest()
    manifest = tmp_path / "case.yaml"
    manifest.write_text(
        f"""
case_id: case-plaso-001
evidence_root: evidence
output_root: output
evidence:
  - id: rd01-plaso
    path: case.plaso
    type: PLASO
    sha256: {digest}
    internally_generated: true
""".strip(),
        encoding="utf-8",
    )

    loaded = load_manifest(manifest)

    record = loaded.evidence[0]
    assert record.evidence_type is EvidenceType.PLASO
    assert record.category is EvidenceCategory.DERIVED
    assert record.pipeline is Pipeline.PROCESSED
    assert record.trust_tier is TrustTier.TIER_2_MEDIUM_HIGH
    assert record.verified is True


def test_load_manifest_accepts_six_mixed_evidence_inputs(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    files = {
        "Security.evtx": (b"evtx", "EVTX"),
        "memory.json": (b"[]", "VOLATILITY_JSON"),
        "yara.txt": (b"SuspiciousRule target.bin\n", "YARA_MATCHES"),
        "strings.txt": (b"powershell -nop\n", "STRINGS_OUTPUT"),
        "timeline.csv": (b"datetime,message\n2026-05-24T00:00:00Z,event\n", "CSV_TIMELINE"),
        "capture.pcap": (b"pcap", "PCAP"),
    }
    evidence_rows: list[str] = []
    for index, (filename, (content, evidence_type)) in enumerate(files.items(), 1):
        (evidence_root / filename).write_bytes(content)
        evidence_rows.append(
            f"""
  - id: evidence-{index}
    path: {filename}
    type: {evidence_type}
    sha256: {hashlib.sha256(content).hexdigest()}
""".rstrip()
        )
    manifest = tmp_path / "case.yaml"
    manifest.write_text(
        f"""
case_id: case-six-inputs
evidence_root: evidence
output_root: output
evidence:
{chr(10).join(evidence_rows)}
""".strip(),
        encoding="utf-8",
    )

    loaded = load_manifest(manifest)

    assert len(loaded.evidence) == 6
    assert loaded.evidence[1].evidence_type is EvidenceType.VOLATILITY_JSON
    assert loaded.evidence[1].category is EvidenceCategory.DERIVED
    assert loaded.evidence[2].evidence_type is EvidenceType.YARA_MATCHES
    assert loaded.evidence[3].evidence_type is EvidenceType.STRINGS_OUTPUT


def test_load_manifest_rejects_more_than_six_evidence_inputs(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    rows: list[str] = []
    for index in range(7):
        filename = f"strings-{index}.txt"
        (evidence_root / filename).write_text(f"value-{index}\n", encoding="utf-8")
        rows.append(
            f"""
  - id: strings-{index}
    path: {filename}
    type: STRINGS_OUTPUT
""".rstrip()
        )
    manifest = tmp_path / "case.yaml"
    manifest.write_text(
        f"""
case_id: case-seven-inputs
evidence_root: evidence
evidence:
{chr(10).join(rows)}
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ManifestError):
        load_manifest(manifest)


def test_manifest_rejects_duplicate_ids(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    (evidence_root / "one.evtx").write_bytes(b"one")
    (evidence_root / "two.evtx").write_bytes(b"two")
    manifest = tmp_path / "case.yaml"
    manifest.write_text(
        """
case_id: case-001
evidence_root: evidence
evidence:
  - id: dup
    path: one.evtx
    type: EVTX
  - id: dup
    path: two.evtx
    type: EVTX
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ManifestError):
        load_manifest(manifest)


def test_manifest_rejects_unknown_schema_fields(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    (evidence_root / "one.evtx").write_bytes(b"one")
    manifest = tmp_path / "case.yaml"
    manifest.write_text(
        """
case_id: case-001
evidence_root: evidence
unexpected: true
evidence:
  - id: one
    path: one.evtx
    type: EVTX
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ManifestError):
        load_manifest(manifest)


def test_manifest_rejects_path_traversal(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    outside = tmp_path / "outside.evtx"
    outside.write_bytes(b"outside")
    manifest = tmp_path / "case.yaml"
    manifest.write_text(
        """
case_id: case-001
evidence_root: evidence
evidence:
  - id: outside
    path: ../outside.evtx
    type: EVTX
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(EvidenceSecurityError):
        load_manifest(manifest)


def test_manifest_rejects_symlink_escape(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    outside = tmp_path / "outside.evtx"
    outside.write_bytes(b"outside")
    link = evidence_root / "link.evtx"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation not available on this platform")
    manifest = tmp_path / "case.yaml"
    manifest.write_text(
        """
case_id: case-001
evidence_root: evidence
evidence:
  - id: linked
    path: link.evtx
    type: EVTX
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(EvidenceSecurityError):
        load_manifest(manifest)


def test_manifest_rejects_missing_file(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    manifest = tmp_path / "case.yaml"
    manifest.write_text(
        """
case_id: case-001
evidence_root: evidence
evidence:
  - id: missing
    path: missing.evtx
    type: EVTX
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(EvidenceSecurityError):
        load_manifest(manifest)


def test_manifest_rejects_hash_mismatch(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    (evidence_root / "Security.evtx").write_bytes(b"evtx")
    manifest = tmp_path / "case.yaml"
    manifest.write_text(
        """
case_id: case-001
evidence_root: evidence
evidence:
  - id: security
    path: Security.evtx
    type: EVTX
    sha256: "0000000000000000000000000000000000000000000000000000000000000000"
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(IntegrityError):
        load_manifest(manifest)


def test_manifest_rejects_detected_type_conflict(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    (evidence_root / "capture.pcap").write_bytes(b"pcap")
    manifest = tmp_path / "case.yaml"
    manifest.write_text(
        """
case_id: case-001
evidence_root: evidence
evidence:
  - id: capture
    path: capture.pcap
    type: EVTX
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValidationError):
        load_manifest(manifest)
