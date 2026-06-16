from __future__ import annotations

import hashlib

import pytest

from blitz_dfir.core.manifest import load_manifest
from blitz_dfir.core.session import create_session
from blitz_dfir.exceptions import EvidenceSecurityError


def test_create_session_uses_output_root_outside_evidence(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    evtx = evidence_root / "Security.evtx"
    evtx.write_bytes(b"evtx")
    digest = hashlib.sha256(b"evtx").hexdigest()
    manifest_path = tmp_path / "case.yaml"
    manifest_path.write_text(
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
    manifest = load_manifest(manifest_path)

    session = create_session(manifest)

    assert session.session_root.exists()
    assert session.audit_log_path.parent.exists()
    assert not session.audit_log_path.exists()


def test_create_session_rejects_output_under_evidence_root(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    evtx = evidence_root / "Security.evtx"
    evtx.write_bytes(b"evtx")
    digest = hashlib.sha256(b"evtx").hexdigest()
    manifest_path = tmp_path / "case.yaml"
    manifest_path.write_text(
        f"""
case_id: case-001
evidence_root: evidence
output_root: evidence/output
evidence:
  - id: security
    path: Security.evtx
    type: EVTX
    sha256: {digest}
""".strip(),
        encoding="utf-8",
    )
    manifest = load_manifest(manifest_path)

    with pytest.raises(EvidenceSecurityError):
        create_session(manifest)


def test_create_session_allows_external_evidence_with_separate_output(tmp_path):
    external_root = tmp_path / "uploaded"
    external_root.mkdir()
    evtx = external_root / "Security.evtx"
    evtx.write_bytes(b"evtx")
    digest = hashlib.sha256(b"evtx").hexdigest()
    manifest_path = tmp_path / "case.yaml"
    manifest_path.write_text(
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
    manifest = load_manifest(manifest_path)

    session = create_session(manifest)

    assert session.session_root.exists()


def test_create_session_rejects_external_output_inside_evidence_directory(tmp_path):
    external_root = tmp_path / "uploaded"
    external_root.mkdir()
    evtx = external_root / "Security.evtx"
    evtx.write_bytes(b"evtx")
    digest = hashlib.sha256(b"evtx").hexdigest()
    manifest_path = tmp_path / "case.yaml"
    manifest_path.write_text(
        f"""
case_id: case-external-001
evidence_root: external
output_root: "{(external_root / "output").as_posix()}"
evidence:
  - id: security
    path: "{evtx.as_posix()}"
    type: EVTX
    sha256: {digest}
""".strip(),
        encoding="utf-8",
    )
    manifest = load_manifest(manifest_path)

    with pytest.raises(EvidenceSecurityError):
        create_session(manifest)
