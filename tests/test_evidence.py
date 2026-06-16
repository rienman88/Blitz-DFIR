from __future__ import annotations

import pytest

from blitz_dfir.core.evidence import open_evidence_readonly, reject_write_to_evidence
from blitz_dfir.exceptions import EvidenceSecurityError


def test_open_evidence_readonly_reads_bytes(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    sample = evidence_root / "sample.evtx"
    sample.write_bytes(b"content")

    with open_evidence_readonly("sample.evtx", evidence_root) as handle:
        assert handle.read() == b"content"


def test_reject_write_to_evidence_always_fails(tmp_path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    sample = evidence_root / "sample.evtx"
    sample.write_bytes(b"content")

    with pytest.raises(EvidenceSecurityError):
        reject_write_to_evidence("sample.evtx", evidence_root)

