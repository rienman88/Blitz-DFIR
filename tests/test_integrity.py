from __future__ import annotations

import hashlib

import pytest

from blitz_dfir.core.integrity import sha256_file, verify_sha256
from blitz_dfir.exceptions import IntegrityError


def test_sha256_file_matches_hashlib(tmp_path):
    evidence = tmp_path / "sample.evtx"
    evidence.write_bytes(b"security events")

    assert sha256_file(evidence) == hashlib.sha256(b"security events").hexdigest()


def test_verify_sha256_rejects_mismatch(tmp_path):
    evidence = tmp_path / "sample.evtx"
    evidence.write_bytes(b"security events")

    with pytest.raises(IntegrityError):
        verify_sha256(evidence, "0" * 64)

