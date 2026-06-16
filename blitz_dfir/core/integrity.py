from __future__ import annotations

import hashlib
from pathlib import Path

from blitz_dfir.exceptions import IntegrityError

SHA256_HEX_LENGTH = 64


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_sha256_hex(value: str) -> str:
    lowered = value.lower()
    if len(lowered) != SHA256_HEX_LENGTH:
        raise IntegrityError("sha256 must be 64 hexadecimal characters")
    try:
        int(lowered, 16)
    except ValueError as exc:
        raise IntegrityError("sha256 must be hexadecimal") from exc
    return lowered


def verify_sha256(path: Path, expected_sha256: str) -> str:
    expected = validate_sha256_hex(expected_sha256)
    actual = sha256_file(path)
    if actual != expected:
        raise IntegrityError(f"sha256 mismatch for {path}: expected {expected}, got {actual}")
    return actual

def hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

