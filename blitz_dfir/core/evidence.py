from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Iterator

from blitz_dfir.exceptions import EvidenceSecurityError


def resolve_path_under_root(candidate: Path | str, root: Path | str) -> Path:
    root_path = Path(root).resolve()
    candidate_path = Path(candidate)
    if not candidate_path.is_absolute():
        candidate_path = root_path / candidate_path
    resolved = candidate_path.resolve()
    if not _is_relative_to(resolved, root_path):
        raise EvidenceSecurityError(f"path escapes evidence root: {resolved}")
    return resolved


def ensure_existing_file(path: Path) -> Path:
    if not path.exists():
        raise EvidenceSecurityError(f"evidence file does not exist: {path}")
    if not path.is_file():
        raise EvidenceSecurityError(f"evidence path is not a file: {path}")
    return path


def reject_write_to_evidence(path: Path | str, evidence_root: Path | str) -> None:
    resolved = resolve_path_under_root(path, evidence_root)
    raise EvidenceSecurityError(f"write access to evidence path is forbidden: {resolved}")


@contextmanager
def open_evidence_readonly(path: Path | str, evidence_root: Path | str) -> Iterator[BinaryIO]:
    resolved = ensure_existing_file(resolve_path_under_root(path, evidence_root))
    with resolved.open("rb") as handle:
        yield handle


def _is_relative_to(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False

