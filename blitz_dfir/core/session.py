from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from blitz_dfir.core.evidence import _is_relative_to
from blitz_dfir.core.models import EvidenceManifest
from blitz_dfir.exceptions import EvidenceSecurityError


@dataclass(frozen=True)
class CaseSession:
    case_id: str
    session_id: str
    session_root: Path
    reports_dir: Path
    audit_dir: Path
    findings_dir: Path
    timelines_dir: Path
    audit_log_path: Path


def create_session(manifest: EvidenceManifest) -> CaseSession:
    if not manifest.external_evidence and _is_relative_to(manifest.output_root, manifest.evidence_root):
        raise EvidenceSecurityError("output root cannot be inside evidence root")
    for evidence in manifest.evidence:
        evidence_parent = evidence.path.parent.resolve()
        if _is_relative_to(manifest.output_root, evidence_parent):
            raise EvidenceSecurityError(f"output root cannot be inside evidence directory: {evidence_parent}")
        if _is_relative_to(evidence_parent, manifest.output_root):
            raise EvidenceSecurityError(f"evidence directory cannot be inside output root: {evidence_parent}")

    session_id = _new_session_id()
    session_root = manifest.output_root / session_id
    reports_dir = session_root / "reports"
    audit_dir = session_root / "audit"
    findings_dir = session_root / "findings"
    timelines_dir = session_root / "timelines"
    for directory in (reports_dir, audit_dir, findings_dir, timelines_dir):
        directory.mkdir(parents=True, exist_ok=False)

    return CaseSession(
        case_id=manifest.case_id,
        session_id=session_id,
        session_root=session_root,
        reports_dir=reports_dir,
        audit_dir=audit_dir,
        findings_dir=findings_dir,
        timelines_dir=timelines_dir,
        audit_log_path=audit_dir / f"{session_id}.ndjson",
    )


def load_existing_session(manifest: EvidenceManifest, session_root: Path) -> CaseSession:
    root = session_root.resolve()
    output_root = manifest.output_root.resolve()
    if not _is_relative_to(root, output_root):
        raise EvidenceSecurityError(f"resume session is outside output root: {root}")
    if not root.is_dir():
        raise EvidenceSecurityError(f"resume session does not exist: {root}")

    session_id = root.name
    if not session_id.startswith("sess-"):
        raise EvidenceSecurityError(f"resume session is not a Blitz session directory: {root}")

    reports_dir = root / "reports"
    audit_dir = root / "audit"
    findings_dir = root / "findings"
    timelines_dir = root / "timelines"
    for directory in (reports_dir, audit_dir, findings_dir, timelines_dir):
        directory.mkdir(parents=True, exist_ok=True)

    audit_log_path = audit_dir / f"{session_id}.ndjson"
    if not audit_log_path.exists():
        audit_files = sorted(audit_dir.glob("*.ndjson"))
        if audit_files:
            audit_log_path = audit_files[0]

    return CaseSession(
        case_id=manifest.case_id,
        session_id=session_id,
        session_root=root,
        reports_dir=reports_dir,
        audit_dir=audit_dir,
        findings_dir=findings_dir,
        timelines_dir=timelines_dir,
        audit_log_path=audit_log_path,
    )


def _new_session_id() -> str:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"sess-{timestamp}-{uuid4().hex[:8]}"
