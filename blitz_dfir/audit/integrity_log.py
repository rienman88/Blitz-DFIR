from __future__ import annotations

from pathlib import Path

from blitz_dfir.audit.audit_log import AuditLogger
from blitz_dfir.audit.execution_trace import correlation_id_for
from blitz_dfir.core.integrity import sha256_file
from blitz_dfir.core.models import EvidenceRecord
from blitz_dfir.tools.provenance import ToolProvenance


def record_evidence_integrity(
    audit: AuditLogger,
    evidence: EvidenceRecord,
    *,
    actual_sha256: str | None = None,
) -> None:
    actual = actual_sha256 or sha256_file(evidence.path)
    audit.append(
        "integrity_check",
        {
            "check_type": "evidence_sha256",
            "evidence_id": evidence.evidence_id,
            "expected_sha256": evidence.sha256,
            "actual_sha256": actual,
            "verified": actual == evidence.sha256.lower(),
            "size_bytes": evidence.size_bytes,
        },
        correlation_id=correlation_id_for(evidence.evidence_id, "integrity"),
    )


def record_tool_integrity(
    audit: AuditLogger,
    *,
    tool_name: str,
    provenance: ToolProvenance,
) -> None:
    audit.append(
        "integrity_check",
        {
            "check_type": "tool_provenance",
            "tool": tool_name,
            "tool_hash": provenance.actual_sha256,
            "tool_hash_expected": provenance.expected_sha256,
            "verified": provenance.verified,
            "warnings": [warning.__dict__ for warning in provenance.warnings],
        },
        correlation_id=correlation_id_for(tool_name, "tool_integrity"),
    )


def record_report_integrity(audit: AuditLogger, report_path: Path) -> None:
    digest = sha256_file(report_path)
    audit.append(
        "integrity_check",
        {
            "check_type": "generated_report_sha256",
            "report_path": report_path,
            "sha256": digest,
            "verified": True,
        },
        correlation_id=correlation_id_for(str(report_path), digest),
    )
