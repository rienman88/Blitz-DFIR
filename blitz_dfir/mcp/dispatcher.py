from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from blitz_dfir.audit.audit_log import AuditLogger
from blitz_dfir.core.models import EvidenceManifest, EvidenceRecord
from blitz_dfir.core.session import CaseSession
from blitz_dfir.exceptions import EvidenceSecurityError, ValidationError
from blitz_dfir.mcp.allowlist import is_allowed_tool
from blitz_dfir.mcp.tool_registry import ToolContext, ToolRegistry


class ToolRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str = Field(min_length=1)
    evidence_id: str = Field(min_length=1)
    params: dict[str, Any] = Field(default_factory=dict)


class ToolDispatcher:
    def __init__(
        self,
        *,
        manifest: EvidenceManifest,
        session: CaseSession,
        registry: ToolRegistry,
        audit: AuditLogger | None = None,
    ) -> None:
        self.manifest = manifest
        self.session = session
        self.registry = registry
        self.audit = audit

    def dispatch(self, request: ToolRequest | dict[str, Any]) -> dict[str, Any]:
        tool_request = request if isinstance(request, ToolRequest) else ToolRequest.model_validate(request)
        if not is_allowed_tool(tool_request.tool):
            self._audit_rejected(tool_request, "tool_not_allowlisted")
            raise ValidationError(f"tool is not allowlisted: {tool_request.tool}")

        evidence = self._get_evidence(tool_request.evidence_id)
        handler = self.registry.get(tool_request.tool)
        context = ToolContext(
            case_id=self.manifest.case_id,
            session_id=self.session.session_id,
            tool_name=tool_request.tool,
            evidence_id=evidence.evidence_id,
            evidence_path=str(evidence.path),
            evidence_type=evidence.evidence_type.value,
            pipeline=evidence.pipeline.value,
        )
        self._audit_requested(tool_request, evidence)
        result = handler(context, tool_request.params)
        self._audit_completed(tool_request, evidence, result)
        return result

    def _get_evidence(self, evidence_id: str) -> EvidenceRecord:
        for record in self.manifest.evidence:
            if record.evidence_id == evidence_id:
                return record
        raise EvidenceSecurityError(f"evidence id is not registered: {evidence_id}")

    def _audit_requested(self, request: ToolRequest, evidence: EvidenceRecord) -> None:
        if self.audit is None:
            return
        self.audit.append(
            "tool_request_validated",
            {
                "tool": request.tool,
                "evidence_id": evidence.evidence_id,
                "evidence_type": evidence.evidence_type.value,
                "pipeline": evidence.pipeline.value,
            },
        )

    def _audit_completed(
        self,
        request: ToolRequest,
        evidence: EvidenceRecord,
        result: dict[str, Any],
    ) -> None:
        if self.audit is None:
            return
        self.audit.append(
            "tool_request_completed",
            {
                "tool": request.tool,
                "evidence_id": evidence.evidence_id,
                "result_keys": sorted(result),
            },
        )

    def _audit_rejected(self, request: ToolRequest, reason: str) -> None:
        if self.audit is None:
            return
        self.audit.append(
            "tool_request_rejected",
            {
                "tool": request.tool,
                "evidence_id": request.evidence_id,
                "reason": reason,
            },
        )
