from __future__ import annotations

from pathlib import Path
from typing import Any

from blitz_dfir.core.models import EvidenceRecord, EvidenceType
from blitz_dfir.core.session import CaseSession
from blitz_dfir.tools.base import BuiltCommand, SafeToolAdapter


class PcapAdapter(SafeToolAdapter):
    tool_name = "pcap"
    executable = "tshark"
    output_subdir = "findings"
    output_suffix = ".json"
    stdout_is_primary_output = True
    allowed_evidence_types = frozenset({EvidenceType.PCAP})

    def build_command(
        self,
        *,
        session: CaseSession,
        evidence: EvidenceRecord,
        output_dir: Path,
        params: dict[str, Any],
    ) -> BuiltCommand:
        output_path = output_dir / f"{evidence.evidence_id}.pcap.json"
        command = (
            self.executable,
            "-r",
            str(evidence.path),
            "-T",
            "json",
            "-e",
            "frame.time_epoch",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "tcp.srcport",
            "-e",
            "tcp.dstport",
            "-e",
            "udp.srcport",
            "-e",
            "udp.dstport",
            "-e",
            "dns.qry.name",
            "-e",
            "http.host",
            "-e",
            "tls.handshake.extensions_server_name",
        )
        return BuiltCommand(command=command, primary_output_path=output_path)
