import re
from dataclasses import dataclass
from typing import List, Optional
from .rules import SCAN_RULES, ScanRule


@dataclass
class ScanFinding:
    rule_name: str
    severity: str
    description: str
    matched_text: str
    masked_text: str
    offset: int
    context: str
    direction: str  # "client_to_server" or "server_to_client"


@dataclass
class SessionScanResult:
    session_id: int
    findings: List[ScanFinding]
    total_findings: int
    high_severity_count: int
    medium_severity_count: int

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "total_findings": self.total_findings,
            "high_severity_count": self.high_severity_count,
            "medium_severity_count": self.medium_severity_count,
            "findings": [
                {
                    "rule_name": f.rule_name,
                    "severity": f.severity,
                    "description": f.description,
                    "matched_text": f.masked_text,
                    "offset": f.offset,
                    "context": f.context,
                    "direction": f.direction,
                }
                for f in self.findings
            ],
        }


class SensitiveScanner:
    def __init__(self, rules: Optional[List[ScanRule]] = None):
        self.rules = rules or SCAN_RULES

    def scan_payload(self, payload: bytes, direction: str) -> List[ScanFinding]:
        findings = []
        for rule in self.rules:
            for match in rule.pattern.finditer(payload):
                matched_bytes = match.group(0)
                try:
                    matched_text = matched_bytes.decode('utf-8', errors='replace')
                except Exception:
                    matched_text = matched_bytes.hex()

                context = self._extract_context(payload, match.start(), match.end())

                findings.append(ScanFinding(
                    rule_name=rule.name,
                    severity=rule.severity,
                    description=rule.description,
                    matched_text=matched_text,
                    masked_text=self._mask_text(matched_text),
                    offset=match.start(),
                    context=context,
                    direction=direction,
                ))

        return findings

    def scan_session(self, session_id: int, client_payload: bytes,
                     server_payload: bytes) -> SessionScanResult:
        findings = []

        if client_payload:
            findings.extend(self.scan_payload(client_payload, "client_to_server"))
        if server_payload:
            findings.extend(self.scan_payload(server_payload, "server_to_client"))

        high_count = sum(1 for f in findings if f.severity in ("high", "critical"))
        medium_count = sum(1 for f in findings if f.severity == "medium")

        return SessionScanResult(
            session_id=session_id,
            findings=findings,
            total_findings=len(findings),
            high_severity_count=high_count,
            medium_severity_count=medium_count,
        )

    @staticmethod
    def _mask_text(text: str) -> str:
        if len(text) <= 6:
            return text[:1] + '*' * (len(text) - 1)
        return text[:2] + '*' * (len(text) - 4) + text[-2:]

    @staticmethod
    def _extract_context(data: bytes, start: int, end: int, window: int = 50) -> str:
        ctx_start = max(0, start - window)
        ctx_end = min(len(data), end + window)
        context_bytes = data[ctx_start:ctx_end]
        try:
            return context_bytes.decode('utf-8', errors='replace')
        except Exception:
            return context_bytes.hex()
