"""Detection normalization layer."""

from __future__ import annotations

from typing import Iterable, List

from ..models import Finding, Run


class DetectionSignal(dict):
    """Small helper to represent detection signals."""

    type: str
    severity: str
    title: str
    evidence: str


def build_findings(run: Run, signals: Iterable[DetectionSignal]) -> List[Finding]:
    """Convert raw detection signals into Finding models."""
    findings: List[Finding] = []
    for signal in signals:
        finding = Finding(
            run_id=run.id,
            type=signal.get("type", "UNKNOWN"),
            severity=signal.get("severity", "INFO"),
            leverage_score=signal.get("leverage", 0.0),
            title=signal.get("title", "Unnamed Finding"),
            evidence=signal.get("evidence"),
            request_snippet=signal.get("request_snippet"),
            response_snippet=signal.get("response_snippet"),
            screenshot_path=signal.get("screenshot"),
        )
        findings.append(finding)
    return findings
