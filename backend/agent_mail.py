"""Utilities for preparing scan digests and dispatching Agent Mail notifications."""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

import httpx

from database import get_findings_by_run, get_scan_run
from models import ScanStatus

logger = logging.getLogger(__name__)

DEFAULT_NOTIFY_EMAIL = os.getenv("DEFAULT_NOTIFY_EMAIL", "vnannapu@umich.edu")
AGENTMAIL_API_URL = os.getenv("AGENTMAIL_API_URL", "https://api.agentmail.to/v1/send")
AGENTMAIL_AGENT_ID = os.getenv("AGENTMAIL_AGENT_ID")
AGENTMAIL_API_KEY = os.getenv("AGENTMAIL_API_KEY")

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _coalesce_notify_email(email: Optional[str]) -> Optional[str]:
    if email and email.strip():
        return email.strip()
    return DEFAULT_NOTIFY_EMAIL


async def prepare_scan_digest(run_id: str) -> Dict[str, Any]:
    """Collect metadata and findings for a completed scan run."""

    run = await get_scan_run(run_id)
    if not run:
        raise ValueError(f"Scan run {run_id} not found")

    findings = await get_findings_by_run(run_id)

    severity_totals: Dict[str, int] = {}
    highest_severity: Optional[str] = None

    for finding in findings:
        severity = finding.severity.lower()
        severity_totals[severity] = severity_totals.get(severity, 0) + 1
        if highest_severity is None:
            highest_severity = severity
        else:
            current_index = SEVERITY_ORDER.index(highest_severity) if highest_severity in SEVERITY_ORDER else len(SEVERITY_ORDER)
            new_index = SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else len(SEVERITY_ORDER)
            if new_index < current_index:
                highest_severity = severity

    digest: Dict[str, Any] = {
        "run_id": run.id,
        "target_url": run.target_url,
        "status": run.status,
        "risk_score": run.risk_score,
        "created_at": run.created_at.isoformat() if run.created_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "finding_count": len(findings),
        "finding_summary": severity_totals,
        "highest_severity": highest_severity,
        "notify_email": _coalesce_notify_email(getattr(run, "notify_email", None)),
        "consent_ip": getattr(run, "consent_ip", None),
        "max_pages": getattr(run, "max_pages", None),
        "findings": [
            {
                "id": finding.id,
                "category": finding.category,
                "title": finding.title,
                "severity": finding.severity,
                "description": finding.description,
                "evidence": finding.evidence,
                "fix_snippet": finding.fix_snippet,
                "reproduce_command": finding.reproduce_command,
                "priority_score": finding.priority_score,
                "created_at": finding.created_at.isoformat() if finding.created_at else None,
            }
            for finding in findings
        ],
    }

    return digest


async def dispatch_post_scan_email(run_id: str, *, error_message: Optional[str] = None) -> None:
    """Send the scan summary email through Agent Mail."""

    if not AGENTMAIL_AGENT_ID or not AGENTMAIL_API_KEY:
        logger.warning("Agent Mail credentials are not configured; skipping email dispatch for run %s", run_id)
        return

    try:
        digest = await prepare_scan_digest(run_id)
    except ValueError as exc:
        logger.error("Unable to build scan digest for %s: %s", run_id, exc)
        return

    if error_message:
        digest["status"] = ScanStatus.FAILED.value
        digest["error"] = error_message

    recipient = _coalesce_notify_email(digest.get("notify_email"))
    if not recipient:
        logger.warning("No recipient email resolved for run %s; skipping Agent Mail dispatch", run_id)
        return

    status_value: Any = digest.get("status", ScanStatus.COMPLETED.value)
    if isinstance(status_value, ScanStatus):
        status_value = status_value.value

    subject = f"Swarm scan {status_value} for {digest.get('target_url', '')}".strip()

    payload = {
        "agent_id": AGENTMAIL_AGENT_ID,
        "to": recipient,
        "subject": subject,
        "context": {
            "scan": digest,
        },
    }

    headers = {
        "Authorization": f"Bearer {AGENTMAIL_API_KEY}",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(timeout=30) as client:
        try:
            response = await client.post(AGENTMAIL_API_URL, json=payload, headers=headers)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            logger.error("Agent Mail dispatch failed for run %s: %s", run_id, exc)
        else:
            logger.info("Agent Mail dispatched for run %s to %s", run_id, recipient)


__all__ = ["prepare_scan_digest", "dispatch_post_scan_email"]
