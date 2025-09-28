"""Utilities for preparing scan digests and dispatching Agent Mail notifications."""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

from database import get_findings_by_run, get_scan_run
from models import ScanStatus

logger = logging.getLogger(__name__)

DEFAULT_NOTIFY_EMAIL = os.getenv("DEFAULT_NOTIFY_EMAIL", "vnannapu@umich.edu")
AGENTMAIL_INBOX_ID = os.getenv("AGENTMAIL_INBOX_ID")
AGENTMAIL_API_KEY = os.getenv("AGENTMAIL_API_KEY")

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _coalesce_notify_email(email: Optional[str]) -> Optional[str]:
    if email and email.strip():
        return email.strip()
    return DEFAULT_NOTIFY_EMAIL


async def prepare_scan_digest(run_id: str) -> Dict[str, Any]:
    """Collect metadata and findings for a completed scan run."""

    logger.debug("📋 Fetching scan run data for %s", run_id)
    run = await get_scan_run(run_id)
    if not run:
        logger.error("❌ Scan run %s not found in database", run_id)
        raise ValueError(f"Scan run {run_id} not found")

    logger.debug("🔍 Fetching findings for run %s", run_id)
    findings = await get_findings_by_run(run_id)
    logger.debug("📊 Found %d findings for run %s", len(findings), run_id)

    severity_totals: Dict[str, int] = {}
    highest_severity: Optional[str] = None

    findings_payload = []
    ai_generated_count = 0
    traditional_count = 0

    for finding in findings:
        severity_value = getattr(finding, "severity", "") or ""
        severity = severity_value.lower() if isinstance(severity_value, str) else str(severity_value).lower()
        severity_totals[severity] = severity_totals.get(severity, 0) + 1
        if highest_severity is None:
            highest_severity = severity
        else:
            current_index = SEVERITY_ORDER.index(highest_severity) if highest_severity in SEVERITY_ORDER else len(SEVERITY_ORDER)
            new_index = SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else len(SEVERITY_ORDER)
            if new_index < current_index:
                highest_severity = severity

        # Track AI-generated vs traditional findings
        is_ai_generated = getattr(finding, "ai_generated", False)
        if is_ai_generated:
            ai_generated_count += 1
        else:
            traditional_count += 1

        findings_payload.append(
            {
                "id": finding.id,
                "category": finding.category,
                "title": finding.title,
                "severity": severity_value,
                "description": finding.description,
                "evidence": finding.evidence,
                "fix_snippet": finding.fix_snippet,
                "reproduce_command": finding.reproduce_command,
                "priority_score": finding.priority_score,
                "created_at": finding.created_at.isoformat() if finding.created_at else None,
                "ai_generated": is_ai_generated,
                "owasp_category": getattr(finding, "owasp_category", ""),
                "attack_category": getattr(finding, "attack_category", ""),
            }
        )

    status_value = getattr(run, "status", ScanStatus.COMPLETED.value)
    if isinstance(status_value, ScanStatus):
        status_value = status_value.value

    risk_score = getattr(run, "risk_score", 0) or 0

    digest: Dict[str, Any] = {
        "run_id": run.id,
        "target_url": run.target_url,
        "status": status_value,
        "risk_score": risk_score,
        "created_at": run.created_at.isoformat() if run.created_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "finding_count": len(findings),
        "traditional_findings": traditional_count,
        "ai_generated_findings": ai_generated_count,
        "finding_summary": severity_totals,
        "highest_severity": highest_severity,
        "notify_email": _coalesce_notify_email(getattr(run, "notify_email", None)),
        "consent_ip": getattr(run, "consent_ip", None),
        "max_pages": getattr(run, "max_pages", None),
        "findings": findings_payload,
        "ai_analysis_enabled": ai_generated_count > 0,
    }

    logger.debug("✅ Digest prepared for %s: %d findings, risk score %d, highest severity: %s, target: %s", 
                run_id, len(findings), risk_score, highest_severity or "none", run.target_url)

    return digest


async def dispatch_post_scan_email(run_id: str, *, error_message: Optional[str] = None) -> None:
    """Send the scan summary email through Agent Mail SDK."""

    logger.info("🚀 Starting email dispatch process for run %s%s", 
                run_id, f" (error case: {error_message[:50]}...)" if error_message else "")

    if not AGENTMAIL_INBOX_ID or not AGENTMAIL_API_KEY:
        logger.warning("❌ Agent Mail credentials are not configured; skipping email dispatch for run %s", run_id)
        return

    try:
        logger.debug("📊 Preparing scan digest for run %s", run_id)
        digest = await prepare_scan_digest(run_id)
        logger.debug("✅ Scan digest prepared successfully: %d findings, risk score %s", 
                    digest.get("finding_count", 0), digest.get("risk_score", "unknown"))
    except ValueError as exc:
        logger.error("❌ Unable to build scan digest for %s: %s", run_id, exc)
        return

    if error_message:
        digest["status"] = ScanStatus.FAILED.value
        digest["error"] = error_message
        logger.info("⚠️ Email will report scan failure for run %s", run_id)

    recipient = _coalesce_notify_email(digest.get("notify_email"))
    if not recipient:
        logger.warning("❌ No recipient email resolved for run %s; skipping Agent Mail dispatch", run_id)
        return

    status_value: Any = digest.get("status", ScanStatus.COMPLETED.value)
    if isinstance(status_value, ScanStatus):
        status_value = status_value.value

    subject = f"Swarm scan {status_value} for {digest.get('target_url', '')}".strip()
    
    logger.info("📧 Preparing to send email to %s with subject: '%s'", recipient, subject)

    # Generate email body from the scan digest
    logger.debug("🎨 Generating email HTML body for run %s", run_id)
    email_body = _generate_email_body(digest, error_message)
    body_size_kb = len(email_body.encode('utf-8')) // 1024
    logger.debug("✅ Email body generated: %d KB", body_size_kb)

    try:
        # Import Agent Mail SDK (lazy import to avoid startup issues)
        logger.debug("📦 Importing Agent Mail SDK")
        from agentmail import AsyncAgentMail
        
        logger.debug("🔐 Creating Agent Mail client with inbox ID: %s", AGENTMAIL_INBOX_ID)
        client = AsyncAgentMail(api_key=AGENTMAIL_API_KEY)
        
        logger.info("📤 Sending email via Agent Mail API...")
        await client.inboxes.messages.send(
            inbox_id=AGENTMAIL_INBOX_ID,
            to=recipient,
            subject=subject,
            html=email_body,
        )
        
        logger.info("✅ Agent Mail email successfully sent for run %s to %s (subject: '%s')", 
                   run_id, recipient, subject)
        
    except Exception as exc:
        logger.error("❌ Agent Mail dispatch failed for run %s to %s: %s", run_id, recipient, exc)
        # Log additional context for debugging
        logger.debug("Failed email details - inbox_id: %s, recipient: %s, subject length: %d chars, body size: %d KB", 
                    AGENTMAIL_INBOX_ID, recipient, len(subject), body_size_kb)
        
        # Log specific API error details if available
        if hasattr(exc, 'status_code'):
            logger.error("API Error Details - Status: %d, Body: %s", exc.status_code, getattr(exc, 'body', 'No body'))
        if hasattr(exc, 'headers'):
            logger.debug("API Response Headers: %s", exc.headers)


def _generate_email_body(digest: Dict[str, Any], error_message: Optional[str] = None) -> str:
    """Generate HTML email body from scan digest."""
    
    target_url = digest.get("target_url", "Unknown")
    status = digest.get("status", "unknown")
    finding_count = digest.get("finding_count", 0)
    risk_score = digest.get("risk_score", 0)
    findings = digest.get("findings", [])
    
    if error_message:
        return f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <h2 style="color: #d32f2f;">🚨 Swarm Security Scan Failed</h2>
            <p>We encountered an issue while scanning <strong>{target_url}</strong>:</p>
            <div style="background-color: #ffebee; padding: 15px; border-left: 4px solid #d32f2f; margin: 15px 0;">
                <strong>Error:</strong> {error_message}
            </div>
            <p>Please try running the scan again. If the issue persists, contact our support team.</p>
            <hr style="margin: 20px 0;">
            <p style="font-size: 12px; color: #666;">
                This email was generated by Swarm Security Scanner. 
                For support, please contact us at support@swarm.app
            </p>
        </body>
        </html>
        """
    
    severity_colors = {
        "critical": "#d32f2f",
        "high": "#f57c00", 
        "medium": "#fbc02d",
        "low": "#388e3c",
        "info": "#1976d2"
    }
    
    # Build findings summary
    findings_html = ""
    if findings:
        findings_html = "<h3>🔍 Security Findings</h3>"
        for finding in findings[:5]:  # Show top 5 findings
            severity = finding.get("severity", "unknown").lower()
            color = severity_colors.get(severity, "#666")
            findings_html += f"""
            <div style="border-left: 4px solid {color}; padding: 15px; margin: 10px 0; background-color: #f9f9f9;">
                <h4 style="margin: 0 0 10px 0; color: {color};">
                    {finding.get('title', 'Security Issue')}
                    <span style="background-color: {color}; color: white; padding: 2px 8px; border-radius: 3px; font-size: 11px; margin-left: 10px;">
                        {severity.upper()}
                    </span>
                </h4>
                <p style="margin: 5px 0;">{finding.get('description', 'No description available.')}</p>
                {f'<div style="background-color: #f5f5f5; padding: 10px; margin: 10px 0; font-family: monospace; font-size: 12px; border-radius: 3px;"><strong>Fix:</strong><br>{finding.get("fix_snippet", "No fix snippet available.")}</div>' if finding.get("fix_snippet") else ""}
            </div>
            """
        
        if len(findings) > 5:
            findings_html += f"<p><em>... and {len(findings) - 5} more findings. View the full report in your dashboard.</em></p>"
    else:
        findings_html = """
        <div style="background-color: #e8f5e8; padding: 15px; border-left: 4px solid #4caf50; margin: 15px 0;">
            <h3 style="color: #2e7d32; margin-top: 0;">✅ No Security Issues Found</h3>
            <p>Great news! Our scan didn't detect any security vulnerabilities in your application.</p>
        </div>
        """
    
    return f"""
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto;">
        <div style="background-color: #1976d2; color: white; padding: 20px; text-align: center;">
            <h1 style="margin: 0;">🛡️ Swarm Security Report</h1>
            <p style="margin: 10px 0 0 0;">Security scan completed for {target_url}</p>
        </div>
        
        <div style="padding: 20px;">
            <h2>📊 Scan Summary</h2>
            <div style="display: flex; flex-wrap: wrap; gap: 15px; margin: 15px 0;">
                <div style="background-color: #f5f5f5; padding: 15px; border-radius: 8px; flex: 1; min-width: 120px;">
                    <strong>Status:</strong><br>
                    <span style="color: {'#4caf50' if status == 'completed' else '#d32f2f'}; font-weight: bold;">
                        {status.upper()}
                    </span>
                </div>
                <div style="background-color: #f5f5f5; padding: 15px; border-radius: 8px; flex: 1; min-width: 120px;">
                    <strong>Risk Score:</strong><br>
                    <span style="font-size: 18px; font-weight: bold; color: {'#d32f2f' if risk_score >= 70 else '#f57c00' if risk_score >= 40 else '#4caf50'};">
                        {risk_score}/100
                    </span>
                </div>
                <div style="background-color: #f5f5f5; padding: 15px; border-radius: 8px; flex: 1; min-width: 120px;">
                    <strong>Issues Found:</strong><br>
                    <span style="font-size: 18px; font-weight: bold;">
                        {finding_count}
                    </span>
                </div>
            </div>
            
            {findings_html}
            
            <div style="background-color: #e3f2fd; padding: 15px; border-radius: 8px; margin: 20px 0;">
                <h3 style="margin-top: 0; color: #1976d2;">🛠️ Next Steps</h3>
                <ul style="margin: 10px 0;">
                    <li>Review each finding and prioritize fixes based on severity</li>
                    <li>Implement the suggested code fixes</li>
                    <li>Run another scan to verify the issues are resolved</li>
                    <li>Consider implementing automated security testing in your CI/CD pipeline</li>
                </ul>
            </div>
            
            <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
            
            <p style="font-size: 12px; color: #666; text-align: center;">
                This email was generated automatically by Swarm Security Scanner.<br>
                For support or questions, contact us at support@swarm.app
            </p>
        </div>
    </body>
    </html>
    """


__all__ = ["prepare_scan_digest", "dispatch_post_scan_email"]
