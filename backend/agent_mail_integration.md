# Agent Mail Integration Guide

This document outlines how to build an internal reporting agent that reads Swarm scan artifacts and sends a follow-up email to customers through [Agent Mail](https://docs.agentmail.to/welcome). The flow leans on the existing FastAPI backend orchestration so that each completed scan automatically produces a high quality narrative that includes remediation advice.

## 1. Understand the existing scan lifecycle

* `run_scan_worker` is the asynchronous orchestrator invoked for every scan request; it updates status, launches the crawler and scanner, populates findings, and marks the run as completed. 【F:backend/main.py†L211-L259】
* `create_demo_findings` shows the structure persisted for each finding, including `fix_snippet` and `reproduce_command` fields that can be reused in outbound communication. 【F:backend/main.py†L261-L333】
* `run_real_scanners` converts the comprehensive security report into stored findings and updates the risk score, which should be summarized in the outbound email. 【F:backend/main.py†L385-L505】

The email agent should trigger after the run status moves to `COMPLETED` (or `FAILED`) inside `run_scan_worker` so it has access to the persisted findings and risk score.

## 2. Shape the report that the agent will read

1. Collect core metadata: target URL, status, timestamps, total findings, and aggregate severity (e.g., highest severity, count per level).
2. Gather each finding’s `category`, `title`, `severity`, `description`, and `fix_snippet`. Include supporting evidence like URLs or headers when it clarifies the recommended fix.
3. Capture operational notes: crawler or scanner errors, duration, and whether demo findings were used.

A helper like `prepare_scan_digest(run_id)` can pull these fields using `get_scan_run` and `get_findings_by_run`, then format them as structured JSON. That digest is the single source of truth for the Agent Mail prompt.

```python
async def prepare_scan_digest(run_id: str) -> dict:
    run = await get_scan_run(run_id)
    findings = await get_findings_by_run(run_id)

    severities = {}
    for finding in findings:
        severities[finding.severity] = severities.get(finding.severity, 0) + 1

    return {
        "run_id": run.id,
        "target_url": run.target_url,
        "notify_email": run.notify_email,
        "status": run.status,
        "risk_score": run.risk_score,
        "created_at": run.created_at.isoformat(),
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "finding_summary": severities,
        "findings": [
            {
                "category": f.category,
                "title": f.title,
                "severity": f.severity,
                "description": f.description,
                "evidence": f.evidence,
                "fix_snippet": f.fix_snippet,
                "reproduce_command": f.reproduce_command,
            }
            for f in findings
        ],
    }
```

## 3. Design the Agent Mail persona

Create a new agent inside Agent Mail with the following framing:

* **Role**: "Security report liaison" that thanks the customer, recaps key findings, and suggests concrete remediation steps.
* **Tone**: Professional and empathetic; acknowledge errors plainly but emphasize actionable fixes.
* **Input contract**: Expect a JSON payload matching the digest above plus any free-form notes (for example `crawler_notes`).
* **Output contract**: Return rendered HTML or Markdown paragraphs suitable for an email body, including a short summary, prioritized findings, and next steps.

Store the agent identifier (or mailbox address) and API key in environment variables such as `AGENTMAIL_AGENT_ID` and `AGENTMAIL_API_KEY` loaded by `python-dotenv` alongside existing settings. 【F:backend/main.py†L9-L24】

## 4. Wire the backend to Agent Mail

1. Install an HTTP client (e.g., `httpx`) in `backend/requirements.txt` if it is not already present.
2. Add a coroutine that posts the digest to Agent Mail and handles retries:

```python
import httpx

AGENTMAIL_API_URL = "https://api.agentmail.to/v1/send"

async def dispatch_post_scan_email(run_id: str):
    digest = await prepare_scan_digest(run_id)
    if not digest.get("findings"):
        return  # Skip empty reports

    payload = {
        "agent_id": os.environ["AGENTMAIL_AGENT_ID"],
        "to": digest.get("notify_email"),
        "subject": f"Swarm Scan Results for {digest['target_url']}",
        "context": {
            "scan": digest,
        },
    }

    headers = {"Authorization": f"Bearer {os.environ['AGENTMAIL_API_KEY']}", "Content-Type": "application/json"}

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(AGENTMAIL_API_URL, json=payload, headers=headers)
        response.raise_for_status()
```

3. Call `dispatch_post_scan_email` at the end of `run_scan_worker` (after status updates) via `asyncio.create_task` so the email does not block the response path. For failure paths, send a pared-down digest that highlights the error message and suggests rerunning the scan.

## 5. Operational checklist

* **Configuration**: Add the Agent Mail variables to `.env` and deployment secrets. Provide a fallback sender (e.g., `reports@swarm.app`).
* **Template testing**: Run a local scan, call `dispatch_post_scan_email` manually, and inspect the generated email to ensure remediation snippets render correctly.
* **Error handling**: Log Agent Mail response codes and surface persistent failures as `scan_failed` events so the frontend can notify operators.
* **Auditing**: Store the email body or Agent Mail message ID for traceability alongside the scan run document.

Following these steps gives every completed scan a consistent narrative that highlights issues, remediation snippets, and follow-up actions without interrupting the existing FastAPI control flow.
