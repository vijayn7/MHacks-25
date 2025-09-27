"""Markdown export helpers."""

from __future__ import annotations

from textwrap import dedent

from ..models import Run


def render_markdown(run: Run) -> str:
    """Render a basic markdown representation of a run."""
    header = dedent(
        f"""
        # AegisFlow Report for Run {run.id}

        **Target:** {run.target.url if run.target else 'Unknown'}  
        **Status:** {run.status}
        """
    ).strip()

    findings_md = []
    for finding in run.findings:
        snippet = dedent(
            f"""
            ## {finding.title}
            *Severity:* {finding.severity}  
            *Type:* {finding.type}  
            *Leverage:* {finding.leverage_score}

            Evidence: {finding.evidence or 'n/a'}
            """
        ).strip()
        findings_md.append(snippet)

    body = "\n\n".join(findings_md) if findings_md else "No findings recorded."
    return f"{header}\n\n{body}\n"
