"""Report export routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Response

from ..models import Run
from ..schemas import ExportResponse
from ..services import reporter
from ..storage.db import session_scope

router = APIRouter(prefix="/export", tags=["export"])


@router.get("/{run_id}")
def export_run(run_id: int) -> Response:
    """Export run findings as Markdown."""
    with session_scope() as session:
        run = session.get(Run, run_id)
        if not run:
            raise HTTPException(status_code=404, detail="Run not found")
        markdown = reporter.render_markdown(run)
        return Response(content=markdown, media_type="text/markdown")
