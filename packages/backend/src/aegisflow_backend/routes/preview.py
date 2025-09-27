"""Preview proxy integration."""

from __future__ import annotations

from fastapi import APIRouter

from ..schemas import PreviewRequest

router = APIRouter(prefix="/apply-preview", tags=["preview"])


@router.post("")
def apply_preview(request: PreviewRequest) -> dict[str, str]:
    """Stub implementation of preview toggle."""
    # In the MVP skeleton we simply acknowledge the request.
    return {"status": "accepted", "run_id": str(request.run_id), "suggestion_id": str(request.suggestion_id)}
