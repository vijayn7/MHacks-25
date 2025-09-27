"""Finding endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ..models import Finding
from ..schemas import FindingSchema
from ..storage.db import session_scope

router = APIRouter(prefix="/finds", tags=["findings"])


@router.get("/{finding_id}", response_model=FindingSchema)
def get_finding(finding_id: int) -> Finding:
    """Return a single finding."""
    with session_scope() as session:
        finding = session.get(Finding, finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        return finding
