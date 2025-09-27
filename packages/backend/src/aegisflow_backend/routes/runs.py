"""Run-related API routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ..models import Run, Target
from ..schemas import RunCreate, RunFindingsResponse, RunSchema, RunStatus
from ..storage.db import session_scope

router = APIRouter(prefix="/runs", tags=["runs"])


@router.post("", response_model=RunSchema)
def start_run(payload: RunCreate) -> Run:
    """Create a new scan run for the given URL."""
    with session_scope() as session:
        target = Target(url=payload.url, status="queued")
        session.add(target)
        session.flush()

        run = Run(target_id=target.id, status="queued")
        session.add(run)
        session.flush()
        session.refresh(run)
        session.refresh(target)
        return run


@router.get("/{run_id}", response_model=RunStatus)
def get_run(run_id: int) -> RunStatus:
    """Return run status metadata."""
    with session_scope() as session:
        run = session.get(Run, run_id)
        if not run:
            raise HTTPException(status_code=404, detail="Run not found")
        target = session.get(Target, run.target_id)
        if not target:
            raise HTTPException(status_code=500, detail="Target missing for run")
        return RunStatus(run=run, target=target)


@router.get("/{run_id}/finds", response_model=RunFindingsResponse)
def get_run_findings(run_id: int) -> RunFindingsResponse:
    """Return findings for a run."""
    with session_scope() as session:
        run = session.get(Run, run_id)
        if not run:
            raise HTTPException(status_code=404, detail="Run not found")
        findings = list(run.findings)
        return RunFindingsResponse(run=run, findings=findings)
