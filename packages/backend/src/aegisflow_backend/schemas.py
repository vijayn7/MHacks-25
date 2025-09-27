"""Pydantic models for API IO."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


class FixSuggestionSchema(BaseModel):
    id: int
    framework: str
    snippet: str
    explanation: str

    class Config:
        orm_mode = True


class FindingSchema(BaseModel):
    id: int
    run_id: int
    type: str
    severity: str
    leverage_score: float
    title: str
    evidence: Optional[str]
    request_snippet: Optional[str]
    response_snippet: Optional[str]
    screenshot_path: Optional[str]
    fix_suggestions: List[FixSuggestionSchema] = []

    class Config:
        orm_mode = True


class RunSchema(BaseModel):
    id: int
    target_id: int
    status: str
    started_at: Optional[datetime]
    finished_at: Optional[datetime]

    class Config:
        orm_mode = True


class TargetSchema(BaseModel):
    id: int
    url: str
    status: str
    started_at: Optional[datetime]
    finished_at: Optional[datetime]

    class Config:
        orm_mode = True


class RunCreate(BaseModel):
    url: str


class RunStatus(BaseModel):
    run: RunSchema
    target: TargetSchema


class RunFindingsResponse(BaseModel):
    run: RunSchema
    findings: List[FindingSchema]


class ExportResponse(BaseModel):
    content_type: str
    content: bytes


class PreviewRequest(BaseModel):
    run_id: int
    suggestion_id: int
