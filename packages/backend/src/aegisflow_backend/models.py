"""Database models for the AegisFlow backend."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from sqlmodel import Field, Relationship, SQLModel


class Target(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    url: str
    status: str = "pending"
    started_at: datetime | None = None
    finished_at: datetime | None = None

    runs: List["Run"] = Relationship(back_populates="target")


class Run(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    target_id: int = Field(foreign_key="target.id")
    status: str = "queued"
    started_at: datetime | None = None
    finished_at: datetime | None = None

    target: Optional[Target] = Relationship(back_populates="runs")
    findings: List["Finding"] = Relationship(back_populates="run")
    logs: List["RunLog"] = Relationship(back_populates="run")


class Finding(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    run_id: int = Field(foreign_key="run.id")
    type: str
    severity: str
    leverage_score: float = 0.0
    title: str
    evidence: Optional[str] = None
    request_snippet: Optional[str] = None
    response_snippet: Optional[str] = None
    screenshot_path: Optional[str] = None

    run: Optional[Run] = Relationship(back_populates="findings")
    fix_suggestions: List["FixSuggestion"] = Relationship(back_populates="finding")


class FixSuggestion(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    finding_id: int = Field(foreign_key="finding.id")
    framework: str
    snippet: str
    explanation: str

    finding: Optional[Finding] = Relationship(back_populates="fix_suggestions")


class RunLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    run_id: int = Field(foreign_key="run.id")
    agent: str
    event: str
    payload: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    run: Optional[Run] = Relationship(back_populates="logs")
