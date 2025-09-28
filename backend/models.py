from pydantic import BaseModel, HttpUrl
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum

class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class CreateScanRequest(BaseModel):
    target_url: HttpUrl
    name: Optional[str] = None
    max_pages: int = 30
    notify_email: Optional[str] = None
    consent: bool

class ScanRunResponse(BaseModel):
    id: str
    target_url: str
    name: Optional[str] = None
    status: ScanStatus
    created_at: datetime
    completed_at: Optional[datetime] = None
    risk_score: int = 0
    finding_count: int = 0

class FindingResponse(BaseModel):
    id: str
    run_id: str
    category: str
    severity: Severity
    title: str
    description: str
    evidence: Dict[str, Any]
    fix_snippet: Optional[str] = None
    reproduce_command: Optional[str] = None
    priority_score: int = 0
    created_at: datetime

class ScanEvent(BaseModel):
    event_type: str  # "status_update", "finding_discovered", "scan_completed"
    data: Dict[str, Any]
    timestamp: datetime

class ReproduceRequest(BaseModel):
    finding_id: str

class UpdateScanRunRequest(BaseModel):
    name: Optional[str] = None