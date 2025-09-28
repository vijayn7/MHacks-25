import os
from datetime import datetime
from typing import Optional, List, Dict, Any
from beanie import Document, init_beanie
from pydantic import BaseModel, Field
from motor.motor_asyncio import AsyncIOMotorClient
import asyncio
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# MongoDB connection
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
DATABASE_NAME = os.getenv("DATABASE_NAME", "swarm_db")

class ScanRun(Document):
    id: str = Field(alias="_id")
    target_url: str
    status: str = "queued"  # queued, running, completed, failed
    created_at: datetime = Field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    consent_ip: Optional[str] = None
    consent_timestamp: datetime = Field(default_factory=datetime.now)
    notify_email: Optional[str] = None
    max_pages: int = 30
    risk_score: int = 0
    user_id: Optional[str] = None

    class Settings:
        name = "scan_runs"

class ScannedPage(Document):
    run_id: str
    url: str
    status_code: Optional[int] = None
    headers: Optional[Dict[str, Any]] = None
    html_snippet: Optional[str] = None
    screenshot_path: Optional[str] = None
    cookies: Optional[List[Dict[str, Any]]] = None
    created_at: datetime = Field(default_factory=datetime.now)

    class Settings:
        name = "scanned_pages"

class Finding(Document):
    id: str = Field(alias="_id")
    run_id: str
    category: str  # clickjacking, cors, xss, etc.
    severity: str  # critical, high, medium, low
    title: str
    description: str
    evidence: Dict[str, Any]  # screenshots, headers, etc.
    fix_snippet: Optional[str] = None
    reproduce_command: Optional[str] = None
    reproduce_seed: Optional[str] = None
    priority_score: int = 0
    created_at: datetime = Field(default_factory=datetime.now)

    class Settings:
        name = "findings"

# Global database client
db_client: Optional[AsyncIOMotorClient] = None

async def init_database():
    """Initialize MongoDB connection and database"""
    global db_client

    # Modify MongoDB URL to include SSL parameters for certificate issues
    mongodb_url = MONGODB_URL
    if "&tlsAllowInvalidCertificates=true" not in mongodb_url:
        mongodb_url += "&tlsAllowInvalidCertificates=true"
    
    print(f"🔌 Connecting to MongoDB at {mongodb_url[:50]}...")

    # Create Motor client
    db_client = AsyncIOMotorClient(
        mongodb_url,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=5000,
        socketTimeoutMS=5000
    )

    # Test connection
    try:
        await db_client.admin.command('ping')
        print("✅ MongoDB connection successful")
    except Exception as e:
        print(f"❌ MongoDB connection failed: {e}")
        raise

    # Initialize Beanie with document models
    database = db_client[DATABASE_NAME]
    await init_beanie(database=database, document_models=[ScanRun, ScannedPage, Finding])

    print(f"🗄️  Database '{DATABASE_NAME}' initialized")

async def close_database():
    """Close database connection"""
    global db_client
    if db_client:
        db_client.close()
        print("🔌 Database connection closed")

# Database dependency for FastAPI
async def get_database():
    """Dependency to ensure database is initialized"""
    global db_client
    if not db_client:
        await init_database()
    return db_client[DATABASE_NAME]

# Helper functions for common operations
async def create_scan_run(scan_data: dict) -> ScanRun:
    """Create a new scan run"""
    scan_run = ScanRun(**scan_data)
    await scan_run.save()
    return scan_run

async def get_scan_run(run_id: str) -> Optional[ScanRun]:
    """Get scan run by ID"""
    return await ScanRun.find_one(ScanRun.id == run_id)

async def get_scan_runs_by_user(user_id: str) -> List[ScanRun]:
    """Get all scan runs that belong to a specific user"""
    runs = await ScanRun.find(ScanRun.user_id == user_id).to_list()

    # Sort newest first for easier display in the UI
    runs.sort(key=lambda run: run.created_at, reverse=True)

    return runs

async def update_scan_run(run_id: str, update_data: dict) -> Optional[ScanRun]:
    """Update scan run"""
    scan_run = await get_scan_run(run_id)
    if scan_run:
        for key, value in update_data.items():
            setattr(scan_run, key, value)
        await scan_run.save()
    return scan_run

async def create_finding(finding_data: dict) -> Finding:
    """Create a new finding"""
    finding = Finding(**finding_data)
    await finding.save()
    return finding

async def get_findings_by_run(run_id: str) -> List[Finding]:
    """Get all findings for a scan run, sorted by severity (critical to low) and then by priority score"""
    findings = await Finding.find(Finding.run_id == run_id).to_list()
    
    # Define severity order for sorting
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    
    # Sort by severity first (descending), then by priority score (descending)
    findings.sort(key=lambda f: (severity_order.get(f.severity, 0), f.priority_score), reverse=True)
    
    return findings

async def get_finding(finding_id: str) -> Optional[Finding]:
    """Get finding by ID"""
    return await Finding.find_one(Finding.id == finding_id)

async def create_scanned_page(page_data: dict) -> ScannedPage:
    """Create a new scanned page record"""
    page = ScannedPage(**page_data)
    await page.save()
    return page

async def get_pages_by_run(run_id: str) -> List[ScannedPage]:
    """Get all pages for a scan run"""
    return await ScannedPage.find(ScannedPage.run_id == run_id).to_list()

# Startup function for FastAPI
async def startup_db():
    """Startup event for FastAPI"""
    await init_database()

# Shutdown function for FastAPI
async def shutdown_db():
    """Shutdown event for FastAPI"""
    await close_database()

if __name__ == "__main__":
    # Test database connection
    async def test_db():
        await init_database()

        # Test creating a scan run
        test_scan = await create_scan_run({
            "id": "test_123",
            "target_url": "https://example.com",
            "status": "queued"
        })
        print(f"✅ Created test scan: {test_scan.id}")

        # Test retrieving it
        retrieved = await get_scan_run("test_123")
        print(f"✅ Retrieved scan: {retrieved.target_url}")

        # Cleanup
        await test_scan.delete()
        print("✅ Test cleanup complete")

        await close_database()

    asyncio.run(test_db())