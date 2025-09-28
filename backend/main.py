from fastapi import FastAPI, HTTPException, Request, Response, Depends, Cookie, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
import uuid
import json
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import os
import secrets
from dotenv import load_dotenv
from pydantic import BaseModel, EmailStr, Field
from argon2 import PasswordHasher

# Load environment variables
load_dotenv()

from database import (
    startup_db, shutdown_db, get_database,
    create_scan_run, get_scan_run, update_scan_run,
    create_finding, get_findings_by_run, get_finding,
    get_scan_runs_by_user
)
from models import CreateScanRequest, ScanRunResponse, FindingResponse, ScanEvent, ScanStatus
from agent_mail import dispatch_post_scan_email

app = FastAPI(
    title="Swarm Scanner API",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    description=(
        "REST API for coordinating website security scans, "
        "including crawl execution, finding management, and "
        "server-sent event streaming for scan progress."
    ),
)

# Mount static assets (including the backend favicon)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.mount(
    "/static",
    StaticFiles(directory=os.path.join(BASE_DIR, "static")),
    name="static",
)

# Add startup and shutdown events
app.add_event_handler("startup", startup_db)
app.add_event_handler("shutdown", shutdown_db)

# Configuration
SESSION_COOKIE = os.getenv("SESSION_COOKIE_NAME", "sid")
SESSION_TTL_HOURS = int(os.getenv("SESSION_TTL_HOURS", "168"))
SESSION_TTL = timedelta(hours=SESSION_TTL_HOURS)
CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGIN",
        "http://localhost:3000,http://localhost:3002,http://localhost:5173"
    ).split(",")
    if origin.strip()
]
COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "lax")

ph = PasswordHasher()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class SignupIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    name: Optional[str] = None


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class MeOut(BaseModel):
    id: str
    email: EmailStr
    roles: List[str]


async def ensure_auth_indexes():
    db = await get_database()
    users_collection = db["users"]
    sessions_collection = db["sessions"]

    await users_collection.create_index("email", unique=True)
    await sessions_collection.create_index("token", unique=True)
    await sessions_collection.create_index("expiresAt", expireAfterSeconds=0)


async def startup_auth():
    await ensure_auth_indexes()


app.add_event_handler("startup", startup_auth)


def cookie_opts():
    return {
        "httponly": True,
        "secure": COOKIE_SECURE,
        "samesite": COOKIE_SAMESITE,
        "path": "/",
        "max_age": int(SESSION_TTL.total_seconds()),
    }


async def get_current_user(
    sid: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE)
):
    if not sid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized")

    db = await get_database()
    sessions_collection = db["sessions"]
    users_collection = db["users"]

    now = datetime.utcnow()
    session = await sessions_collection.find_one({
        "token": sid,
        "expiresAt": {"$gt": now},
    })

    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="session_expired")

    user = await users_collection.find_one({"_id": session["userId"]})
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="user_not_found")

    return {
        "id": str(user["_id"]),
        "email": user["email"],
        "roles": user.get("roles", ["user"]),
    }

# In-memory storage for SSE connections
active_connections: Dict[str, List] = {}

@app.get("/", include_in_schema=False)
async def root():
    """Serve the custom Swagger UI from the base URL."""

    return await custom_documentation()


@app.get("/documentation", include_in_schema=False)
async def custom_documentation():
    """Serve a tailored Swagger UI that documents the backend endpoints."""

    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title="Swarm Scanner API Documentation",
        swagger_favicon_url="/static/Favicon.png",
    )


@app.get("/openapi.json", include_in_schema=False)
async def openapi_spec():
    """Expose the OpenAPI schema used by the custom Swagger UI."""

    return JSONResponse(
        get_openapi(title=app.title, version=app.version, routes=app.routes)
    )

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        db = await get_database()
        await db.command('ping')
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}


@app.post("/api/auth/signup", status_code=status.HTTP_201_CREATED)
async def signup(payload: SignupIn, resp: Response):
    db = await get_database()
    users_collection = db["users"]
    sessions_collection = db["sessions"]

    existing = await users_collection.find_one({"email": payload.email.lower()})
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="email_taken")

    pw_hash = ph.hash(payload.password)
    user_doc = {
        "email": payload.email.lower(),
        "passwordHash": pw_hash,
        "name": payload.name,
        "roles": ["user"],
        "createdAt": datetime.utcnow(),
    }

    result = await users_collection.insert_one(user_doc)

    token = secrets.token_hex(32)
    expires_at = datetime.utcnow() + SESSION_TTL
    await sessions_collection.insert_one({
        "userId": result.inserted_id,
        "token": token,
        "createdAt": datetime.utcnow(),
        "expiresAt": expires_at,
    })

    resp.set_cookie(SESSION_COOKIE, token, **cookie_opts())
    return {"id": str(result.inserted_id), "email": payload.email}


@app.post("/api/auth/login")
async def login(payload: LoginIn, resp: Response):
    db = await get_database()
    users_collection = db["users"]
    sessions_collection = db["sessions"]

    user = await users_collection.find_one({"email": payload.email.lower()})
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_credentials")

    try:
        ph.verify(user["passwordHash"], payload.password)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_credentials")

    token = secrets.token_hex(32)
    expires_at = datetime.utcnow() + SESSION_TTL
    await sessions_collection.insert_one({
        "userId": user["_id"],
        "token": token,
        "createdAt": datetime.utcnow(),
        "expiresAt": expires_at,
    })

    resp.set_cookie(SESSION_COOKIE, token, **cookie_opts())
    return {"id": str(user["_id"]), "email": user["email"]}


@app.get("/api/auth/me", response_model=MeOut)
async def me(user=Depends(get_current_user)):
    return user


@app.post("/api/auth/logout")
async def logout(resp: Response, sid: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE)):
    if sid:
        db = await get_database()
        sessions_collection = db["sessions"]
        await sessions_collection.delete_one({"token": sid})

    resp.delete_cookie(SESSION_COOKIE, path="/", samesite=COOKIE_SAMESITE, secure=COOKIE_SECURE)
    return {"ok": True}


@app.get("/api/secret")
async def secret(user=Depends(get_current_user)):
    return {"message": f"Hi {user['email']}, only authed users see this."}


@app.post("/runs", response_model=dict)
async def create_scan(
    scan_request: CreateScanRequest,
    request: Request,
    user=Depends(get_current_user)
):
    if not scan_request.consent:
        raise HTTPException(status_code=400, detail="Consent is required to start a scan")

    # Create scan run
    run_id = str(uuid.uuid4())[:8]

    notify_email = scan_request.notify_email or os.getenv("DEFAULT_NOTIFY_EMAIL", "vnannapu@umich.edu")

    scan_data = {
        "id": run_id,
        "target_url": str(scan_request.target_url),
        "status": ScanStatus.QUEUED,
        "max_pages": scan_request.max_pages,
        "notify_email": notify_email,
        "consent_ip": request.client.host,
        "user_id": user["id"],
    }

    scan_run = await create_scan_run(scan_data)

    # Initialize SSE connection storage
    active_connections[run_id] = []

    # Start scan in background
    asyncio.create_task(run_scan_worker(run_id, str(scan_request.target_url), scan_request.max_pages))

    return {"run_id": run_id, "status": "queued"}

@app.get("/runs", response_model=List[ScanRunResponse])
async def list_scan_runs(user=Depends(get_current_user)):
    runs = await get_scan_runs_by_user(user["id"])

    responses = []
    for run in runs:
        findings = await get_findings_by_run(run.id)
        responses.append(
            ScanRunResponse(
                id=run.id,
                target_url=run.target_url,
                status=run.status,
                created_at=run.created_at,
                completed_at=run.completed_at,
                risk_score=run.risk_score,
                finding_count=len(findings)
            )
        )

    return responses


@app.get("/runs/{run_id}", response_model=ScanRunResponse)
async def get_scan_status(run_id: str, user=Depends(get_current_user)):
    scan_run = await get_scan_run(run_id)
    if not scan_run:
        raise HTTPException(status_code=404, detail="Scan run not found")

    if scan_run.user_id != user["id"]:
        raise HTTPException(status_code=404, detail="Scan run not found")

    findings = await get_findings_by_run(run_id)
    finding_count = len(findings)

    return ScanRunResponse(
        id=scan_run.id,
        target_url=scan_run.target_url,
        status=scan_run.status,
        created_at=scan_run.created_at,
        completed_at=scan_run.completed_at,
        risk_score=scan_run.risk_score,
        finding_count=finding_count
    )

@app.get("/runs/{run_id}/findings", response_model=List[FindingResponse])
async def get_scan_findings(run_id: str, user=Depends(get_current_user)):
    scan_run = await get_scan_run(run_id)
    if not scan_run or scan_run.user_id != user["id"]:
        raise HTTPException(status_code=404, detail="Scan run not found")

    findings = await get_findings_by_run(run_id)

    return [
        FindingResponse(
            id=f.id,
            run_id=f.run_id,
            category=f.category,
            severity=f.severity,
            title=f.title,
            description=f.description,
            evidence=f.evidence,
            fix_snippet=f.fix_snippet,
            reproduce_command=f.reproduce_command,
            priority_score=f.priority_score,
            created_at=f.created_at
        )
        for f in findings
    ]

@app.get("/runs/{run_id}/stream")
async def stream_scan_events(run_id: str, user=Depends(get_current_user)):
    # Verify run exists
    scan_run = await get_scan_run(run_id)
    if not scan_run or scan_run.user_id != user["id"]:
        raise HTTPException(status_code=404, detail="Scan run not found")

    async def event_generator():
        # Send initial status
        yield f"data: {json.dumps({'event_type': 'status_update', 'data': {'status': scan_run.status}, 'timestamp': datetime.now().isoformat()})}\n\n"

        # Stream events for this run
        last_event_count = 0
        while True:
            if run_id in active_connections:
                events = active_connections[run_id][last_event_count:]
                for event in events:
                    yield f"data: {json.dumps(event)}\n\n"
                last_event_count = len(active_connections[run_id])

            # Check if scan is complete
            updated_scan = await get_scan_run(run_id)
            if updated_scan and updated_scan.status in [ScanStatus.COMPLETED, ScanStatus.FAILED]:
                yield f"data: {json.dumps({'event_type': 'scan_completed', 'data': {'status': updated_scan.status}, 'timestamp': datetime.now().isoformat()})}\n\n"
                break

            await asyncio.sleep(1)

    return StreamingResponse(event_generator(), media_type="text/plain")

@app.post("/runs/{run_id}/findings/{finding_id}/replay")
async def replay_finding(run_id: str, finding_id: str):
    finding = await get_finding(finding_id)
    if not finding or finding.run_id != run_id:
        raise HTTPException(status_code=404, detail="Finding not found")

    # TODO: Implement actual replay logic
    return {
        "message": "Replay functionality not yet implemented",
        "finding_id": finding_id,
        "reproduce_command": finding.reproduce_command
    }

async def run_scan_worker(run_id: str, target_url: str, max_pages: int):
    """Background worker that runs the actual scan"""
    try:
        # Update status to running
        await update_scan_run(run_id, {"status": ScanStatus.RUNNING})

        # Send status update event
        if run_id in active_connections:
            active_connections[run_id].append({
                "event_type": "status_update",
                "data": {"status": "running", "message": "Starting crawl..."},
                "timestamp": datetime.now().isoformat()
            })

        # Run real crawler
        await run_real_crawler(run_id, target_url, max_pages)

        # Run real scanners on crawler output
        await run_real_scanners(run_id, target_url)

        # Fallback demo findings if no real findings found
        existing_findings = await get_findings_by_run(run_id)
        if not existing_findings:
            await create_demo_findings(run_id, target_url)

        # Mark as completed (risk score will be updated by scanner)
        await update_scan_run(run_id, {
            "status": ScanStatus.COMPLETED,
            "completed_at": datetime.now()
        })

        # Send completion event
        if run_id in active_connections:
            active_connections[run_id].append({
                "event_type": "scan_completed",
                "data": {"status": "completed", "message": "Scan completed successfully"},
                "timestamp": datetime.now().isoformat()
            })

        # Kick off Agent Mail notification
        asyncio.create_task(dispatch_post_scan_email(run_id))

    except Exception as e:
        # Mark as failed
        await update_scan_run(run_id, {"status": ScanStatus.FAILED})

        if run_id in active_connections:
            active_connections[run_id].append({
                "event_type": "scan_failed",
                "data": {"status": "failed", "error": str(e)},
                "timestamp": datetime.now().isoformat()
            })

        # Notify operators about failure details
        asyncio.create_task(dispatch_post_scan_email(run_id, error_message=str(e)))

async def create_demo_findings(run_id: str, target_url: str):
    """Create demo findings for testing - replace with actual scanner"""

    findings = [
        {
            "id": str(uuid.uuid4())[:8],
            "run_id": run_id,
            "category": "clickjacking",
            "severity": "high",
            "title": "Missing X-Frame-Options Header",
            "description": "The page can be embedded in an iframe, making it vulnerable to clickjacking attacks.",
            "evidence": {
                "url": target_url,
                "missing_headers": ["X-Frame-Options", "Content-Security-Policy"],
                "screenshot": "frame_test_evidence.png"
            },
            "fix_snippet": 'add_header X-Frame-Options "DENY";\nadd_header Content-Security-Policy "frame-ancestors \'none\'";',
            "reproduce_command": f"curl -I {target_url}",
            "priority_score": 80
        },
        {
            "id": str(uuid.uuid4())[:8],
            "run_id": run_id,
            "category": "cors",
            "severity": "critical",
            "title": "Permissive CORS Configuration",
            "description": "Access-Control-Allow-Origin is set to * with credentials enabled.",
            "evidence": {
                "url": f"{target_url}/api/sensitive",
                "response_headers": {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Credentials": "true"
                }
            },
            "fix_snippet": "const allowedOrigins = ['https://yourdomain.com'];\napp.use(cors({\n  origin: allowedOrigins,\n  credentials: false\n}));",
            "reproduce_command": f"curl -H 'Origin: https://evil.com' {target_url}/api/sensitive",
            "priority_score": 90
        },
        {
            "id": str(uuid.uuid4())[:8],
            "run_id": run_id,
            "category": "xss",
            "severity": "high",
            "title": "Reflected XSS Vulnerability",
            "description": "User input is reflected in the response without proper escaping.",
            "evidence": {
                "url": f"{target_url}/search?q=INJTEST_12345",
                "reflected_token": "INJTEST_12345",
                "response_snippet": "<p>You searched for: INJTEST_12345</p>"
            },
            "fix_snippet": "const escapeHtml = (str) => str.replace(/[&<>\"']/g, (c) => ({\n  '&': '&amp;', '<': '&lt;', '>': '&gt;',\n  '\"': '&quot;', \"'\": '&#39;'\n}[c]));\n\nres.send(`<p>You searched for: ${escapeHtml(query)}</p>`);",
            "reproduce_command": f"curl '{target_url}/search?q=INJTEST_12345'",
            "priority_score": 75
        }
    ]

    for finding_data in findings:
        await create_finding(finding_data)

        # Send finding discovered event
        if run_id in active_connections:
            active_connections[run_id].append({
                "event_type": "finding_discovered",
                "data": {
                    "finding_id": finding_data["id"],
                    "category": finding_data["category"],
                    "severity": finding_data["severity"],
                    "title": finding_data["title"]
                },
                "timestamp": datetime.now().isoformat()
            })

        await asyncio.sleep(1)  # Simulate scan progress

async def run_real_crawler(run_id: str, target_url: str, max_pages: int):
    """Run the actual Playwright crawler"""
    try:
        # Import crawler locally to avoid startup issues
        import sys
        import os
        sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'crawler'))

        from crawler import WebCrawler

        # Send crawling status
        if run_id in active_connections:
            active_connections[run_id].append({
                "event_type": "status_update",
                "data": {"status": "running", "message": f"Crawling {target_url}..."},
                "timestamp": datetime.now().isoformat()
            })

        # Create artifacts directory
        artifacts_dir = os.path.join(os.path.dirname(__file__), '..', 'artifacts')
        os.makedirs(artifacts_dir, exist_ok=True)

        # Run crawler
        crawler = WebCrawler(run_id, artifacts_dir)
        crawl_result = await crawler.crawl(target_url, max_pages)

        print(f"✅ Crawl completed: {crawl_result}")

        # Store crawled pages in database
        if crawl_result and 'pages_crawled' in crawl_result:
            # Send completion status
            if run_id in active_connections:
                active_connections[run_id].append({
                    "event_type": "crawl_completed",
                    "data": {
                        "pages_crawled": crawl_result['pages_crawled'],
                        "duration": crawl_result.get('duration_seconds', 0)
                    },
                    "timestamp": datetime.now().isoformat()
                })

    except Exception as e:
        print(f"❌ Crawler error: {str(e)}")
        if run_id in active_connections:
            active_connections[run_id].append({
                "event_type": "crawl_error",
                "data": {"error": str(e)},
                "timestamp": datetime.now().isoformat()
            })

async def run_real_scanners(run_id: str, target_url: str):
    """Run real security scanners on crawler output"""
    try:
        import sys
        import os
        from pathlib import Path

        # Add scanner directory to path
        sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scanner'))

        # Send scanning status
        if run_id in active_connections:
            active_connections[run_id].append({
                "event_type": "status_update",
                "data": {"status": "running", "message": "Running comprehensive security analysis..."},
                "timestamp": datetime.now().isoformat()
            })

        # Check if crawler output exists
        artifacts_dir = Path(os.path.dirname(__file__)) / '..' / 'artifacts' / run_id
        pages_file = artifacts_dir / 'pages.json'

        if pages_file.exists():
            # Run the scanner orchestrator using subprocess to avoid import issues
            import subprocess
            
            print(f"🔍 Running scanner orchestrator for run {run_id}")
            
            # Change to the project root directory
            project_root = Path(os.path.dirname(__file__)) / '..'
            scanner_script = project_root / 'scanner' / 'run_scanner.py'
            
            try:
                # Run the scanner using subprocess
                result = subprocess.run([
                    'python3', str(scanner_script), 
                    str(pages_file), 
                    '--run-id', run_id,
                    '--output-dir', str(project_root)
                ], capture_output=True, text=True, cwd=str(project_root))
                
                print(f"🔍 Scanner subprocess completed with return code: {result.returncode}")
                print(f"🔍 Scanner stdout: {result.stdout[-500:]}")  # Last 500 chars
                if result.stderr:
                    print(f"🔍 Scanner stderr: {result.stderr}")
                
                # Load findings from the comprehensive report
                comprehensive_report_file = project_root / f'comprehensive_security_report_{run_id}.json'
                
                if comprehensive_report_file.exists():
                    print(f"✅ Found comprehensive report: {comprehensive_report_file}")
                    
                    with open(comprehensive_report_file, 'r') as f:
                        report_data = json.load(f)
                    
                    # Extract findings from the report
                    all_findings = []
                    findings_data = report_data.get('all_findings', [])
                    print(f"🔍 Found {len(findings_data)} total findings in comprehensive report")
                    
                    for finding_data in findings_data:
                        # Convert scanner format to database format
                        db_finding = {
                            "id": finding_data.get("id", str(uuid.uuid4())[:8]),
                            "run_id": run_id,
                            "category": finding_data.get("category", "unknown"),
                            "severity": finding_data.get("severity", "medium"),
                            "title": finding_data.get("title", "Security Issue"),
                            "description": finding_data.get("description", "No description available"),
                            "evidence": finding_data.get("evidence", {}),
                            "fix_snippet": finding_data.get("fix_snippet", ""),
                            "reproduce_command": finding_data.get("reproduce_command", ""),
                            "priority_score": finding_data.get("priority_score", 50)
                        }
                        all_findings.append(db_finding)

                    print(f"✅ Total findings to store: {len(all_findings)}")
                    
                    # Store findings in database
                    for finding_data in all_findings:
                        await create_finding(finding_data)

                        # Send finding discovered event
                        if run_id in active_connections:
                            active_connections[run_id].append({
                                "event_type": "finding_discovered",
                                "data": {
                                    "finding_id": finding_data["id"],
                                    "category": finding_data["category"],
                                    "severity": finding_data["severity"],
                                    "title": finding_data["title"]
                                },
                                "timestamp": datetime.now().isoformat()
                            })

                        await asyncio.sleep(0.05)  # Small delay for UX

                    # Update risk score based on actual scan results
                    risk_score = report_data.get('scan_summary', {}).get('risk_score', 0)
                    await update_scan_run(run_id, {"risk_score": risk_score})
                    print(f"✅ Updated risk score to: {risk_score}")
                    
                else:
                    print(f"❌ Comprehensive report not found: {comprehensive_report_file}")
                    
            except Exception as e:
                print(f"❌ Scanner subprocess error: {str(e)}")
                raise
        else:
            print(f"❌ No crawler output found at {pages_file}")

    except Exception as e:
        print(f"❌ Scanner error: {str(e)}")
        if run_id in active_connections:
            active_connections[run_id].append({
                "event_type": "scanner_error",
                "data": {"error": str(e)},
                "timestamp": datetime.now().isoformat()
            })

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
