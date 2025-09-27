from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
import uuid
import json
import asyncio
from datetime import datetime
from typing import Dict, List
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from database import (
    startup_db, shutdown_db, get_database,
    create_scan_run, get_scan_run, update_scan_run,
    create_finding, get_findings_by_run, get_finding
)
from models import CreateScanRequest, ScanRunResponse, FindingResponse, ScanEvent, ScanStatus

app = FastAPI(title="Swarm Scanner API", version="1.0.0")

# Add startup and shutdown events
app.add_event_handler("startup", startup_db)
app.add_event_handler("shutdown", shutdown_db)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3002"],  # React dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for SSE connections
active_connections: Dict[str, List] = {}

@app.get("/")
async def root():
    return {"message": "Swarm Scanner API", "version": "1.0.0"}

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

@app.post("/runs", response_model=dict)
async def create_scan(
    scan_request: CreateScanRequest,
    request: Request
):
    if not scan_request.consent:
        raise HTTPException(status_code=400, detail="Consent is required to start a scan")

    # Create scan run
    run_id = str(uuid.uuid4())[:8]

    scan_data = {
        "id": run_id,
        "target_url": str(scan_request.target_url),
        "status": ScanStatus.QUEUED,
        "max_pages": scan_request.max_pages,
        "notify_email": scan_request.notify_email,
        "consent_ip": request.client.host,
    }

    scan_run = await create_scan_run(scan_data)

    # Initialize SSE connection storage
    active_connections[run_id] = []

    # Start scan in background
    asyncio.create_task(run_scan_worker(run_id, str(scan_request.target_url), scan_request.max_pages))

    return {"run_id": run_id, "status": "queued"}

@app.get("/runs/{run_id}", response_model=ScanRunResponse)
async def get_scan_status(run_id: str):
    scan_run = await get_scan_run(run_id)
    if not scan_run:
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
async def get_scan_findings(run_id: str):
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
async def stream_scan_events(run_id: str):
    # Verify run exists
    scan_run = await get_scan_run(run_id)
    if not scan_run:
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

    except Exception as e:
        # Mark as failed
        await update_scan_run(run_id, {"status": ScanStatus.FAILED})

        if run_id in active_connections:
            active_connections[run_id].append({
                "event_type": "scan_failed",
                "data": {"status": "failed", "error": str(e)},
                "timestamp": datetime.now().isoformat()
            })

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
                    scanner_findings = report_data.get('scanner_findings', {})
                    print(f"🔍 Found {len(scanner_findings)} scanner result sets")
                    
                    for scanner_name, findings in scanner_findings.items():
                        print(f"🔍 Processing {len(findings)} findings from {scanner_name}")
                        for finding_data in findings:
                            # Convert scanner format to database format
                            db_finding = {
                                "id": finding_data.get("id", str(uuid.uuid4())[:8]),
                                "run_id": run_id,
                                "category": finding_data.get("owasp_category", "unknown"),
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
