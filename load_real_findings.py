#!/usr/bin/env python3
"""
Script to load real scanner findings into the database
"""

import json
import asyncio
import sys
import os
from pathlib import Path

# Add backend directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

from database import create_finding, get_findings_by_run, startup_db

async def load_real_findings(run_id: str):
    """Load real findings from comprehensive report into database"""
    
    # Load comprehensive report
    report_file = Path(f'comprehensive_security_report_{run_id}.json')
    
    if not report_file.exists():
        print(f"❌ Comprehensive report not found: {report_file}")
        return
    
    with open(report_file, 'r') as f:
        report_data = json.load(f)
    
    all_findings = report_data.get('all_findings', [])
    print(f"📊 Found {len(all_findings)} findings in comprehensive report")
    
    # Check existing findings for this run
    existing_findings = await get_findings_by_run(run_id)
    print(f"📊 Found {len(existing_findings)} existing findings in database")
    
    # Load new findings
    loaded_count = 0
    for finding_data in all_findings:
        try:
            # Convert to database format
            db_finding = {
                "id": finding_data.get("id", ""),
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
            
            await create_finding(db_finding)
            loaded_count += 1
            
            if loaded_count % 10 == 0:
                print(f"📝 Loaded {loaded_count}/{len(all_findings)} findings...")
                
        except Exception as e:
            print(f"❌ Error loading finding {finding_data.get('id', 'unknown')}: {str(e)}")
    
    print(f"✅ Successfully loaded {loaded_count} findings into database")
    
    # Update risk score
    risk_score = report_data.get('scan_summary', {}).get('risk_score', 0)
    print(f"📊 Risk score: {risk_score}")

async def main():
    if len(sys.argv) != 2:
        print("Usage: python load_real_findings.py <run_id>")
        sys.exit(1)
    
    # Initialize database
    await startup_db()
    
    run_id = sys.argv[1]
    await load_real_findings(run_id)

if __name__ == "__main__":
    asyncio.run(main())
