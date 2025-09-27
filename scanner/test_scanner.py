#!/usr/bin/env python3
"""
Test script to create sample data and test the scanner
"""

import json
from pathlib import Path
import os
import sys

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.scanner_orchestrator import ScannerOrchestrator

def create_sample_pages_data():
    """Create sample pages data for testing"""
    
    sample_data = {
        "run_id": "test_run",
        "pages": [
            {
                "url": "https://example.com",
                "status_code": 200,
                "headers": {
                    "Server": "nginx/1.18.0",
                    "Content-Type": "text/html; charset=UTF-8",
                    "X-Powered-By": "PHP/7.4.3"
                },
                "title": "Example Domain",
                "html_snippet": """
                <html>
                <head>
                    <title>Example Domain</title>
                    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
                </head>
                <body>
                    <h1>Example Domain</h1>
                    <form action="/login" method="POST">
                        <input type="text" name="username" required>
                        <input type="password" name="password" required>
                        <button type="submit">Login</button>
                    </form>
                    <script>
                        document.write('<p>Welcome!</p>');
                        eval('console.log("test")');
                    </script>
                </body>
                </html>
                """,
                "forms": [
                    {
                        "action": "/login",
                        "method": "POST",
                        "inputs": [
                            {"name": "username", "type": "text", "value": ""},
                            {"name": "password", "type": "password", "value": ""}
                        ]
                    }
                ],
                "scripts": [
                    {
                        "type": "external",
                        "src": "https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.4/jquery.min.js"
                    },
                    {
                        "type": "inline",
                        "content": 'document.write(\'<p>Welcome!</p>\'); eval(\'console.log("test")\');'
                    }
                ],
                "cookies": [
                    {
                        "name": "sessionid",
                        "value": "abc123",
                        "domain": "example.com",
                        "path": "/",
                        "secure": False,
                        "httpOnly": False,
                        "sameSite": ""
                    }
                ],
                "meta_tags": {
                    "viewport": "width=device-width, initial-scale=1.0",
                    "description": "Example domain for testing"
                },
                "timestamp": "2024-01-01T00:00:00Z"
            },
            {
                "url": "http://insecure.example.com/admin",
                "status_code": 200,
                "headers": {
                    "Server": "Apache/2.4.41",
                    "Content-Type": "text/html"
                },
                "title": "Admin Panel",
                "html_snippet": """
                <html>
                <head><title>Admin Panel</title></head>
                <body>
                    <h1>Admin Dashboard</h1>
                    <p>Welcome to the admin panel</p>
                </body>
                </html>
                """,
                "forms": [],
                "scripts": [],
                "cookies": [],
                "meta_tags": {},
                "timestamp": "2024-01-01T00:00:00Z"
            }
        ],
        "summary": {
            "total_pages": 2,
            "unique_domains": 2,
            "forms_found": 1,
            "scripts_found": 2
        },
        "timestamp": "2024-01-01T00:00:00Z"
    }
    
    return sample_data

def main():
    print("🧪 Scanner Test Suite")
    print("=" * 50)
    
    # Create sample data
    print("📝 Creating sample pages data...")
    sample_data = create_sample_pages_data()
    
    # Save to file
    pages_file = Path("test_pages.json")
    with open(pages_file, 'w') as f:
        json.dump(sample_data, f, indent=2)
    
    print(f"💾 Sample data saved to: {pages_file}")
    print(f"📊 Sample data contains:")
    print(f"   - {len(sample_data['pages'])} pages")
    print(f"   - {sample_data['summary']['forms_found']} forms")
    print(f"   - {sample_data['summary']['scripts_found']} scripts")
    print()
    
    # Test the scanner
    print("🚀 Testing scanner...")
    print("=" * 50)
    
    try:
        orchestrator = ScannerOrchestrator("test_run")
        summary = orchestrator.scan_all(pages_file)
        
        if "error" in summary:
            print(f"❌ Scanner failed: {summary['error']}")
        else:
            print(f"✅ Scanner completed successfully!")
            print(f"📊 Total findings: {summary.get('total_findings', 0)}")
            print(f"🎯 Risk score: {summary.get('risk_score', 0)}/100")
            
            # Show findings breakdown
            severity_counts = summary.get('severity_breakdown', {})
            print(f"\n📈 Findings by severity:")
            for severity, count in severity_counts.items():
                if count > 0:
                    print(f"   {severity.upper()}: {count}")
            
            # Show OWASP categories
            owasp_counts = summary.get('owasp_category_breakdown', {})
            print(f"\n🏷️  Findings by OWASP category:")
            for category, count in owasp_counts.items():
                if count > 0:
                    print(f"   {category}: {count}")
            
            # Show top findings
            top_findings = summary.get('top_findings', [])
            if top_findings:
                print(f"\n🔝 Top findings:")
                for i, finding in enumerate(top_findings[:5], 1):
                    print(f"   {i}. {finding['title']} ({finding['severity']}) - {finding['owasp_category']}")
            
            # Save comprehensive report
            print(f"\n💾 Saving comprehensive report...")
            orchestrator.save_comprehensive_report(Path("."))
            
    except Exception as e:
        print(f"❌ Scanner crashed: {str(e)}")
        import traceback
        traceback.print_exc()
    
    print(f"\n🧹 Cleaning up...")
    if pages_file.exists():
        pages_file.unlink()
        print(f"🗑️  Removed test file: {pages_file}")
    
    print(f"\n✅ Test completed!")

if __name__ == "__main__":
    main()
