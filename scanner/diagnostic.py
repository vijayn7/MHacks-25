#!/usr/bin/env python3
"""
Diagnostic script to help debug scanner issues
"""

import json
import sys
from pathlib import Path
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.scanner_orchestrator import ScannerOrchestrator

def main():
    print("🔍 Scanner Diagnostic Tool")
    print("=" * 50)
    
    # Check if we're in the right directory
    current_dir = Path.cwd()
    print(f"📁 Current directory: {current_dir}")
    
    # Look for pages.json files
    pages_files = list(current_dir.glob("**/pages.json"))
    print(f"📄 Found {len(pages_files)} pages.json files:")
    
    for pages_file in pages_files:
        print(f"   - {pages_file}")
        
        # Check file size and content
        try:
            file_size = pages_file.stat().st_size
            print(f"     Size: {file_size} bytes")
            
            if file_size > 0:
                with open(pages_file, 'r') as f:
                    data = json.load(f)
                
                pages_count = len(data.get('pages', []))
                print(f"     Pages: {pages_count}")
                
                if pages_count > 0:
                    sample_page = data['pages'][0]
                    print(f"     Sample URL: {sample_page.get('url', 'N/A')}")
                    print(f"     Sample status: {sample_page.get('status_code', 'N/A')}")
                    print(f"     Sample headers: {len(sample_page.get('headers', {}))}")
                    print(f"     Sample forms: {len(sample_page.get('forms', []))}")
                    print(f"     Sample scripts: {len(sample_page.get('scripts', []))}")
                    
                    # Show actual headers
                    headers = sample_page.get('headers', {})
                    if headers:
                        print(f"     Headers found:")
                        for header_name, header_value in list(headers.items())[:5]:  # Show first 5
                            print(f"       {header_name}: {header_value[:50]}...")
                    
                    # Show forms
                    forms = sample_page.get('forms', [])
                    if forms:
                        print(f"     Forms found:")
                        for i, form in enumerate(forms[:3]):  # Show first 3
                            print(f"       Form {i+1}: {form.get('action', 'N/A')} ({form.get('method', 'N/A')})")
                            inputs = form.get('inputs', [])
                            print(f"         Inputs: {len(inputs)}")
                            for inp in inputs[:3]:  # Show first 3 inputs
                                print(f"           - {inp.get('name', 'N/A')} ({inp.get('type', 'N/A')})")
                    
                    # Show scripts
                    scripts = sample_page.get('scripts', [])
                    if scripts:
                        print(f"     Scripts found:")
                        for i, script in enumerate(scripts[:3]):  # Show first 3
                            script_type = script.get('type', 'unknown')
                            if script_type == 'external':
                                print(f"       Script {i+1}: External - {script.get('src', 'N/A')}")
                            else:
                                content = script.get('content', '')
                                print(f"       Script {i+1}: Inline - {len(content)} chars")
                
                print()
                
        except Exception as e:
            print(f"     ❌ Error reading file: {str(e)}")
            print()
    
    # If no pages.json found, show how to create one
    if not pages_files:
        print("❌ No pages.json files found!")
        print()
        print("💡 To create a pages.json file, run the crawler first:")
        print("   python crawler/crawler.py")
        print()
        print("   Or create a test file manually:")
        print("   {")
        print('     "pages": [')
        print('       {')
        print('         "url": "https://example.com",')
        print('         "status_code": 200,')
        print('         "headers": {')
        print('           "server": "nginx/1.18.0"')
        print('         },')
        print('         "forms": [],')
        print('         "scripts": []')
        print('       }')
        print('     ]')
        print("   }")
        return
    
    # Try to run the scanner on the first pages.json found
    if pages_files:
        pages_file = pages_files[0]
        print(f"🚀 Testing scanner with: {pages_file}")
        print("=" * 50)
        
        try:
            orchestrator = ScannerOrchestrator("diagnostic_run")
            summary = orchestrator.scan_all(pages_file)
            
            if "error" in summary:
                print(f"❌ Scanner failed: {summary['error']}")
            else:
                print(f"✅ Scanner completed successfully!")
                print(f"📊 Total findings: {summary.get('total_findings', 0)}")
                print(f"🎯 Risk score: {summary.get('risk_score', 0)}/100")
                
        except Exception as e:
            print(f"❌ Scanner crashed: {str(e)}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()
