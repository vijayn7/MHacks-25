#!/usr/bin/env python3
"""
Command-line interface for the security scanner
"""

import sys
import argparse
from pathlib import Path
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.scanner_orchestrator import ScannerOrchestrator

def main():
    parser = argparse.ArgumentParser(description='Security Scanner - OWASP Top 10 Analysis')
    parser.add_argument('pages_file', nargs='?', default='pages.json', 
                       help='Path to pages.json file (default: pages.json)')
    parser.add_argument('--run-id', default='manual_run',
                       help='Run ID for this scan (default: manual_run)')
    parser.add_argument('--output-dir', default='.',
                       help='Output directory for reports (default: current directory)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    pages_file = Path(args.pages_file)
    output_dir = Path(args.output_dir)
    
    print("🛡️  Security Scanner - OWASP Top 10 Analysis")
    print("=" * 60)
    print(f"📁 Pages file: {pages_file}")
    print(f"📁 Output directory: {output_dir}")
    print(f"🆔 Run ID: {args.run_id}")
    print()
    
    # Check if pages file exists
    if not pages_file.exists():
        print(f"❌ ERROR: Pages file '{pages_file}' not found!")
        print()
        print("💡 To create a pages.json file:")
        print("   1. Run the crawler: python crawler/crawler.py")
        print("   2. Or use the test script: python scanner/test_scanner.py")
        print("   3. Or run diagnostics: python scanner/diagnostic.py")
        return 1
    
    # Check file size
    file_size = pages_file.stat().st_size
    if file_size == 0:
        print(f"❌ ERROR: Pages file '{pages_file}' is empty!")
        return 1
    
    print(f"📏 File size: {file_size:,} bytes")
    
    # Run the scanner
    try:
        print(f"\n🚀 Starting security scan...")
        orchestrator = ScannerOrchestrator(args.run_id)
        summary = orchestrator.scan_all(pages_file)
        
        if "error" in summary:
            print(f"❌ Scan failed: {summary['error']}")
            return 1
        
        # Show results
        print(f"\n🎯 Scan Results:")
        print(f"   Total findings: {summary.get('total_findings', 0)}")
        print(f"   Risk score: {summary.get('risk_score', 0)}/100")
        print(f"   Duration: {summary.get('duration_seconds', 0):.2f} seconds")
        
        # Show severity breakdown
        severity_counts = summary.get('severity_breakdown', {})
        print(f"\n📊 Severity Breakdown:")
        for severity in ['critical', 'high', 'medium', 'low']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                print(f"   {severity.upper()}: {count}")
        
        # Show OWASP categories
        owasp_counts = summary.get('owasp_category_breakdown', {})
        print(f"\n🏷️  OWASP Categories:")
        for category, count in owasp_counts.items():
            if count > 0:
                print(f"   {category}: {count}")
        
        # Show top findings
        top_findings = summary.get('top_findings', [])
        if top_findings:
            print(f"\n🔝 Top Findings:")
            for i, finding in enumerate(top_findings[:10], 1):
                print(f"   {i:2d}. {finding['title']} ({finding['severity']})")
                print(f"       Category: {finding['owasp_category']}")
                print(f"       Scanner: {finding['scanner']}")
                print()
        
        # Save reports
        print(f"💾 Saving reports to {output_dir}...")
        orchestrator.save_comprehensive_report(output_dir)
        
        # Show file locations
        report_file = output_dir / f"comprehensive_security_report_{args.run_id}.json"
        summary_file = output_dir / f"executive_summary_{args.run_id}.json"
        
        print(f"\n📄 Reports saved:")
        print(f"   Comprehensive report: {report_file}")
        print(f"   Executive summary: {summary_file}")
        
        # Individual scanner reports
        print(f"\n📋 Individual scanner reports:")
        for scanner_name in summary.get('scanners_run', []):
            scanner_file = output_dir / f"{scanner_name.lower()}_findings.json"
            if scanner_file.exists():
                print(f"   {scanner_name}: {scanner_file}")
        
        print(f"\n✅ Scan completed successfully!")
        
        # Return appropriate exit code
        critical_count = severity_counts.get('critical', 0)
        high_count = severity_counts.get('high', 0)
        
        if critical_count > 0:
            print(f"⚠️  WARNING: {critical_count} critical issues found!")
            return 2
        elif high_count > 0:
            print(f"⚠️  WARNING: {high_count} high-severity issues found!")
            return 3
        else:
            print(f"✅ No critical or high-severity issues found!")
            return 0
            
    except Exception as e:
        print(f"❌ Scanner crashed: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
