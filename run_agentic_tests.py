#!/usr/bin/env python3
"""
Run Agentic Security Tests - Complete integration example
"""

import asyncio
import json
import os
import sys
from pathlib import Path

# Add the scanner directory to the path
sys.path.append(str(Path(__file__).parent / "scanner"))

from code_aware_test_generator import CodeAwareTestGenerator
from test_runner import TestRunner
from enhanced_attack_suite import EnhancedAttackSuite

async def run_agentic_security_tests():
    """
    Complete example of running agentic security tests
    """
    print("🚀 Agentic Security Testing System")
    print("=" * 50)
    
    # Configuration
    codebase_path = input("Enter path to your codebase (or press Enter for demo): ").strip()
    target_url = input("Enter target URL to test (or press Enter for demo): ").strip()
    user_request = input("Describe what you want to test: ").strip()
    
    # Default values for demo
    if not codebase_path:
        codebase_path = "/path/to/your/codebase"
        print(f"Using demo codebase path: {codebase_path}")
    
    if not target_url:
        target_url = "https://httpbin.org"
        print(f"Using demo target URL: {target_url}")
    
    if not user_request:
        user_request = "Test for SQL injection and XSS vulnerabilities in our web application"
        print(f"Using demo request: {user_request}")
    
    print(f"\n🎯 Target: {target_url}")
    print(f"📁 Codebase: {codebase_path}")
    print(f"💬 Request: {user_request}")
    print("\n" + "=" * 50)
    
    # Step 1: Analyze codebase (if it exists)
    if os.path.exists(codebase_path):
        print("\n🔍 Step 1: Analyzing codebase...")
        generator = CodeAwareTestGenerator()
        code_files = await generator.analyze_codebase(codebase_path)
        print(f"✅ Analyzed {len(code_files)} files")
        
        # Generate targeted test cases
        print("\n🤖 Step 2: Generating targeted test cases...")
        test_cases = await generator.generate_targeted_tests(code_files, user_request)
        print(f"✅ Generated {len(test_cases)} targeted test cases")
    else:
        print("\n🤖 Step 1: Generating generic test cases...")
        # Use the enhanced attack suite for generic testing
        suite = EnhancedAttackSuite()
        test_cases = await suite.run_llm_assisted_generation(target_url, user_request)
        print(f"✅ Generated {len(test_cases)} generic test cases")
    
    # Step 2: Execute test cases
    print("\n⚡ Step 3: Executing test cases...")
    runner = TestRunner(headless=True)
    results = await runner.run_test_cases(test_cases, target_url)
    
    # Step 3: Generate report
    print("\n📊 Step 4: Generating report...")
    report = runner.generate_report(results)
    
    # Display results
    print("\n" + "=" * 50)
    print("📊 TEST EXECUTION RESULTS")
    print("=" * 50)
    
    print(f"Total Tests: {report['summary']['total_tests']}")
    print(f"Completed: {report['summary']['completed_tests']}")
    print(f"Failed: {report['summary']['failed_tests']}")
    print(f"Success Rate: {report['summary']['success_rate']}")
    print(f"Total Findings: {report['summary']['total_findings']}")
    print(f"Risk Score: {report['summary']['risk_score']}")
    
    print(f"\nSeverity Breakdown:")
    for severity, count in report['severity_breakdown'].items():
        print(f"  {severity.capitalize()}: {count}")
    
    if report['top_findings']:
        print(f"\n🔍 Top Findings:")
        for i, finding in enumerate(report['top_findings'], 1):
            print(f"  {i}. {finding['description']}")
            print(f"     Severity: {finding['severity']}")
            print(f"     Type: {finding['type']}")
            if 'payload' in finding:
                print(f"     Payload: {finding['payload']}")
            print()
    
    # Save detailed report
    report_file = "agentic_security_report.json"
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"📄 Detailed report saved to: {report_file}")
    
    # Save test cases for review
    test_cases_file = "generated_test_cases.json"
    with open(test_cases_file, "w") as f:
        json.dump(test_cases, f, indent=2, default=str)
    
    print(f"🧪 Test cases saved to: {test_cases_file}")
    
    return report

async def run_demo():
    """
    Run a quick demo without requiring user input
    """
    print("🚀 Agentic Security Testing - Demo Mode")
    print("=" * 50)
    
    # Demo configuration
    target_url = "https://httpbin.org"
    user_request = "Test for SQL injection and XSS vulnerabilities"
    
    print(f"🎯 Target: {target_url}")
    print(f"💬 Request: {user_request}")
    print("\n" + "=" * 50)
    
    # Generate test cases using enhanced attack suite
    print("\n🤖 Generating test cases...")
    suite = EnhancedAttackSuite()
    test_cases = await suite.run_llm_assisted_generation(target_url, user_request)
    print(f"✅ Generated {len(test_cases)} test cases")
    
    # Execute test cases
    print("\n⚡ Executing test cases...")
    runner = TestRunner(headless=True)
    results = await runner.run_test_cases(test_cases, target_url)
    
    # Generate report
    print("\n📊 Generating report...")
    report = runner.generate_report(results)
    
    # Display results
    print("\n" + "=" * 50)
    print("📊 DEMO RESULTS")
    print("=" * 50)
    
    print(f"Total Tests: {report['summary']['total_tests']}")
    print(f"Completed: {report['summary']['completed_tests']}")
    print(f"Total Findings: {report['summary']['total_findings']}")
    print(f"Risk Score: {report['summary']['risk_score']}")
    
    if report['top_findings']:
        print(f"\n🔍 Top Findings:")
        for i, finding in enumerate(report['top_findings'][:3], 1):
            print(f"  {i}. {finding['description']} (Severity: {finding['severity']})")
    
    # Save report
    with open("demo_security_report.json", "w") as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"\n📄 Demo report saved to: demo_security_report.json")
    
    return report

def main():
    """
    Main entry point
    """
    import argparse
    
    parser = argparse.ArgumentParser(description="Run Agentic Security Tests")
    parser.add_argument("--demo", action="store_true", help="Run in demo mode")
    parser.add_argument("--codebase", type=str, help="Path to codebase to analyze")
    parser.add_argument("--target", type=str, help="Target URL to test")
    parser.add_argument("--request", type=str, help="Security testing request")
    
    args = parser.parse_args()
    
    if args.demo:
        asyncio.run(run_demo())
    else:
        asyncio.run(run_agentic_security_tests())

if __name__ == "__main__":
    main()
