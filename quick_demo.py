#!/usr/bin/env python3
"""
Quick demo of the Agentic Security Testing System
"""

import asyncio
import json

async def main():
    print("🤖 Agentic Security Testing System - Quick Demo")
    print("=" * 60)
    
    print("\n🔍 Step 1: Code Analysis")
    print("   - Scanning codebase for vulnerabilities...")
    print("   - Found 3 SQL injection patterns")
    print("   - Found 2 XSS vulnerabilities")
    print("   - Found 1 authentication bypass")
    
    print("\n🤖 Step 2: AI Test Generation")
    print("   - Generating targeted test cases...")
    print("   - Created 5 SQL injection tests")
    print("   - Created 3 XSS tests")
    print("   - Created 2 authentication tests")
    
    print("\n⚡ Step 3: Test Execution")
    print("   - Executing tests against target...")
    print("   - Running SQL injection tests...")
    print("   - Running XSS tests...")
    print("   - Running authentication tests...")
    
    print("\n📊 Step 4: Results")
    print("   - Total Tests: 10")
    print("   - Completed: 10")
    print("   - Findings: 4")
    print("   - Risk Score: 28")
    
    print("\n🚨 Top Findings:")
    print("   1. SQL Injection in searchUsers function (High)")
    print("   2. XSS in comment system (High)")
    print("   3. Authentication bypass in login (Critical)")
    print("   4. Missing security headers (Medium)")
    
    print("\n✅ Demo complete! To run the actual system:")
    print("   python3 run_agentic_tests.py --demo")

if __name__ == "__main__":
    asyncio.run(main())
