#!/usr/bin/env python3
"""
Example usage of the Agentic Security Testing System with GitHub integration
"""

import asyncio
import json
import requests
import os
from typing import Dict, Any

# Configuration
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
API_BASE_URL = "http://localhost:8000/api"

def print_header(title: str):
    """Print a formatted header"""
    print(f"\n{'='*60}")
    print(f"🤖 {title}")
    print(f"{'='*60}")

def print_step(step: str, description: str):
    """Print a step with emoji"""
    print(f"\n{step} {description}")

async def example_github_integration():
    """Example of using GitHub integration"""
    print_header("GITHUB INTEGRATION EXAMPLE")
    
    if not GITHUB_TOKEN:
        print("❌ GITHUB_TOKEN environment variable not set")
        print("   Set it with: export GITHUB_TOKEN=your_token_here")
        return
    
    # Example 1: Analyze a repository
    print_step("🔍", "Analyzing GitHub repository...")
    
    analyze_request = {
        "repo_owner": "your-username",
        "repo_name": "your-repo",
        "target_url": "https://your-app.com",
        "test_request": "Test for SQL injection and XSS vulnerabilities",
        "branch": "main"
    }
    
    try:
        response = requests.post(f"{API_BASE_URL}/analyze-repo", json=analyze_request)
        if response.status_code == 200:
            analysis = response.json()
            print(f"✅ Analyzed {analysis['files_analyzed']} files")
            print(f"   Found {analysis['vulnerabilities_found']} potential vulnerabilities")
        else:
            print(f"❌ Analysis failed: {response.text}")
    except Exception as e:
        print(f"❌ Error: {str(e)}")
    
    # Example 2: Generate test cases from repository
    print_step("🤖", "Generating test cases from repository...")
    
    try:
        response = requests.post(f"{API_BASE_URL}/generate-tests-from-repo", json=analyze_request)
        if response.status_code == 200:
            tests = response.json()
            print(f"✅ Generated {tests['test_cases_generated']} test cases")
            
            # Show first few test cases
            for i, test_case in enumerate(tests['test_cases'][:3], 1):
                print(f"   {i}. {test_case['name']}")
                print(f"      Type: {test_case['attack_type']}")
                print(f"      Risk: {test_case['risk_level']}")
                print(f"      File: {test_case['target_file']}")
        else:
            print(f"❌ Test generation failed: {response.text}")
    except Exception as e:
        print(f"❌ Error: {str(e)}")
    
    # Example 3: Trigger GitHub Actions workflow
    print_step("⚡", "Triggering GitHub Actions workflow...")
    
    try:
        response = requests.post(f"{API_BASE_URL}/trigger-github-tests", json=analyze_request)
        if response.status_code == 200:
            workflow = response.json()
            print(f"✅ Workflow triggered: {workflow['workflow_id']}")
            print(f"   Status: {workflow['status']}")
            print(f"   URL: {workflow['workflow_url']}")
        else:
            print(f"❌ Workflow trigger failed: {response.text}")
    except Exception as e:
        print(f"❌ Error: {str(e)}")

async def example_local_testing():
    """Example of local testing without GitHub"""
    print_header("LOCAL TESTING EXAMPLE")
    
    # Example: Test a local application
    print_step("🧪", "Testing local application...")
    
    test_request = {
        "target_url": "http://localhost:3000",
        "test_request": "Test for authentication bypass and XSS vulnerabilities"
    }
    
    try:
        response = requests.post(f"{API_BASE_URL}/trigger-workflow", json=test_request)
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Test triggered: {result['workflow_id']}")
            print(f"   Status: {result['status']}")
        else:
            print(f"❌ Test trigger failed: {response.text}")
    except Exception as e:
        print(f"❌ Error: {str(e)}")

async def example_manual_testing():
    """Example of manual test case creation"""
    print_header("MANUAL TEST CASE CREATION")
    
    # Example test cases
    test_cases = [
        {
            "test_id": "manual_001",
            "name": "SQL Injection in Login Form",
            "description": "Test for SQL injection in user authentication",
            "attack_type": "sql_injection",
            "target_function": "authenticateUser",
            "target_file": "src/auth.js",
            "payloads": [
                "admin'--",
                "admin' OR '1'='1",
                "admin'/*",
                "admin'#"
            ],
            "expected_behavior": "Should reject invalid credentials",
            "risk_level": "critical",
            "code_snippet": "SELECT * FROM users WHERE username='${username}' AND password='${password}'",
            "mitigation": "Use parameterized queries and proper password hashing"
        },
        {
            "test_id": "manual_002",
            "name": "XSS in Comment System",
            "description": "Test for XSS vulnerability in comment submission",
            "attack_type": "xss",
            "target_function": "addComment",
            "target_file": "src/comments.js",
            "payloads": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')"
            ],
            "expected_behavior": "Should sanitize HTML content",
            "risk_level": "high",
            "code_snippet": "innerHTML = commentText",
            "mitigation": "Use textContent instead of innerHTML or sanitize input"
        }
    ]
    
    print_step("📝", "Created manual test cases...")
    print(f"✅ Created {len(test_cases)} test cases")
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"   {i}. {test_case['name']}")
        print(f"      Type: {test_case['attack_type']}")
        print(f"      Risk: {test_case['risk_level']}")
        print(f"      Payloads: {len(test_case['payloads'])}")
    
    # Save test cases
    with open("manual_test_cases.json", "w") as f:
        json.dump(test_cases, f, indent=2)
    
    print(f"\n📄 Test cases saved to: manual_test_cases.json")

def show_setup_instructions():
    """Show setup instructions"""
    print_header("SETUP INSTRUCTIONS")
    
    print("1. 🔑 Set up GitHub token:")
    print("   export GITHUB_TOKEN=your_github_token_here")
    print("   # Or add to .env file: GITHUB_TOKEN=your_token_here")
    
    print("\n2. 🚀 Start the backend server:")
    print("   cd backend")
    print("   python main.py")
    
    print("\n3. 🎯 Set up GitHub Actions workflow:")
    print("   - Copy .github/workflows/agentic-security-tests.yml to your repo")
    print("   - Add GITHUB_TOKEN to your repository secrets")
    print("   - Push to trigger the workflow")
    
    print("\n4. 🧪 Run tests:")
    print("   python example_usage.py")

async def main():
    """Main example function"""
    print_header("AGENTIC SECURITY TESTING SYSTEM - USAGE EXAMPLES")
    
    print("This example shows different ways to use the system:")
    print("1. 🔍 GitHub integration (analyzes real code)")
    print("2. 🧪 Local testing (tests your local app)")
    print("3. 📝 Manual test creation (custom test cases)")
    
    # Show setup instructions
    show_setup_instructions()
    
    # Example 1: GitHub integration
    await example_github_integration()
    
    # Example 2: Local testing
    await example_local_testing()
    
    # Example 3: Manual test creation
    await example_manual_testing()
    
    print_header("EXAMPLES COMPLETE")
    print("Check the generated files and GitHub Actions for results!")

if __name__ == "__main__":
    asyncio.run(main())
