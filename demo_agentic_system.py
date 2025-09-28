#!/usr/bin/env python3
"""
Demo script for the Agentic Security Testing System
"""

import asyncio
import json
import sys
import os
from pathlib import Path

# Add the scanner directory to the path
sys.path.append(str(Path(__file__).parent / "scanner"))

from enhanced_attack_suite import EnhancedAttackSuite

async def demo_agentic_system():
    """
    Demonstrate the agentic security testing system
    """
    print("🚀 Agentic Security Testing System Demo")
    print("=" * 50)
    
    # Initialize the enhanced attack suite
    try:
        suite = EnhancedAttackSuite()
        print("✅ Enhanced Attack Suite initialized")
    except Exception as e:
        print(f"❌ Failed to initialize attack suite: {e}")
        return
    
    # Demo target URL (using a safe test URL)
    target_url = "https://httpbin.org"  # Safe test endpoint
    
    print(f"\n🎯 Target URL: {target_url}")
    print("\n" + "=" * 50)
    
    # Demo 1: LLM-Assisted Test Generation
    print("\n🤖 Demo 1: LLM-Assisted Test Generation")
    print("-" * 40)
    
    user_request = "Test for SQL injection vulnerabilities in form inputs"
    print(f"User Request: {user_request}")
    
    try:
        llm_findings = await suite.run_llm_assisted_generation(target_url, user_request)
        print(f"✅ Generated {len(llm_findings)} test cases")
        
        for i, finding in enumerate(llm_findings[:3], 1):  # Show first 3
            print(f"  {i}. {finding.get('description', 'No description')}")
            print(f"     Severity: {finding.get('severity', 'Unknown')}")
            print(f"     Type: {finding.get('type', 'Unknown')}")
    except Exception as e:
        print(f"❌ LLM-assisted generation failed: {e}")
    
    # Demo 2: Complex Input Fuzzing
    print("\n🔍 Demo 2: Complex Input Fuzzing")
    print("-" * 40)
    
    input_types = ["json", "jwt"]
    print(f"Testing input types: {', '.join(input_types)}")
    
    try:
        fuzzing_findings = await suite.run_complex_input_fuzzing(target_url, input_types)
        print(f"✅ Found {len(fuzzing_findings)} potential issues")
        
        for i, finding in enumerate(fuzzing_findings[:3], 1):  # Show first 3
            print(f"  {i}. {finding.get('description', 'No description')}")
            print(f"     Severity: {finding.get('severity', 'Unknown')}")
            print(f"     Type: {finding.get('type', 'Unknown')}")
    except Exception as e:
        print(f"❌ Complex input fuzzing failed: {e}")
    
    # Demo 3: Security Headers Check
    print("\n🛡️ Demo 3: Security Headers Check")
    print("-" * 40)
    
    try:
        header_findings = await suite._check_security_headers(target_url)
        print(f"✅ Checked security headers")
        
        if header_findings:
            print(f"Found {len(header_findings)} missing security headers:")
            for i, finding in enumerate(header_findings, 1):
                print(f"  {i}. {finding.get('description', 'No description')}")
                print(f"     Recommendation: {finding.get('recommendation', 'No recommendation')}")
        else:
            print("✅ All security headers present")
    except Exception as e:
        print(f"❌ Security headers check failed: {e}")
    
    # Demo 4: Error Message Analysis
    print("\n🔍 Demo 4: Error Message Analysis")
    print("-" * 40)
    
    try:
        error_findings = await suite._check_error_messages(target_url)
        print(f"✅ Analyzed error messages")
        
        if error_findings:
            print(f"Found {len(error_findings)} potential information disclosures:")
            for i, finding in enumerate(error_findings, 1):
                print(f"  {i}. {finding.get('description', 'No description')}")
                print(f"     Evidence: {finding.get('evidence', 'No evidence')}")
        else:
            print("✅ No sensitive information found in error messages")
    except Exception as e:
        print(f"❌ Error message analysis failed: {e}")
    
    # Demo 5: Business Logic Templates
    print("\n🏢 Demo 5: Business Logic Template Testing")
    print("-" * 40)
    
    business_type = "ecommerce"
    print(f"Testing business type: {business_type}")
    
    try:
        template_findings = await suite.run_business_logic_templates(target_url, business_type)
        print(f"✅ Executed business logic templates")
        
        if template_findings:
            print(f"Found {len(template_findings)} business logic issues:")
            for i, finding in enumerate(template_findings, 1):
                print(f"  {i}. {finding.get('description', 'No description')}")
                print(f"     Severity: {finding.get('severity', 'Unknown')}")
        else:
            print("✅ No business logic vulnerabilities detected")
    except Exception as e:
        print(f"❌ Business logic template testing failed: {e}")
    
    # Demo 6: False-Positive Reduction
    print("\n🎯 Demo 6: False-Positive Reduction")
    print("-" * 40)
    
    # Combine all findings
    all_findings = []
    try:
        all_findings.extend(llm_findings)
        all_findings.extend(fuzzing_findings)
        all_findings.extend(header_findings)
        all_findings.extend(error_findings)
        all_findings.extend(template_findings)
        
        print(f"Total findings before filtering: {len(all_findings)}")
        
        filtered_findings = await suite.run_false_positive_reduction(all_findings)
        print(f"Total findings after filtering: {len(filtered_findings)}")
        
        if filtered_findings:
            print("\nVerified findings:")
            for i, finding in enumerate(filtered_findings, 1):
                confidence = finding.get('confidence_score', 0)
                print(f"  {i}. {finding.get('description', 'No description')}")
                print(f"     Confidence: {confidence:.2f}")
                print(f"     Verified: {finding.get('verified', False)}")
    except Exception as e:
        print(f"❌ False-positive reduction failed: {e}")
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 DEMO SUMMARY")
    print("=" * 50)
    
    print(f"✅ Enhanced Attack Suite: 11 attack types available")
    print(f"✅ LLM Integration: Gemini AI for test generation")
    print(f"✅ Complex Input Fuzzing: JSON, GraphQL, JWT, File Upload")
    print(f"✅ Security Headers: Comprehensive header analysis")
    print(f"✅ Error Analysis: Information disclosure detection")
    print(f"✅ Business Logic: Template-based testing")
    print(f"✅ False-Positive Reduction: Confidence scoring and verification")
    
    print("\n🎉 Demo completed successfully!")
    print("\nTo use the full system:")
    print("1. Start the backend: cd backend && python main.py")
    print("2. Start the frontend: cd frontend && npm start")
    print("3. Navigate to /agentic for the AI chat interface")
    print("4. Describe what you want to test in natural language")

if __name__ == "__main__":
    asyncio.run(demo_agentic_system())
