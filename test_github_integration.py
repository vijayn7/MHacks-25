#!/usr/bin/env python3
"""
Test GitHub App Integration
"""

import os
import asyncio
import sys
from pathlib import Path

# Add scanner directory to path
sys.path.append(str(Path(__file__).parent / "scanner"))

async def test_github_integration():
    """Test GitHub App integration"""
    print("🧪 Testing GitHub App Integration")
    print("=" * 40)
    
    # Check environment variables
    required_vars = [
        "GITHUB_APP_ID",
        "GITHUB_CLIENT_ID", 
        "GITHUB_CLIENT_SECRET",
        "GITHUB_PRIVATE_KEY_PATH"
    ]
    
    missing_vars = []
    for var in required_vars:
        if not os.getenv(var) or os.getenv(var) == f"your_{var.lower()}_here":
            missing_vars.append(var)
    
    if missing_vars:
        print(f"❌ Missing environment variables: {', '.join(missing_vars)}")
        print("   Please update your .env file with the correct values")
        return False
    
    print("✅ Environment variables configured")
    
    # Check private key file
    private_key_path = os.getenv("GITHUB_PRIVATE_KEY_PATH")
    if not os.path.exists(private_key_path):
        print(f"❌ Private key file not found: {private_key_path}")
        print("   Please save your GitHub App private key as github_app_private_key.pem")
        return False
    
    print("✅ Private key file found")
    
    # Test GitHub API access
    try:
        from github_code_analyzer import GitHubCodeAnalyzer
        
        analyzer = GitHubCodeAnalyzer()
        print("✅ GitHub Code Analyzer initialized")
        
        # Test with a public repository
        print("🔍 Testing repository analysis...")
        code_files = await analyzer.analyze_repository("octocat", "Hello-World", "main")
        
        if code_files:
            print(f"✅ Successfully analyzed {len(code_files)} files")
            print("   GitHub App integration is working!")
            return True
        else:
            print("⚠️  No files analyzed (this might be normal for some repositories)")
            return True
            
    except Exception as e:
        print(f"❌ GitHub API test failed: {str(e)}")
        return False

async def main():
    """Main test function"""
    success = await test_github_integration()
    
    if success:
        print("\n🎉 GitHub App integration test passed!")
        print("   You can now use the agentic security testing system")
    else:
        print("\n❌ GitHub App integration test failed!")
        print("   Please check the setup instructions in GITHUB_APP_SETUP.md")

if __name__ == "__main__":
    asyncio.run(main())
