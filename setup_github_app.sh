#!/bin/bash

# GitHub App Setup Script for Swarm Security Scanner

echo "🚀 Setting up GitHub App for Swarm Security Scanner"
echo "=================================================="

# Check if required tools are installed
if ! command -v jq &> /dev/null; then
    echo "❌ jq is required but not installed."
    echo "   Install with: brew install jq (macOS) or apt-get install jq (Ubuntu)"
    exit 1
fi

if ! command -v openssl &> /dev/null; then
    echo "❌ openssl is required but not installed."
    exit 1
fi

echo "✅ Required tools are available"

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file..."
    cat > .env << EOF
# GitHub App Configuration
GITHUB_APP_ID=your_app_id_here
GITHUB_CLIENT_ID=your_client_id_here
GITHUB_CLIENT_SECRET=your_client_secret_here
GITHUB_PRIVATE_KEY_PATH=./github_app_private_key.pem
GITHUB_WEBHOOK_SECRET=your_webhook_secret_here

# Gemini API Configuration
GEMINI_API_KEY=your_gemini_api_key_here

# Test Configuration
HEADLESS_MODE=true
TEST_TIMEOUT=30
SCREENSHOTS_DIR=test_screenshots

# Target Configuration
DEFAULT_TARGET_URL=https://httpbin.org
EOF
    echo "✅ Created .env file"
else
    echo "✅ .env file already exists"
fi

# Create private key file
echo "🔑 Setting up private key file..."
if [ ! -f github_app_private_key.pem ]; then
    echo "📝 Please create github_app_private_key.pem with your GitHub App private key"
    echo "   You can get this from your GitHub App settings"
    echo "   The file should start with: -----BEGIN RSA PRIVATE KEY-----"
    echo "   and end with: -----END RSA PRIVATE KEY-----"
else
    echo "✅ Private key file already exists"
fi

# Create webhook secret
echo "🔐 Generating webhook secret..."
if ! grep -q "GITHUB_WEBHOOK_SECRET=" .env || grep -q "your_webhook_secret_here" .env; then
    WEBHOOK_SECRET=$(openssl rand -hex 32)
    sed -i.bak "s/GITHUB_WEBHOOK_SECRET=your_webhook_secret_here/GITHUB_WEBHOOK_SECRET=$WEBHOOK_SECRET/" .env
    echo "✅ Generated webhook secret: $WEBHOOK_SECRET"
    echo "   Add this to your GitHub App webhook settings"
else
    echo "✅ Webhook secret already configured"
fi

# Create GitHub App configuration file
echo "📋 Creating GitHub App configuration..."
cat > github_app_config.json << EOF
{
  "app_id": "your_app_id_here",
  "client_id": "your_client_id_here",
  "client_secret": "your_client_secret_here",
  "private_key_path": "./github_app_private_key.pem",
  "webhook_secret": "your_webhook_secret_here",
  "permissions": {
    "contents": "read",
    "metadata": "read",
    "pull_requests": "write",
    "actions": "write",
    "issues": "write"
  },
  "events": [
    "push",
    "pull_request",
    "issues",
    "workflow_run"
  ]
}
EOF

echo "✅ Created github_app_config.json"

# Create setup instructions
echo "📚 Creating setup instructions..."
cat > GITHUB_APP_SETUP.md << 'EOF'
# GitHub App Setup Instructions

## 1. Create GitHub App

1. Go to [GitHub.com](https://github.com) → Settings → Developer settings → GitHub Apps
2. Click "New GitHub App"
3. Fill in the details:
   - **GitHub App name**: Swarm Security Scanner
   - **Homepage URL**: https://your-domain.com
   - **User authorization callback URL**: https://your-domain.com/auth/callback
   - **Webhook URL**: https://your-domain.com/webhook
   - **Webhook secret**: (use the generated secret from .env)

## 2. Set Permissions

Set these repository permissions:
- Contents: Read
- Metadata: Read
- Pull requests: Write
- Actions: Write
- Issues: Write

## 3. Subscribe to Events

Check these events:
- Push
- Pull request
- Issues
- Workflow run

## 4. Get Credentials

After creating the app, get:
- App ID
- Client ID
- Client Secret
- Private Key (download as .pem file)

## 5. Update Configuration

1. Update .env file with your credentials
2. Save your private key as github_app_private_key.pem
3. Update webhook secret in GitHub App settings

## 6. Install App

1. Go to your app page
2. Click "Install App"
3. Select repositories to test
4. Click "Install"

## 7. Test Integration

Run the test script:
```bash
python3 test_github_integration.py
```

## 8. Set Up Webhook

If you're running locally, use ngrok:
```bash
# Install ngrok
brew install ngrok  # macOS
# or download from https://ngrok.com

# Start ngrok
ngrok http 8000

# Use the ngrok URL as your webhook URL
# Example: https://abc123.ngrok.io/webhook
```

## 9. Configure Repository

1. Copy .github/workflows/agentic-security-tests.yml to your repository
2. Add GITHUB_TOKEN to repository secrets
3. Push to trigger the workflow

## Troubleshooting

### Common Issues:

1. **Webhook not receiving events**:
   - Check webhook URL is accessible
   - Verify webhook secret matches
   - Check GitHub App permissions

2. **Authentication errors**:
   - Verify App ID and Client ID
   - Check private key format
   - Ensure app is installed on repository

3. **Permission denied**:
   - Check repository permissions
   - Verify app is installed
   - Check token scopes

### Debug Commands:

```bash
# Test GitHub API access
curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user

# Test webhook
curl -X POST https://your-domain.com/webhook \
  -H "Content-Type: application/json" \
  -d '{"test": "webhook"}'

# Check app installation
curl -H "Authorization: token $GITHUB_TOKEN" \
  https://api.github.com/app/installations
```
EOF

echo "✅ Created GITHUB_APP_SETUP.md"

# Create test script
echo "🧪 Creating test script..."
cat > test_github_integration.py << 'EOF'
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
EOF

chmod +x test_github_integration.py
echo "✅ Created test_github_integration.py"

# Create ngrok setup script
echo "🌐 Creating ngrok setup script..."
cat > setup_ngrok.sh << 'EOF'
#!/bin/bash

# Ngrok Setup Script for Local Development

echo "🌐 Setting up ngrok for local development"
echo "========================================"

# Check if ngrok is installed
if ! command -v ngrok &> /dev/null; then
    echo "❌ ngrok is not installed"
    echo "   Install with: brew install ngrok (macOS)"
    echo "   Or download from: https://ngrok.com/download"
    exit 1
fi

echo "✅ ngrok is installed"

# Start ngrok
echo "🚀 Starting ngrok on port 8000..."
echo "   This will create a public URL for your local server"
echo "   Use this URL as your webhook URL in GitHub App settings"
echo ""
echo "   Example: https://abc123.ngrok.io/webhook"
echo ""

# Start ngrok in background
ngrok http 8000 &
NGROK_PID=$!

# Wait a moment for ngrok to start
sleep 3

# Get the public URL
NGROK_URL=$(curl -s http://localhost:4040/api/tunnels | jq -r '.tunnels[0].public_url')

if [ "$NGROK_URL" != "null" ] && [ -n "$NGROK_URL" ]; then
    echo "✅ Ngrok started successfully!"
    echo "   Public URL: $NGROK_URL"
    echo "   Webhook URL: $NGROK_URL/webhook"
    echo ""
    echo "📝 Update your GitHub App webhook URL to: $NGROK_URL/webhook"
    echo ""
    echo "Press Ctrl+C to stop ngrok"
    
    # Wait for user to stop
    wait $NGROK_PID
else
    echo "❌ Failed to get ngrok URL"
    kill $NGROK_PID
    exit 1
fi
EOF

chmod +x setup_ngrok.sh
echo "✅ Created setup_ngrok.sh"

echo ""
echo "🎉 GitHub App setup script completed!"
echo ""
echo "Next steps:"
echo "1. 📖 Read GITHUB_APP_SETUP.md for detailed instructions"
echo "2. 🔧 Update .env file with your GitHub App credentials"
echo "3. 🔑 Save your private key as github_app_private_key.pem"
echo "4. 🧪 Run: python3 test_github_integration.py"
echo "5. 🌐 For local development, run: ./setup_ngrok.sh"
echo ""
echo "Happy testing! 🚀"
