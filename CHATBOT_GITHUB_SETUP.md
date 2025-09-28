# 🤖 GitHub App Setup for Your Chatbot Agent

This guide will help you set up GitHub integration for your AI security testing chatbot, allowing it to analyze your actual code and generate targeted test cases.

## 🚀 **Quick Start**

### **Step 1: Run the Setup Script**
```bash
cd /Users/ashmi/Downloads/MHacks-25/MHacks-25
./setup_github_app.sh
```

### **Step 2: Create GitHub App**

1. **Go to GitHub Settings**:
   - Navigate to [GitHub.com](https://github.com) → Settings → Developer settings → GitHub Apps
   - Click **"New GitHub App"**

2. **Fill in App Details**:
   ```
   GitHub App name: Swarm Security Scanner
   Homepage URL: http://localhost:3000 (or your domain)
   User authorization callback URL: http://localhost:3000/auth/callback
   Webhook URL: http://localhost:3000/webhook (or your ngrok URL)
   Webhook secret: [Use the generated secret from .env file]
   ```

3. **Set Permissions**:
   ```
   Repository permissions:
   - Contents: Read (to read your code)
   - Metadata: Read (to access repository info)
   - Pull requests: Write (to comment on PRs)
   - Actions: Write (to trigger workflows)
   - Issues: Write (to create security issues)
   ```

4. **Subscribe to Events**:
   ```
   Check these events:
   - Push
   - Pull request
   - Issues
   - Workflow run
   ```

5. **Click "Create GitHub App"**

### **Step 3: Get App Credentials**

After creating the app, you'll get:
- **App ID**: Copy this to your `.env` file
- **Client ID**: Copy this to your `.env` file
- **Client Secret**: Generate and copy to your `.env` file
- **Private Key**: Download and save as `github_app_private_key.pem`

### **Step 4: Update Configuration**

Update your `.env` file with the credentials:
```bash
# GitHub App Configuration
GITHUB_APP_ID=your_app_id_here
GITHUB_CLIENT_ID=your_client_id_here
GITHUB_CLIENT_SECRET=your_client_secret_here
GITHUB_PRIVATE_KEY_PATH=./github_app_private_key.pem
GITHUB_WEBHOOK_SECRET=your_webhook_secret_here

# Gemini API Configuration
GEMINI_API_KEY=your_gemini_api_key_here
```

### **Step 5: Install the App**

1. Go to your app page
2. Click **"Install App"**
3. Select repositories you want to test
4. Click **"Install"**

## 🎯 **How It Works in Your Chatbot**

### **Chat Tab (Default)**
- Users can describe what they want to test
- AI generates generic test cases based on common patterns
- Good for quick testing without code access

### **GitHub Tab (New)**
- Users can connect to their GitHub repositories
- AI analyzes actual code to find vulnerabilities
- Generates targeted test cases based on real code
- Triggers GitHub Actions workflows for automated testing

## 🔧 **Backend Integration**

### **Add GitHub Routes to Your Backend**

The setup script created these files:
- `backend/github_integration.py` - GitHub API integration
- `scanner/github_code_analyzer.py` - Code analysis
- `scanner/github_app_client.py` - GitHub App client

### **Update Your Backend**

Your `backend/main.py` already includes the GitHub integration router:
```python
from github_integration import router as github_integration_router
app.include_router(github_integration_router, prefix="/api", tags=["github-integration"])
```

### **Add GitHub OAuth Endpoints**

Add these endpoints to your backend for GitHub authentication:

```python
# In backend/main.py
@app.get("/api/github/connect")
async def github_connect():
    """Redirect to GitHub OAuth"""
    client_id = os.getenv("GITHUB_CLIENT_ID")
    redirect_uri = "http://localhost:3000/auth/callback"
    scope = "repo,read:user"
    
    auth_url = f"https://github.com/login/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}"
    return {"auth_url": auth_url}

@app.get("/api/github/callback")
async def github_callback(code: str):
    """Handle GitHub OAuth callback"""
    # Exchange code for access token
    # Store token in session
    # Redirect to frontend
    pass

@app.get("/api/github-status")
async def github_status():
    """Check GitHub connection status"""
    # Check if user has valid GitHub token
    # Return connection status and repositories
    pass
```

## 🌐 **Local Development Setup**

### **For Local Testing with Webhooks**

1. **Install ngrok**:
   ```bash
   brew install ngrok  # macOS
   # or download from https://ngrok.com
   ```

2. **Start ngrok**:
   ```bash
   ./setup_ngrok.sh
   ```

3. **Update GitHub App webhook URL**:
   - Use the ngrok URL as your webhook URL
   - Example: `https://abc123.ngrok.io/webhook`

### **Start Your Application**

1. **Start Backend**:
   ```bash
   cd backend
   python main.py
   ```

2. **Start Frontend**:
   ```bash
   cd frontend
   npm start
   ```

3. **Test Integration**:
   ```bash
   python3 test_github_integration.py
   ```

## 🎨 **Frontend Integration**

### **New Components Added**

1. **`GitHubIntegration.js`** - GitHub connection and repository selection
2. **Updated `AgenticChat.js`** - Added GitHub tab with integration

### **How Users Interact**

1. **Open Chatbot**: Navigate to `/agentic` in your app
2. **Switch to GitHub Tab**: Click the "GitHub" tab
3. **Connect to GitHub**: Click "Connect to GitHub"
4. **Select Repository**: Choose from your repositories
5. **Describe Test**: Enter what you want to test
6. **Generate Tests**: Click "Generate Tests" or "Run Workflow"

### **User Experience Flow**

```
User opens chatbot
    ↓
Clicks "GitHub" tab
    ↓
Connects to GitHub (OAuth)
    ↓
Selects repository
    ↓
Describes what to test
    ↓
AI analyzes actual code
    ↓
Generates targeted test cases
    ↓
Executes tests via GitHub Actions
    ↓
Shows results in chat
```

## 🚨 **Security Considerations**

### **GitHub App Security**
- ✅ **Read-only access**: App only reads code, never modifies
- ✅ **Repository permissions**: Limited to selected repositories
- ✅ **Token-based auth**: Uses secure OAuth tokens
- ✅ **Webhook validation**: Validates webhook signatures

### **Test Execution Safety**
- ✅ **Non-destructive**: Tests use safe payloads
- ✅ **Controlled environment**: Tests run in GitHub Actions
- ✅ **Rate limiting**: Built-in delays between requests
- ✅ **Error handling**: Comprehensive error handling

## 🔍 **Testing Your Setup**

### **1. Test GitHub Connection**
```bash
python3 test_github_integration.py
```

### **2. Test Frontend Integration**
1. Open your app at `http://localhost:3000/agentic`
2. Click the "GitHub" tab
3. Try connecting to GitHub
4. Select a repository
5. Generate some test cases

### **3. Test Full Workflow**
1. Make a change to your repository
2. Push to GitHub
3. Check if the GitHub Action runs
4. Verify test results appear in your chatbot

## 🐛 **Troubleshooting**

### **Common Issues**

1. **"GitHub App not found"**:
   - Check App ID in `.env` file
   - Verify app is installed on repository

2. **"Permission denied"**:
   - Check repository permissions
   - Verify app has access to repository

3. **"Webhook not receiving events"**:
   - Check webhook URL is accessible
   - Verify webhook secret matches
   - Check ngrok is running (for local development)

4. **"Authentication failed"**:
   - Check Client ID and Client Secret
   - Verify private key file exists
   - Check token expiration

### **Debug Commands**

```bash
# Check environment variables
cat .env

# Test GitHub API access
curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user

# Check webhook
curl -X POST http://localhost:8000/webhook \
  -H "Content-Type: application/json" \
  -d '{"test": "webhook"}'

# Check app installation
curl -H "Authorization: token $GITHUB_TOKEN" \
  https://api.github.com/app/installations
```

## 📚 **Next Steps**

1. **Set up GitHub App** using the instructions above
2. **Test the integration** with a simple repository
3. **Customize the chatbot** for your specific needs
4. **Scale up** to your production repositories
5. **Monitor results** and adjust as needed

## 🎉 **What You'll Get**

After setup, your chatbot will be able to:

- ✅ **Analyze your actual code** for vulnerabilities
- ✅ **Generate targeted test cases** based on your specific code
- ✅ **Execute tests automatically** via GitHub Actions
- ✅ **Comment on PRs** with security findings
- ✅ **Create security issues** for critical vulnerabilities
- ✅ **Provide detailed reports** with code locations and fixes

The AI will truly understand your code and create tests that are **accurate**, **targeted**, and **actionable**!

---

**Happy Testing! 🚀🔒**
