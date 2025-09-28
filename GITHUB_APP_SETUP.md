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
