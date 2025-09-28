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
