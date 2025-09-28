#!/bin/bash

echo "🔍 Setting up Dynamic Scanner Test Application..."

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js first."
    exit 1
fi

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo "❌ npm is not installed. Please install npm first."
    exit 1
fi

echo "📦 Installing dependencies..."
npm install

if [ $? -eq 0 ]; then
    echo "✅ Dependencies installed successfully!"
    echo ""
    echo "🚀 Starting the test application..."
    echo "📍 The app will be available at: http://localhost:3002"
    echo "⚠️  This app is INTENTIONALLY VULNERABLE for testing!"
    echo ""
    echo "Press Ctrl+C to stop the server"
    echo ""
    npm start
else
    echo "❌ Failed to install dependencies. Please check your npm configuration."
    exit 1
fi
