#!/bin/bash

# Setup script for Agentic Security Testing System

echo "🚀 Setting up Agentic Security Testing System"
echo "=============================================="

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is required but not installed."
    exit 1
fi

echo "✅ Python 3 and pip3 are available"

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip3 install -r requirements.txt

# Install Playwright browsers
echo "🎭 Installing Playwright browsers..."
python3 -m playwright install

# Set up environment variables
echo "🔧 Setting up environment variables..."
if [ ! -f .env ]; then
    cat > .env << EOF
# Gemini API Configuration
GEMINI_API_KEY=your_gemini_api_key_here

# Test Configuration
HEADLESS_MODE=true
TEST_TIMEOUT=30
SCREENSHOTS_DIR=test_screenshots

# Target Configuration
DEFAULT_TARGET_URL=https://httpbin.org
EOF
    echo "📝 Created .env file - please add your Gemini API key"
else
    echo "✅ .env file already exists"
fi

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p test_screenshots
mkdir -p test_reports
mkdir -p generated_tests

# Make scripts executable
echo "🔧 Making scripts executable..."
chmod +x run_agentic_tests.py
chmod +x setup_agentic_tests.sh

echo ""
echo "✅ Setup complete!"
echo ""
echo "To get started:"
echo "1. Add your Gemini API key to the .env file"
echo "2. Run: python3 run_agentic_tests.py --demo"
echo "3. Or run: python3 run_agentic_tests.py"
echo ""
echo "For more help: python3 run_agentic_tests.py --help"
