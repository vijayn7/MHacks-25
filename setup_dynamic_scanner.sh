#!/bin/bash

# Setup script for Dynamic Scanner with Gemini AI
# This script installs dependencies and configures the dynamic scanner

echo "🔐 Setting up Dynamic Scanner with Gemini AI"
echo "=============================================="
echo

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    echo "   Please install Python 3.8 or higher and try again."
    exit 1
fi

echo "✅ Python 3 found: $(python3 --version)"
echo

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is required but not installed."
    echo "   Please install pip3 and try again."
    exit 1
fi

echo "✅ pip3 found: $(pip3 --version)"
echo

# Install dynamic scanner dependencies
echo "📦 Installing Dynamic Scanner dependencies..."
pip3 install -r scanner/dynamic_requirements.txt

if [ $? -eq 0 ]; then
    echo "✅ Dependencies installed successfully"
else
    echo "❌ Failed to install dependencies"
    exit 1
fi
echo

# Check for Gemini API key
if [ -z "$GEMINI_API_KEY" ]; then
    echo "⚠️  GEMINI_API_KEY environment variable not set"
    echo "   To enable AI-powered analysis, set your Gemini API key:"
    echo "   export GEMINI_API_KEY='your-api-key-here'"
    echo
    echo "   You can get a free API key from: https://aistudio.google.com/apikey"
    echo
else
    echo "✅ GEMINI_API_KEY is set"
fi
echo

# Create sample codebase if it doesn't exist
if [ ! -d "sample_vulnerable_app" ]; then
    echo "📁 Creating sample vulnerable codebase for testing..."
    python3 demo_dynamic_scanner.py --create-sample
    if [ $? -eq 0 ]; then
        echo "✅ Sample codebase created"
    else
        echo "⚠️  Failed to create sample codebase (this is optional)"
    fi
else
    echo "✅ Sample codebase already exists"
fi
echo

# Test the dynamic scanner
echo "🧪 Testing Dynamic Scanner..."
python3 -c "
import sys
sys.path.append('scanner')
try:
    from dynamic_scanner import DynamicScanner
    print('✅ Dynamic Scanner imports successfully')
except ImportError as e:
    print(f'❌ Import error: {e}')
    sys.exit(1)
except Exception as e:
    print(f'⚠️  Warning: {e}')
"

if [ $? -eq 0 ]; then
    echo "✅ Dynamic Scanner test passed"
else
    echo "❌ Dynamic Scanner test failed"
    exit 1
fi
echo

# Display usage instructions
echo "🚀 Dynamic Scanner Setup Complete!"
echo "=================================="
echo
echo "Usage Examples:"
echo "1. Run the demo:"
echo "   python3 demo_dynamic_scanner.py"
echo
echo "2. Run interactive demo:"
echo "   python3 demo_dynamic_scanner.py --interactive"
echo
echo "3. Run enhanced scanner:"
echo "   python3 integrate_dynamic_scanner.py"
echo
echo "4. Use in your code:"
echo "   from scanner.dynamic_scanner import DynamicScanner"
echo "   scanner = DynamicScanner()"
echo "   results = await scanner.run_full_analysis(codebase_path, target_url)"
echo
echo "Configuration:"
echo "- Set GEMINI_API_KEY for AI-powered analysis"
echo "- Modify scanner/dynamic_config.py for custom settings"
echo "- Check DYNAMIC_SCANNER_README.md for detailed documentation"
echo
echo "Happy scanning! 🔐"

