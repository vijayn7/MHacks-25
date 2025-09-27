#!/bin/bash

echo "🛡️  Setting up Swarm - Web Security Scanner"
echo "============================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    print_error "Node.js is not installed. Please install Node.js first."
    exit 1
fi

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed. Please install Python 3 first."
    exit 1
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    print_error "pip3 is not installed. Please install pip3 first."
    exit 1
fi

print_status "Installing demo app dependencies..."
cd demo-app
if npm install; then
    print_success "Demo app dependencies installed"
else
    print_error "Failed to install demo app dependencies"
    exit 1
fi
cd ..

print_status "Installing backend dependencies..."
cd backend
if pip3 install -r requirements.txt; then
    print_success "Backend dependencies installed"
else
    print_error "Failed to install backend dependencies"
    exit 1
fi
cd ..

print_status "Installing crawler dependencies..."
cd crawler
if pip3 install -r requirements.txt; then
    print_success "Crawler dependencies installed"
else
    print_error "Failed to install crawler dependencies"
    exit 1
fi

print_status "Installing Playwright browsers..."
if playwright install; then
    print_success "Playwright browsers installed"
else
    print_error "Failed to install Playwright browsers"
    exit 1
fi
cd ..

print_status "Installing frontend dependencies..."
cd frontend
if npm install; then
    print_success "Frontend dependencies installed"
else
    print_error "Failed to install frontend dependencies"
    exit 1
fi
cd ..

print_success "🎉 Dependencies installed successfully!"
echo ""

# MongoDB setup check
print_status "Checking MongoDB setup..."

if [ -f "backend/.env" ]; then
    print_success "Found backend/.env file"
else
    print_warning "No backend/.env file found"
    echo ""
    echo "📋 MongoDB Setup Required:"
    echo "=========================="
    echo ""
    echo "You need to set up MongoDB before running Swarm."
    echo "Choose one option:"
    echo ""
    echo "Option 1 - MongoDB Atlas (Cloud, Recommended):"
    echo "  1. Go to https://www.mongodb.com/atlas"
    echo "  2. Create free account and cluster"
    echo "  3. Get connection string"
    echo "  4. Create backend/.env file with:"
    echo "     MONGODB_URL=mongodb+srv://user:pass@cluster.mongodb.net/swarm_db"
    echo ""
    echo "Option 2 - Local MongoDB:"
    echo "  macOS: brew install mongodb-community && brew services start mongodb-community"
    echo "  Ubuntu: sudo apt install mongodb"
    echo "  Create backend/.env file with:"
    echo "     MONGODB_URL=mongodb://localhost:27017"
    echo ""
    echo "📖 See MONGODB_SETUP.md for detailed instructions"
    echo ""
fi

# Test database connection if .env exists
if [ -f "backend/.env" ]; then
    print_status "Testing database connection..."
    cd backend
    if python database.py; then
        print_success "Database connection successful!"
    else
        print_error "Database connection failed. Check your .env file and MongoDB setup."
        echo "See MONGODB_SETUP.md for troubleshooting."
    fi
    cd ..
fi

echo ""
print_success "🚀 Setup complete!"
echo ""
echo "🔥 Quick Start:"
echo "==============="
echo ""
echo "1. Set up MongoDB (if not done already):"
echo "   See MONGODB_SETUP.md for instructions"
echo ""
echo "2. Start the vulnerable demo app:"
echo "   cd demo-app && npm start"
echo "   (Runs on http://localhost:3001)"
echo ""
echo "3. Start the backend API:"
echo "   cd backend && python main.py"
echo "   (Runs on http://localhost:8000)"
echo ""
echo "4. Start the frontend:"
echo "   cd frontend && npm start"
echo "   (Runs on http://localhost:3000)"
echo ""
echo "5. Open http://localhost:3000 and scan http://localhost:3001"
echo ""
print_warning "⚠️  Only scan websites you own or have permission to test!"