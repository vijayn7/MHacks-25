#!/bin/bash

echo "🚀 Starting Swarm Web Security Scanner"
echo "======================================"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

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

# Check if MongoDB is configured
if [ ! -f "backend/.env" ]; then
    print_error "MongoDB not configured! Please run ./setup.sh first."
    exit 1
fi

# Test database connection
print_status "Testing database connection..."
cd backend
if python database.py > /dev/null 2>&1; then
    print_success "Database connection successful"
else
    print_error "Database connection failed. Check MONGODB_SETUP.md"
    exit 1
fi
cd ..

echo ""
print_status "Starting all services..."
echo ""

# Function to kill background processes on exit
cleanup() {
    print_warning "Shutting down services..."
    kill $DEMO_PID $BACKEND_PID $FRONTEND_PID 2>/dev/null
    exit 0
}

trap cleanup SIGINT SIGTERM

# Start demo app
print_status "Starting vulnerable demo app on http://localhost:3001..."
cd demo-app
npm start > ../demo-app.log 2>&1 &
DEMO_PID=$!
cd ..

# Wait for demo app to start
sleep 3

# Start backend
print_status "Starting backend API on http://localhost:8000..."
cd backend
python main.py > ../backend.log 2>&1 &
BACKEND_PID=$!
cd ..

# Wait for backend to start
sleep 3

# Test backend health
if curl -s http://localhost:8000/health > /dev/null; then
    print_success "Backend API is healthy"
else
    print_error "Backend API failed to start"
    cleanup
fi

# Start frontend
print_status "Starting frontend on http://localhost:3000..."
cd frontend
npm start > ../frontend.log 2>&1 &
FRONTEND_PID=$!
cd ..

echo ""
print_success "🎉 All services started successfully!"
echo ""
echo "📊 Service URLs:"
echo "=================="
echo "🎯 Frontend (Main App):    http://localhost:3000"
echo "🔌 Backend API:            http://localhost:8000"
echo "🎯 Demo Vulnerable App:    http://localhost:3001"
echo "💊 API Health Check:       http://localhost:8000/health"
echo ""
echo "📋 How to Use:"
echo "==============="
echo "1. Open http://localhost:3000 in your browser"
echo "2. Enter target URL: http://localhost:3001"
echo "3. Accept consent and start scan"
echo "4. View real-time results with fix snippets"
echo ""
echo "📝 Log Files:"
echo "=============="
echo "Demo App:  tail -f demo-app.log"
echo "Backend:   tail -f backend.log"
echo "Frontend:  tail -f frontend.log"
echo ""
print_warning "Press Ctrl+C to stop all services"
echo ""

# Wait for user interrupt
while true; do
    sleep 1
done