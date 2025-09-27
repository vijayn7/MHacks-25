#!/bin/bash

echo "🎬 AegisWeb Demo Script"
echo "======================="

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_demo() {
    echo -e "${BLUE}[DEMO]${NC} $1"
}

print_action() {
    echo -e "${GREEN}[ACTION]${NC} $1"
}

print_wait() {
    echo -e "${YELLOW}[WAIT]${NC} $1"
}

echo ""
print_demo "This script demonstrates AegisWeb's key features"
echo ""

print_action "1. Starting vulnerable demo app..."
cd demo-app
npm start &
DEMO_PID=$!
cd ..

print_wait "Waiting for demo app to start..."
sleep 5

print_action "2. Starting backend API..."
cd backend
python main.py &
BACKEND_PID=$!
cd ..

print_wait "Waiting for backend to start..."
sleep 3

print_action "3. Testing API endpoints..."
echo ""
echo "Testing vulnerable endpoints:"

echo "🔍 Testing missing headers:"
curl -I http://localhost:3001/ | head -10

echo ""
echo "🔍 Testing CORS misconfiguration:"
curl -H "Origin: https://evil.com" http://localhost:3001/api/sensitive

echo ""
echo "🔍 Testing reflected XSS:"
curl "http://localhost:3001/search?q=INJTEST_12345"

echo ""
echo "🔍 Testing open redirect:"
curl -I "http://localhost:3001/redirect?url=https://google.com" | grep Location

echo ""
print_action "4. Running crawler test..."
cd crawler
python -c "
import asyncio
from crawler import WebCrawler

async def test():
    crawler = WebCrawler('demo_test')
    result = await crawler.crawl('http://localhost:3001', max_pages=3)
    print(f'✅ Crawled {result[\"pages_crawled\"]} pages in {result[\"duration_seconds\"]}s')

asyncio.run(test())
"
cd ..

print_action "5. Running header scanner test..."
cd scanner
python -c "
from pathlib import Path
from header_scanner import HeaderScanner

if Path('../crawler/artifacts/demo_test/pages.json').exists():
    scanner = HeaderScanner('demo_test')
    findings = scanner.scan_pages(Path('../crawler/artifacts/demo_test/pages.json'))
    scanner.save_findings(Path('../crawler/artifacts/demo_test'))
    print(f'✅ Found {len(findings)} security issues')
else:
    print('❌ No crawler output found')
"
cd ..

echo ""
print_demo "Demo complete! Key findings:"
echo "• Missing X-Frame-Options (Clickjacking vulnerability)"
echo "• Permissive CORS configuration"
echo "• Reflected XSS in search endpoint"
echo "• Open redirect vulnerability"
echo "• Missing security headers (CSP, HSTS, etc.)"
echo ""
print_action "Now start the frontend with: cd frontend && npm start"
print_action "Then visit http://localhost:3000 to see the full UI!"

# Cleanup
print_wait "Cleaning up background processes..."
kill $DEMO_PID 2>/dev/null
kill $BACKEND_PID 2>/dev/null