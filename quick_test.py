#!/usr/bin/env python3
"""
Quick test script to verify the crawler integration
"""

import asyncio
import sys
import os
from pathlib import Path

# Add paths
sys.path.append('backend')
sys.path.append('crawler')

async def test_integration():
    """Test the full crawler -> scanner pipeline"""

    print("🧪 Testing Swarm Integration")
    print("=" * 40)

    # Test 1: Crawler
    print("1. Testing Crawler...")
    try:
        from crawler.crawler import WebCrawler

        crawler = WebCrawler("test_integration", "artifacts")
        result = await crawler.crawl("http://localhost:3001", max_pages=3)
        print(f"   ✅ Crawler: {result.get('pages_crawled', 0)} pages crawled")

    except Exception as e:
        print(f"   ❌ Crawler failed: {e}")
        return

    # Test 2: Scanner
    print("2. Testing Scanner...")
    try:
        sys.path.append('scanner')
        from scanner.header_scanner import HeaderScanner

        pages_file = Path("artifacts/test_integration/pages.json")
        if pages_file.exists():
            scanner = HeaderScanner("test_integration")
            findings = scanner.scan_pages(pages_file)
            print(f"   ✅ Scanner: {len(findings)} findings discovered")

            for finding in findings[:3]:  # Show first 3
                print(f"      - {finding['severity'].upper()}: {finding['title']}")
        else:
            print(f"   ❌ No pages.json found at {pages_file}")

    except Exception as e:
        print(f"   ❌ Scanner failed: {e}")
        return

    print("\n🎉 Integration test completed!")
    print("\nNext steps:")
    print("- Start demo app: cd demo-app && npm start")
    print("- Restart backend to use new integration")
    print("- Test full pipeline via frontend")

if __name__ == "__main__":
    asyncio.run(test_integration())