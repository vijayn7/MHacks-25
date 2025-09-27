import asyncio
import json
import os
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from playwright.async_api import async_playwright, Browser, Page
from bs4 import BeautifulSoup
import requests


class WebCrawler:
    def __init__(self, run_id: str, output_dir: str = "artifacts"):
        self.run_id = run_id
        self.output_dir = Path(output_dir) / run_id
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.visited_urls: Set[str] = set()
        self.pages_data: List[Dict] = []
        self.cookies_data: List[Dict] = []

    async def crawl(self, start_url: str, max_pages: int = 30) -> Dict:
        """Crawl website starting from start_url up to max_pages"""

        print(f"🕷️  Starting crawl of {start_url} (max {max_pages} pages)")
        start_time = time.time()

        try:
            async with async_playwright() as p:
                # Launch browser with additional options for stability
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        '--no-sandbox',
                        '--disable-setuid-sandbox',
                        '--disable-dev-shm-usage',
                        '--disable-accelerated-2d-canvas',
                        '--no-first-run',
                        '--no-zygote',
                        '--disable-gpu'
                    ]
                )
                context = await browser.new_context(
                    user_agent="AegisWeb-Scanner/1.0 (Security Scanner)",
                    viewport={"width": 1280, "height": 720}
                )

                # Enable request/response logging
                page = await context.new_page()

                # Set up request/response interceptors
                page.on("response", self._handle_response)

                try:
                    await self._crawl_recursive(page, start_url, max_pages)

                    # Test frameability
                    await self._test_frameability(page, start_url)

                    # Collect cookies
                    await self._collect_cookies(context, start_url)

                finally:
                    await browser.close()

        except Exception as e:
            print(f"❌ Playwright crawler failed: {str(e)}")
            print("🔄 Falling back to simple crawler...")
            return await self._fallback_crawl(start_url, max_pages, start_time)

        # Save results
        await self._save_results()

        end_time = time.time()

        return {
            "run_id": self.run_id,
            "start_url": start_url,
            "pages_crawled": len(self.pages_data),
            "duration_seconds": round(end_time - start_time, 2),
            "output_dir": str(self.output_dir)
        }

    async def _crawl_recursive(self, page: Page, url: str, remaining_pages: int, depth: int = 0):
        """Recursively crawl pages"""

        if remaining_pages <= 0 or url in self.visited_urls:
            return

        if depth > 3:  # Limit recursion depth
            return

        try:
            print(f"  📄 Crawling: {url}")
            self.visited_urls.add(url)

            # Navigate to page
            response = await page.goto(url, wait_until="networkidle", timeout=30000)

            if not response or response.status >= 400:
                print(f"    ❌ Failed to load {url}: {response.status if response else 'No response'}")
                return

            # Wait for page to stabilize
            await page.wait_for_timeout(1000)

            # Capture page data
            page_data = await self._capture_page_data(page, url, response)
            self.pages_data.append(page_data)

            # Find links to follow
            links = await self._extract_links(page, url)

            # Follow links
            for link in links[:max(1, remaining_pages - 1)]:
                await self._crawl_recursive(page, link, remaining_pages - 1, depth + 1)
                remaining_pages -= 1
                if remaining_pages <= 0:
                    break

        except Exception as e:
            print(f"    ❌ Error crawling {url}: {str(e)}")

    async def _capture_page_data(self, page: Page, url: str, response) -> Dict:
        """Capture comprehensive page data"""

        # Take screenshot
        screenshot_path = self.output_dir / f"screenshot_{len(self.pages_data)}.png"
        await page.screenshot(path=screenshot_path, full_page=True)

        # Get HTML content
        html_content = await page.content()

        # Parse with BeautifulSoup for analysis
        soup = BeautifulSoup(html_content, 'html.parser')

        # Extract forms
        forms = []
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }

            for input_elem in form.find_all(['input', 'textarea', 'select']):
                form_data['inputs'].append({
                    'name': input_elem.get('name', ''),
                    'type': input_elem.get('type', 'text'),
                    'value': input_elem.get('value', '')
                })

            forms.append(form_data)

        # Extract scripts
        scripts = []
        for script in soup.find_all('script'):
            src = script.get('src')
            if src:
                scripts.append({'type': 'external', 'src': src})
            elif script.string:
                scripts.append({'type': 'inline', 'content': script.string[:200] + '...' if len(script.string) > 200 else script.string})

        # Extract meta tags
        meta_tags = {}
        for meta in soup.find_all('meta'):
            name = meta.get('name') or meta.get('property') or meta.get('http-equiv')
            content = meta.get('content')
            if name and content:
                meta_tags[name] = content

        # Get cookies
        cookies = await page.context.cookies(url)

        return {
            'url': url,
            'status_code': response.status,
            'headers': dict(response.headers),
            'title': soup.title.string if soup.title else '',
            'html_snippet': html_content[:1000] + '...' if len(html_content) > 1000 else html_content,
            'screenshot_path': str(screenshot_path.name),
            'forms': forms,
            'scripts': scripts,
            'meta_tags': meta_tags,
            'cookies': [
                {
                    'name': cookie['name'],
                    'value': cookie['value'][:50] + '...' if len(cookie['value']) > 50 else cookie['value'],
                    'domain': cookie['domain'],
                    'path': cookie['path'],
                    'secure': cookie.get('secure', False),
                    'httpOnly': cookie.get('httpOnly', False),
                    'sameSite': cookie.get('sameSite', '')
                }
                for cookie in cookies
            ],
            'timestamp': datetime.now().isoformat()
        }

    async def _extract_links(self, page: Page, base_url: str) -> List[str]:
        """Extract same-origin links from page"""

        base_domain = urlparse(base_url).netloc
        links = []

        # Get all links
        link_elements = await page.query_selector_all('a[href]')

        for element in link_elements:
            href = await element.get_attribute('href')
            if not href:
                continue

            # Resolve relative URLs
            full_url = urljoin(base_url, href)
            parsed = urlparse(full_url)

            # Only follow same-origin links
            if parsed.netloc == base_domain and full_url not in self.visited_urls:
                # Skip common non-content URLs
                if not any(skip in full_url.lower() for skip in ['logout', 'signout', 'delete', 'remove', 'javascript:', 'mailto:', 'tel:']):
                    links.append(full_url)

        return list(set(links))[:10]  # Limit links per page

    async def _test_frameability(self, page: Page, url: str):
        """Test if page can be framed (clickjacking test)"""

        try:
            # Create iframe test HTML
            iframe_test_html = f"""
            <!DOCTYPE html>
            <html>
            <head><title>Frame Test</title></head>
            <body>
                <h1>Iframe Test</h1>
                <iframe src="{url}" width="800" height="600" id="test-frame"></iframe>
                <script>
                    setTimeout(() => {{
                        try {{
                            const frame = document.getElementById('test-frame');
                            const result = {{
                                can_frame: true,
                                src: frame.src,
                                loaded: frame.contentDocument !== null
                            }};
                            window.frameTestResult = result;
                        }} catch(e) {{
                            window.frameTestResult = {{ can_frame: false, error: e.message }};
                        }}
                    }}, 3000);
                </script>
            </body>
            </html>
            """

            # Save test HTML
            test_file = self.output_dir / "frame_test.html"
            with open(test_file, 'w') as f:
                f.write(iframe_test_html)

            # Navigate to test page
            await page.goto(f"file://{test_file.absolute()}")
            await page.wait_for_timeout(4000)

            # Get result
            result = await page.evaluate("window.frameTestResult")

            # Save frameability result
            frame_result = {
                'url': url,
                'can_frame': result.get('can_frame', False) if result else True,
                'test_timestamp': datetime.now().isoformat(),
                'evidence_file': 'frame_test.html'
            }

            with open(self.output_dir / "frameability_test.json", 'w') as f:
                json.dump(frame_result, f, indent=2)

            print(f"    🖼️  Frame test: {'Vulnerable' if frame_result['can_frame'] else 'Protected'}")

        except Exception as e:
            print(f"    ❌ Frame test failed: {str(e)}")

    async def _collect_cookies(self, context, start_url: str):
        """Collect and analyze cookies"""

        try:
            cookies = await context.cookies()

            cookie_analysis = []
            for cookie in cookies:
                analysis = {
                    'name': cookie['name'],
                    'domain': cookie['domain'],
                    'path': cookie['path'],
                    'secure': cookie.get('secure', False),
                    'httpOnly': cookie.get('httpOnly', False),
                    'sameSite': cookie.get('sameSite', ''),
                    'issues': []
                }

                # Check for security issues
                if not analysis['secure'] and 'https' in start_url:
                    analysis['issues'].append('Missing Secure flag on HTTPS site')

                if not analysis['httpOnly']:
                    analysis['issues'].append('Missing HttpOnly flag')

                if not analysis['sameSite']:
                    analysis['issues'].append('Missing SameSite attribute')

                cookie_analysis.append(analysis)

            # Save cookie analysis
            with open(self.output_dir / "cookie_analysis.json", 'w') as f:
                json.dump(cookie_analysis, f, indent=2)

        except Exception as e:
            print(f"    ❌ Cookie analysis failed: {str(e)}")

    def _handle_response(self, response):
        """Handle response for header collection"""
        # This is called for every response - we'll process headers here
        pass

    async def _fallback_crawl(self, start_url: str, max_pages: int, start_time: float) -> Dict:
        """Fallback to simple HTTP crawler when Playwright fails"""
        
        print(f"🔄 Using simple HTTP crawler fallback")
        
        # Import the simple crawler functionality
        import requests
        from bs4 import BeautifulSoup
        
        # Set up session
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'AegisWeb-Scanner/1.0 (Security Scanner)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        try:
            await self._simple_crawl_recursive(session, start_url, max_pages)
            
            # Save results
            await self._save_results()
            
            end_time = time.time()
            
            return {
                "run_id": self.run_id,
                "start_url": start_url,
                "pages_crawled": len(self.pages_data),
                "duration_seconds": round(end_time - start_time, 2),
                "output_dir": str(self.output_dir),
                "method": "simple_fallback"
            }
            
        except Exception as e:
            print(f"❌ Simple crawler also failed: {str(e)}")
            return {"error": str(e), "method": "simple_fallback"}

    async def _simple_crawl_recursive(self, session, url: str, remaining_pages: int, depth: int = 0):
        """Simple HTTP-based recursive crawling"""
        
        if remaining_pages <= 0 or url in self.visited_urls or depth > 2:
            return
            
        try:
            print(f"  📄 Simple crawling: {url}")
            self.visited_urls.add(url)
            
            # Make request
            response = session.get(url, timeout=10)
            
            if response.status_code >= 400:
                print(f"    ❌ Failed to load {url}: {response.status_code}")
                return
            
            # Parse HTML
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Capture page data (simplified version)
            page_data = await self._simple_capture_page_data(url, response, soup)
            self.pages_data.append(page_data)
            
            # Find links to follow
            if remaining_pages > 1:
                links = await self._simple_extract_links(soup, url)
                for link in links[:min(3, remaining_pages - 1)]:
                    await self._simple_crawl_recursive(session, link, remaining_pages - 1, depth + 1)
                    remaining_pages -= 1
                    if remaining_pages <= 0:
                        break
                        
        except Exception as e:
            print(f"    ❌ Error simple crawling {url}: {str(e)}")

    async def _simple_capture_page_data(self, url: str, response, soup) -> Dict:
        """Simple page data capture without screenshots"""
        
        # Extract forms
        forms = []
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }
            
            for input_elem in form.find_all(['input', 'textarea', 'select']):
                form_data['inputs'].append({
                    'name': input_elem.get('name', ''),
                    'type': input_elem.get('type', 'text'),
                    'value': input_elem.get('value', '')
                })
            
            forms.append(form_data)
        
        # Extract scripts
        scripts = []
        for script in soup.find_all('script'):
            src = script.get('src')
            if src:
                scripts.append({'type': 'external', 'src': src})
            elif script.string:
                scripts.append({
                    'type': 'inline', 
                    'content': script.string[:200] + '...' if len(script.string) > 200 else script.string
                })
        
        # Extract meta tags
        meta_tags = {}
        for meta in soup.find_all('meta'):
            name = meta.get('name') or meta.get('property') or meta.get('http-equiv')
            content = meta.get('content')
            if name and content:
                meta_tags[name] = content
        
        # Get cookies from response
        cookies = []
        for cookie in response.cookies:
            cookies.append({
                'name': cookie.name,
                'value': cookie.value[:50] + '...' if len(cookie.value) > 50 else cookie.value,
                'domain': cookie.domain,
                'path': cookie.path,
                'secure': cookie.secure,
                'httpOnly': getattr(cookie, 'httponly', False),
                'sameSite': getattr(cookie, 'samesite', '')
            })
        
        return {
            'url': url,
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'title': soup.title.string if soup.title else '',
            'html_snippet': response.text[:1000] + '...' if len(response.text) > 1000 else response.text,
            'screenshot_path': None,  # No screenshots in simple mode
            'forms': forms,
            'scripts': scripts,
            'meta_tags': meta_tags,
            'cookies': cookies,
            'timestamp': datetime.now().isoformat(),
            'method': 'simple_fallback'
        }

    async def _simple_extract_links(self, soup, base_url: str) -> List[str]:
        """Simple link extraction"""
        
        base_domain = urlparse(base_url).netloc
        links = []
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            if not href:
                continue
                
            # Resolve relative URLs
            full_url = urljoin(base_url, href)
            parsed = urlparse(full_url)
            
            # Only follow same-origin links
            if parsed.netloc == base_domain and full_url not in self.visited_urls:
                # Skip common non-content URLs
                if not any(skip in full_url.lower() for skip in [
                    'logout', 'signout', 'delete', 'remove', 'javascript:', 'mailto:', 'tel:'
                ]):
                    links.append(full_url)
        
        return list(set(links))[:5]  # Limit links per page

    async def _save_results(self):
        """Save crawling results to JSON"""

        results = {
            'run_id': self.run_id,
            'pages': self.pages_data,
            'summary': {
                'total_pages': len(self.pages_data),
                'unique_domains': len(set(urlparse(page['url']).netloc for page in self.pages_data)),
                'forms_found': sum(len(page.get('forms', [])) for page in self.pages_data),
                'scripts_found': sum(len(page.get('scripts', [])) for page in self.pages_data),
            },
            'timestamp': datetime.now().isoformat()
        }

        # Save main results
        with open(self.output_dir / "pages.json", 'w') as f:
            json.dump(results, f, indent=2)

        print(f"  💾 Saved results to {self.output_dir}/pages.json")


async def main():
    """Test the crawler"""

    crawler = WebCrawler("test_run")
    result = await crawler.crawl("http://localhost:3001", max_pages=5)
    print(f"✅ Crawl completed: {result}")


if __name__ == "__main__":
    asyncio.run(main())
