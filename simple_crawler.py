#!/usr/bin/env python3
"""
Simple HTTP crawler that doesn't require Playwright
Uses requests and BeautifulSoup for basic crawling
"""

import json
import requests
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup


class SimpleCrawler:
    def __init__(self, run_id: str, output_dir: str = "artifacts"):
        self.run_id = run_id
        self.output_dir = Path(output_dir) / run_id
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.visited_urls = set()
        self.pages_data = []
        
        # Set up session with proper headers
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'AegisWeb-Scanner/1.0 (Security Scanner)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })

    def crawl(self, start_url: str, max_pages: int = 5) -> Dict:
        """Crawl website starting from start_url up to max_pages"""
        
        print(f"🕷️  Starting simple crawl of {start_url} (max {max_pages} pages)")
        start_time = time.time()
        
        try:
            self._crawl_recursive(start_url, max_pages)
            
            # Save results
            self._save_results()
            
            end_time = time.time()
            duration = end_time - start_time
            
            return {
                "run_id": self.run_id,
                "start_url": start_url,
                "pages_crawled": len(self.pages_data),
                "duration_seconds": round(duration, 2),
                "output_dir": str(self.output_dir)
            }
            
        except Exception as e:
            print(f"❌ Crawl failed: {str(e)}")
            return {"error": str(e)}

    def _crawl_recursive(self, url: str, remaining_pages: int, depth: int = 0):
        """Recursively crawl pages"""
        
        if remaining_pages <= 0 or url in self.visited_urls or depth > 2:
            return
            
        try:
            print(f"  📄 Crawling: {url}")
            self.visited_urls.add(url)
            
            # Make request
            response = self.session.get(url, timeout=10)
            
            if response.status_code >= 400:
                print(f"    ❌ Failed to load {url}: {response.status_code}")
                return
            
            # Parse HTML
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Capture page data
            page_data = self._capture_page_data(url, response, soup)
            self.pages_data.append(page_data)
            
            # Find links to follow
            if remaining_pages > 1:
                links = self._extract_links(soup, url)
                for link in links[:min(3, remaining_pages - 1)]:
                    self._crawl_recursive(link, remaining_pages - 1, depth + 1)
                    remaining_pages -= 1
                    if remaining_pages <= 0:
                        break
                        
        except Exception as e:
            print(f"    ❌ Error crawling {url}: {str(e)}")

    def _capture_page_data(self, url: str, response: requests.Response, soup: BeautifulSoup) -> Dict:
        """Capture comprehensive page data"""
        
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
            'forms': forms,
            'scripts': scripts,
            'meta_tags': meta_tags,
            'cookies': cookies,
            'timestamp': datetime.now().isoformat()
        }

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract same-origin links from page"""
        
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

    def _save_results(self):
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


def main():
    """Test the simple crawler"""
    
    crawler = SimpleCrawler("simple_test")
    result = crawler.crawl("http://localhost:3001", max_pages=3)
    
    if "error" in result:
        print(f"❌ Crawl failed: {result['error']}")
    else:
        print(f"✅ Crawl completed: {result}")


if __name__ == "__main__":
    main()
