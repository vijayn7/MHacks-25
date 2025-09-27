import json
import uuid
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse
from base_scanner import BaseScanner, OWASP_CATEGORIES


class HeaderScanner(BaseScanner):
    """Analyzes HTTP headers for security issues"""

    SECURITY_HEADERS = {
        'content-security-policy': {
            'severity': 'high',
            'description': 'Missing Content Security Policy header',
            'fix_snippet': 'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\';";'
        },
        'x-frame-options': {
            'severity': 'high',
            'description': 'Missing X-Frame-Options header (clickjacking protection)',
            'fix_snippet': 'add_header X-Frame-Options "DENY";'
        },
        'strict-transport-security': {
            'severity': 'medium',
            'description': 'Missing Strict-Transport-Security header',
            'fix_snippet': 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";'
        },
        'x-content-type-options': {
            'severity': 'medium',
            'description': 'Missing X-Content-Type-Options header',
            'fix_snippet': 'add_header X-Content-Type-Options "nosniff";'
        },
        'referrer-policy': {
            'severity': 'low',
            'description': 'Missing Referrer-Policy header',
            'fix_snippet': 'add_header Referrer-Policy "strict-origin-when-cross-origin";'
        },
        'permissions-policy': {
            'severity': 'low',
            'description': 'Missing Permissions-Policy header',
            'fix_snippet': 'add_header Permissions-Policy "geolocation=(), microphone=(), camera=()";'
        }
    }

    def __init__(self, run_id: str):
        super().__init__(run_id)

    def scan_pages(self, pages_file: Path) -> List[Dict]:
        """Scan pages.json file for header security issues"""

        print(f"🔍 Scanning headers for run {self.run_id}")

        data = self._load_pages_data(pages_file)
        pages = data.get('pages', [])

        print(f"    📋 Analyzing {len(pages)} pages for header security issues")

        for i, page in enumerate(pages, 1):
            url = page.get('url', f'Page {i}')
            print(f"    📄 [{i}/{len(pages)}] Analyzing: {url}")
            self._analyze_page_headers(page)

        # Check frameability
        print(f"    🖼️  Checking frameability tests...")
        self._check_frameability(pages_file.parent)

        print(f"    ✅ HeaderScanner completed: {len(self.findings)} findings")
        return self.findings

    def _analyze_page_headers(self, page: Dict):
        """Analyze headers for a single page"""

        url = page['url']
        headers = {k.lower(): v for k, v in page.get('headers', {}).items()}
        status_code = page.get('status_code', 0)

        print(f"      📋 Analyzing headers for {url}")

        # Check for missing security headers
        for header_name, header_info in self.SECURITY_HEADERS.items():
            if header_name not in headers:
                self._add_finding(
                    category='missing_headers',
                    severity=header_info['severity'],
                    title=f"Missing {header_name.replace('-', ' ').title()}",
                    description=header_info['description'],
                    evidence={
                        'url': url,
                        'missing_header': header_name,
                        'all_headers': list(headers.keys()),
                        'status_code': status_code
                    },
                    fix_snippet=header_info['fix_snippet'],
                    reproduce_command=f"curl -I {url}",
                    owasp_category="A05 - Security Misconfiguration"
                )

        # Check for weak CSP
        csp = headers.get('content-security-policy', '')
        if csp:
            self._analyze_csp(url, csp)

        # Check HSTS on HTTPS
        if url.startswith('https://') and 'strict-transport-security' not in headers:
            self._add_finding(
                category='missing_hsts',
                severity='medium',
                title='Missing HSTS on HTTPS Site',
                description='HTTPS site missing Strict-Transport-Security header',
                evidence={
                    'url': url,
                    'scheme': 'https',
                    'headers': headers
                },
                fix_snippet='add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";',
                reproduce_command=f"curl -I {url}",
                owasp_category="A05 - Security Misconfiguration"
            )

        # Check for server information disclosure
        server_header = headers.get('server', '')
        if server_header and any(info in server_header.lower() for info in ['apache/', 'nginx/', 'iis/', 'version']):
            self._add_finding(
                category='info_disclosure',
                severity='low',
                title='Server Information Disclosure',
                description='Server header reveals software version information',
                evidence={
                    'url': url,
                    'server_header': server_header
                },
                fix_snippet='server_tokens off;  # Nginx\n# or\nServerTokens Prod  # Apache',
                reproduce_command=f"curl -I {url}",
                owasp_category="A05 - Security Misconfiguration"
            )

        # Check cookies
        self._analyze_cookies(page)

        # Analyze forms for security issues
        self._analyze_forms(url, page)

        # Analyze scripts for security issues
        self._analyze_scripts(url, page)

    def _analyze_csp(self, url: str, csp: str):
        """Analyze Content Security Policy for weaknesses"""

        issues = []

        if "'unsafe-eval'" in csp:
            issues.append("Contains 'unsafe-eval'")

        if "'unsafe-inline'" in csp and 'script-src' in csp:
            issues.append("Contains 'unsafe-inline' for scripts")

        if csp.count('*') > 2:
            issues.append("Too many wildcard sources")

        if issues:
            self._add_finding(
                category='weak_csp',
                severity='medium',
                title='Weak Content Security Policy',
                description=f"CSP has security issues: {', '.join(issues)}",
                evidence={
                    'url': url,
                    'csp_header': csp,
                    'issues': issues
                },
                fix_snippet='Content-Security-Policy: default-src \'self\'; script-src \'self\'; object-src \'none\';',
                reproduce_command=f"curl -I {url}",
                owasp_category="A05 - Security Misconfiguration"
            )

    def _analyze_cookies(self, page: Dict):
        """Analyze cookie security"""

        url = page['url']
        cookies = page.get('cookies', [])

        for cookie in cookies:
            issues = []

            if not cookie.get('secure') and url.startswith('https://'):
                issues.append('Missing Secure flag on HTTPS')

            if not cookie.get('httpOnly'):
                issues.append('Missing HttpOnly flag')

            if not cookie.get('sameSite'):
                issues.append('Missing SameSite attribute')

            if issues:
                self._add_finding(
                    category='insecure_cookies',
                    severity='medium',
                    title=f"Insecure Cookie: {cookie['name']}",
                    description=f"Cookie has security issues: {', '.join(issues)}",
                    evidence={
                        'url': url,
                        'cookie_name': cookie['name'],
                        'cookie_attributes': {
                            'secure': cookie.get('secure', False),
                            'httpOnly': cookie.get('httpOnly', False),
                            'sameSite': cookie.get('sameSite', '')
                        },
                        'issues': issues
                    },
                    fix_snippet='res.cookie("name", "value", {\n  secure: true,\n  httpOnly: true,\n  sameSite: "strict"\n});',
                    reproduce_command=f"curl -I {url}",
                    owasp_category="A05 - Security Misconfiguration"
                )

    def _analyze_forms(self, url: str, page: Dict):
        """Analyze forms for security issues"""

        forms = self._extract_forms_from_page(page)
        
        for form in forms:
            form_action = form.get('action', '')
            form_method = form.get('method', 'GET')
            inputs = form.get('inputs', [])

            # Check for forms without CSRF protection
            if form_method.upper() == 'POST' and not any('csrf' in inp.get('name', '').lower() for inp in inputs):
                self._add_finding(
                    category='missing_csrf',
                    severity='medium',
                    title='Form Missing CSRF Protection',
                    description=f'POST form may be missing CSRF protection token.',
                    evidence={
                        'url': url,
                        'form_action': form_action,
                        'form_method': form_method,
                        'csrf_token_present': False
                    },
                    fix_snippet='<input type="hidden" name="_csrf" value="{{csrfToken}}">',
                    reproduce_command=f"curl '{url}' | grep -A 10 -B 5 form",
                    owasp_category="A05 - Security Misconfiguration"
                )

            # Check for forms submitting to HTTP
            if form_action and form_action.startswith('http://') and url.startswith('https://'):
                self._add_finding(
                    category='mixed_content',
                    severity='high',
                    title='Form Submits to HTTP',
                    description=f'Form on HTTPS page submits to HTTP endpoint.',
                    evidence={
                        'url': url,
                        'form_action': form_action,
                        'mixed_content': True
                    },
                    fix_snippet='<form action="https://example.com/submit" method="POST">',
                    reproduce_command=f"curl '{url}' | grep -i form",
                    owasp_category="A05 - Security Misconfiguration"
                )

    def _analyze_scripts(self, url: str, page: Dict):
        """Analyze scripts for security issues"""

        scripts = self._extract_scripts_from_page(page)
        
        for script in scripts:
            script_type = script.get('type', '')
            script_content = script.get('content', '') if script_type == 'inline' else ''
            script_src = script.get('src', '') if script_type == 'external' else ''

            # Check for inline scripts without nonce
            if script_type == 'inline' and script_content:
                # Look for dangerous patterns
                dangerous_patterns = [
                    r'eval\s*\(',
                    r'innerHTML\s*=',
                    r'document\.write\s*\(',
                    r'setTimeout\s*\(\s*["\']',
                    r'setInterval\s*\(\s*["\']'
                ]

                found_patterns = []
                for pattern in dangerous_patterns:
                    if re.search(pattern, script_content, re.IGNORECASE):
                        found_patterns.append(pattern)

                if found_patterns:
                    self._add_finding(
                        category='dangerous_script',
                        severity='medium',
                        title='Dangerous JavaScript Patterns',
                        description=f'Inline script contains potentially dangerous patterns.',
                        evidence={
                            'url': url,
                            'script_type': 'inline',
                            'dangerous_patterns': found_patterns,
                            'script_snippet': script_content[:200] + '...' if len(script_content) > 200 else script_content
                        },
                        fix_snippet='// Use safe alternatives:\n// element.textContent = userInput;\n// setTimeout(() => {}, 1000);',
                        reproduce_command=f"curl '{url}' | grep -A 5 -B 5 script",
                        owasp_category="A05 - Security Misconfiguration"
                    )

            # Check for external scripts without integrity
            if script_type == 'external' and script_src:
                # This would require checking the HTML content for integrity attributes
                # For now, we'll just note external scripts
                if 'integrity=' not in str(page.get('html_snippet', '')):
                    self._add_finding(
                        category='missing_integrity',
                        severity='low',
                        title='External Script Missing Integrity',
                        description=f'External script may be missing integrity attribute.',
                        evidence={
                            'url': url,
                            'script_src': script_src,
                            'integrity_present': False
                        },
                        fix_snippet='<script src="script.js" integrity="sha384-..." crossorigin="anonymous"></script>',
                        reproduce_command=f"curl '{url}' | grep -i script",
                        owasp_category="A05 - Security Misconfiguration"
                    )

    def _check_frameability(self, artifacts_dir: Path):
        """Check frameability test results"""

        frameability_file = artifacts_dir / "frameability_test.json"

        if not frameability_file.exists():
            return

        try:
            with open(frameability_file, 'r') as f:
                frame_data = json.load(f)

            if frame_data.get('can_frame', False):
                self._add_finding(
                    category='clickjacking',
                    severity='high',
                    title='Clickjacking Vulnerability',
                    description='Page can be embedded in iframe, vulnerable to clickjacking attacks',
                    evidence={
                        'url': frame_data['url'],
                        'can_frame': True,
                        'test_file': frame_data.get('evidence_file'),
                        'test_timestamp': frame_data.get('test_timestamp')
                    },
                    fix_snippet='add_header X-Frame-Options "DENY";\nadd_header Content-Security-Policy "frame-ancestors \'none\'";',
                    reproduce_command=f"curl -I {frame_data['url']}",
                    owasp_category="A05 - Security Misconfiguration"
                )

        except Exception as e:
            print(f"    ❌ Error checking frameability: {str(e)}")


def main():
    """Test the header scanner"""

    # Test with demo crawler output
    scanner = HeaderScanner("test_run")

    # Mock pages file for testing
    test_pages = Path("test_pages.json")
    if test_pages.exists():
        findings = scanner.scan_pages(test_pages)
        scanner.save_findings(Path("."))
        print(f"✅ Found {len(findings)} security issues")
    else:
        print("❌ No test_pages.json found. Run crawler first.")


if __name__ == "__main__":
    main()
