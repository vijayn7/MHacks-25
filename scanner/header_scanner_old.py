import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse


class HeaderScanner:
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
        self.run_id = run_id
        self.findings: List[Dict] = []

    def scan_pages(self, pages_file: Path) -> List[Dict]:
        """Scan pages.json file for header security issues"""

        print(f"🔍 Scanning headers for run {self.run_id}")

        with open(pages_file, 'r') as f:
            data = json.load(f)

        pages = data.get('pages', [])

        for page in pages:
            self._analyze_page_headers(page)

        # Check frameability
        self._check_frameability(pages_file.parent)

        return self.findings

    def _analyze_page_headers(self, page: Dict):
        """Analyze headers for a single page"""

        url = page['url']
        headers = {k.lower(): v for k, v in page.get('headers', {}).items()}
        status_code = page.get('status_code', 0)

        print(f"  📋 Analyzing headers for {url}")

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
                    reproduce_command=f"curl -I {url}"
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
                reproduce_command=f"curl -I {url}"
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
                reproduce_command=f"curl -I {url}"
            )

        # Check cookies
        self._analyze_cookies(page)

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
                reproduce_command=f"curl -I {url}"
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
                    reproduce_command=f"curl -I {url}"
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
                    reproduce_command=f"curl -I {frame_data['url']}"
                )

        except Exception as e:
            print(f"    ❌ Error checking frameability: {str(e)}")

    def _add_finding(self, category: str, severity: str, title: str, description: str,
                     evidence: Dict, fix_snippet: str, reproduce_command: str):
        """Add a security finding"""

        finding = {
            'id': str(uuid.uuid4())[:8],
            'run_id': self.run_id,
            'category': category,
            'severity': severity,
            'title': title,
            'description': description,
            'evidence': evidence,
            'fix_snippet': fix_snippet,
            'reproduce_command': reproduce_command,
            'reproduce_seed': str(uuid.uuid4())[:8],
            'priority_score': self._calculate_priority_score(severity, category),
            'timestamp': datetime.now().isoformat()
        }

        self.findings.append(finding)
        print(f"    🚨 Found: {title} ({severity})")

    def _calculate_priority_score(self, severity: str, category: str) -> int:
        """Calculate priority score based on severity and fix ease"""

        severity_scores = {
            'critical': 90,
            'high': 70,
            'medium': 50,
            'low': 30
        }

        # Adjust for fix difficulty
        easy_fixes = ['missing_headers', 'insecure_cookies']
        fix_bonus = 10 if category in easy_fixes else 0

        return severity_scores.get(severity, 30) + fix_bonus

    def save_findings(self, output_dir: Path):
        """Save findings to file"""

        findings_file = output_dir / "findings.json"

        output = {
            'run_id': self.run_id,
            'findings': self.findings,
            'summary': {
                'total_findings': len(self.findings),
                'by_severity': {
                    'critical': len([f for f in self.findings if f['severity'] == 'critical']),
                    'high': len([f for f in self.findings if f['severity'] == 'high']),
                    'medium': len([f for f in self.findings if f['severity'] == 'medium']),
                    'low': len([f for f in self.findings if f['severity'] == 'low'])
                }
            },
            'timestamp': datetime.now().isoformat()
        }

        with open(findings_file, 'w') as f:
            json.dump(output, f, indent=2)

        print(f"  💾 Saved {len(self.findings)} findings to {findings_file}")


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