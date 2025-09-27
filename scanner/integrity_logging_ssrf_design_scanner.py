import json
import uuid
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse
from base_scanner import BaseScanner


class IntegrityScanner(BaseScanner):
    """Analyzes software and data integrity failures (OWASP A08)"""

    def __init__(self, run_id: str):
        super().__init__(run_id)

    def scan_pages(self, pages_file: Path) -> List[Dict]:
        """Scan pages for integrity failures"""

        print(f"🔍 Scanning for integrity failures for run {self.run_id}")

        data = self._load_pages_data(pages_file)
        pages = data.get('pages', [])

        for page in pages:
            self._analyze_page_integrity(page)

        return self.findings

    def _analyze_page_integrity(self, page: Dict):
        """Analyze a single page for integrity issues"""

        url = page['url']
        headers = {k.lower(): v for k, v in page.get('headers', {}).items()}
        html_content = page.get('html_snippet', '')
        scripts = self._extract_scripts_from_page(page)

        print(f"  🔒 Analyzing integrity for {url}")

        # Check for missing integrity attributes
        self._check_missing_integrity(url, scripts, html_content)

        # Check for insecure external resources
        self._check_insecure_resources(url, html_content)

        # Check for missing CSP
        self._check_missing_csp(url, headers)

    def _check_missing_integrity(self, url: str, scripts: List[Dict], html_content: str):
        """Check for missing Subresource Integrity attributes"""

        # Check external scripts
        for script in scripts:
            if script.get('type') == 'external':
                src = script.get('src', '')
                if src and not self._has_integrity_attribute(html_content, src):
                    self._add_finding(
                        category='integrity_failures',
                        severity='medium',
                        title='Missing Subresource Integrity',
                        description=f'External script missing integrity attribute: {src}',
                        evidence={
                            'url': url,
                            'resource': src,
                            'missing_integrity': True
                        },
                        fix_snippet=self._get_integrity_fix_snippet(),
                        reproduce_command=f"curl '{url}' | grep -i integrity",
                        owasp_category="A08 - Software and Data Integrity Failures"
                    )

    def _check_insecure_resources(self, url: str, html_content: str):
        """Check for insecure external resources"""

        # Look for HTTP resources on HTTPS pages
        if url.startswith('https://'):
            http_patterns = [
                r'src=["\']http://',
                r'href=["\']http://',
                r'action=["\']http://'
            ]

            for pattern in http_patterns:
                matches = re.findall(pattern, html_content)
                if matches:
                    self._add_finding(
                        category='integrity_failures',
                        severity='medium',
                        title='Mixed Content: HTTP Resources on HTTPS Page',
                        description=f'HTTPS page contains HTTP resources which may be blocked by browsers.',
                        evidence={
                            'url': url,
                            'http_resources': matches[:3],
                            'mixed_content': True
                        },
                        fix_snippet=self._get_mixed_content_fix_snippet(),
                        reproduce_command=f"curl '{url}' | grep -i http://",
                        owasp_category="A08 - Software and Data Integrity Failures"
                    )

    def _check_missing_csp(self, url: str, headers: Dict):
        """Check for missing Content Security Policy"""

        if 'content-security-policy' not in headers:
            self._add_finding(
                category='integrity_failures',
                severity='high',
                title='Missing Content Security Policy',
                description='Page missing Content Security Policy header for resource integrity protection.',
                evidence={
                    'url': url,
                    'missing_csp': True
                },
                fix_snippet=self._get_csp_fix_snippet(),
                reproduce_command=f"curl -I '{url}' | grep -i csp",
                owasp_category="A08 - Software and Data Integrity Failures"
            )

    def _has_integrity_attribute(self, html_content: str, src: str) -> bool:
        """Check if resource has integrity attribute"""
        return f'integrity=' in html_content and src in html_content

    def _get_integrity_fix_snippet(self) -> str:
        return """// Add Subresource Integrity attributes
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js" 
        integrity="sha384-..." 
        crossorigin="anonymous"></script>"""

    def _get_mixed_content_fix_snippet(self) -> str:
        return """// Fix mixed content issues
// Use HTTPS for all resources
<script src="https://cdn.example.com/library.js"></script>
<link href="https://cdn.example.com/style.css" rel="stylesheet">"""

    def _get_csp_fix_snippet(self) -> str:
        return """// Add Content Security Policy
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;"""


class LoggingScanner(BaseScanner):
    """Analyzes security logging and monitoring failures (OWASP A09)"""

    def __init__(self, run_id: str):
        super().__init__(run_id)

    def scan_pages(self, pages_file: Path) -> List[Dict]:
        """Scan pages for logging failures"""

        print(f"🔍 Scanning for logging failures for run {self.run_id}")

        data = self._load_pages_data(pages_file)
        pages = data.get('pages', [])

        for page in pages:
            self._analyze_page_logging(page)

        return self.findings

    def _analyze_page_logging(self, page: Dict):
        """Analyze a single page for logging issues"""

        url = page['url']
        status_code = page.get('status_code', 0)
        headers = {k.lower(): v for k, v in page.get('headers', {}).items()}

        print(f"  📝 Analyzing logging for {url}")

        # Check for missing security headers
        self._check_missing_security_headers(url, headers)

        # Check for error disclosure
        self._check_error_disclosure(url, status_code)

    def _check_missing_security_headers(self, url: str, headers: Dict):
        """Check for missing security monitoring headers"""

        security_headers = ['x-content-type-options', 'x-frame-options', 'strict-transport-security']
        
        for header in security_headers:
            if header not in headers:
                self._add_finding(
                    category='logging_failures',
                    severity='low',
                    title=f'Missing Security Header: {header}',
                    description=f'Missing security header {header} reduces monitoring capabilities.',
                    evidence={
                        'url': url,
                        'missing_header': header
                    },
                    fix_snippet=self._get_security_header_fix_snippet(),
                    reproduce_command=f"curl -I '{url}'",
                    owasp_category="A09 - Security Logging and Monitoring Failures"
                )

    def _check_error_disclosure(self, url: str, status_code: int):
        """Check for error disclosure"""

        if status_code >= 500:
            self._add_finding(
                category='logging_failures',
                severity='medium',
                title=f'Server Error: {status_code}',
                description=f'Server returns error {status_code} which should be logged and monitored.',
                evidence={
                    'url': url,
                    'status_code': status_code,
                    'error_type': 'server_error'
                },
                fix_snippet=self._get_error_logging_fix_snippet(),
                reproduce_command=f"curl -I '{url}'",
                owasp_category="A09 - Security Logging and Monitoring Failures"
            )

    def _get_security_header_fix_snippet(self) -> str:
        return """// Add security headers for monitoring
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;"""

    def _get_error_logging_fix_snippet(self) -> str:
        return """// Implement proper error logging
app.use((err, req, res, next) => {
    console.error('Error:', err);
    // Log to monitoring service
    logger.error('Server error', { error: err.message, url: req.url });
    res.status(500).json({ error: 'Internal server error' });
});"""


class SSRFScanner(BaseScanner):
    """Analyzes Server-Side Request Forgery vulnerabilities (OWASP A10)"""

    def __init__(self, run_id: str):
        super().__init__(run_id)

    def scan_pages(self, pages_file: Path) -> List[Dict]:
        """Scan pages for SSRF vulnerabilities"""

        print(f"🔍 Scanning for SSRF vulnerabilities for run {self.run_id}")

        data = self._load_pages_data(pages_file)
        pages = data.get('pages', [])

        for page in pages:
            self._analyze_page_ssrf(page)

        return self.findings

    def _analyze_page_ssrf(self, page: Dict):
        """Analyze a single page for SSRF issues"""

        url = page['url']
        html_content = page.get('html_snippet', '')
        forms = self._extract_forms_from_page(page)

        print(f"  🌐 Analyzing SSRF for {url}")

        # Check for URL parameters that might be vulnerable
        self._check_url_parameters(url)

        # Check forms for SSRF patterns
        self._check_forms_for_ssrf(url, forms)

    def _check_url_parameters(self, url: str):
        """Check URL parameters for SSRF patterns"""

        parsed_url = urlparse(url)
        if parsed_url.query:
            params = parsed_url.query.lower()
            
            ssrf_params = ['url', 'link', 'redirect', 'next', 'return', 'callback', 'proxy']
            
            for param in ssrf_params:
                if param in params:
                    self._add_finding(
                        category='ssrf',
                        severity='high',
                        title=f'Potential SSRF Parameter: {param}',
                        description=f'URL parameter "{param}" might be vulnerable to Server-Side Request Forgery.',
                        evidence={
                            'url': url,
                            'parameter': param,
                            'ssrf_risk': True
                        },
                        fix_snippet=self._get_ssrf_fix_snippet(),
                        reproduce_command=f"curl '{url}'",
                        owasp_category="A10 - Server-Side Request Forgery"
                    )

    def _check_forms_for_ssrf(self, url: str, forms: List[Dict]):
        """Check forms for SSRF vulnerabilities"""

        for form in forms:
            inputs = form.get('inputs', [])
            
            for input_field in inputs:
                input_name = input_field.get('name', '').lower()
                
                if any(ssrf_word in input_name for ssrf_word in ['url', 'link', 'redirect', 'proxy']):
                    self._add_finding(
                        category='ssrf',
                        severity='high',
                        title=f'Potential SSRF Form Field: {input_name}',
                        description=f'Form field "{input_name}" might be vulnerable to Server-Side Request Forgery.',
                        evidence={
                            'url': url,
                            'form_field': input_name,
                            'ssrf_risk': True
                        },
                        fix_snippet=self._get_ssrf_fix_snippet(),
                        reproduce_command=f"curl '{url}' | grep -i {input_name}",
                        owasp_category="A10 - Server-Side Request Forgery"
                    )

    def _get_ssrf_fix_snippet(self) -> str:
        return """// Prevent SSRF attacks
// 1. Validate and whitelist URLs
function isValidURL(url) {
    const allowedDomains = ['example.com', 'api.example.com'];
    try {
        const parsed = new URL(url);
        return allowedDomains.includes(parsed.hostname);
    } catch {
        return false;
    }
}

// 2. Use allowlist approach
const ALLOWED_URLS = [
    'https://api.example.com/',
    'https://internal.example.com/'
];

// 3. Block private IP ranges
function isPrivateIP(hostname) {
    const privateRanges = [
        /^10\./,
        /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
        /^192\.168\./,
        /^127\./,
        /^localhost$/
    ];
    return privateRanges.some(range => range.test(hostname));
}"""


class DesignScanner(BaseScanner):
    """Analyzes insecure design vulnerabilities (OWASP A04)"""

    def __init__(self, run_id: str):
        super().__init__(run_id)

    def scan_pages(self, pages_file: Path) -> List[Dict]:
        """Scan pages for insecure design issues"""

        print(f"🔍 Scanning for insecure design for run {self.run_id}")

        data = self._load_pages_data(pages_file)
        pages = data.get('pages', [])

        for page in pages:
            self._analyze_page_design(page)

        return self.findings

    def _analyze_page_design(self, page: Dict):
        """Analyze a single page for design issues"""

        url = page['url']
        html_content = page.get('html_snippet', '')
        forms = self._extract_forms_from_page(page)

        print(f"  🎨 Analyzing design for {url}")

        # Check for insecure design patterns
        self._check_insecure_patterns(url, html_content, forms)

    def _check_insecure_patterns(self, url: str, html_content: str, forms: List[Dict]):
        """Check for insecure design patterns"""

        # Check for client-side validation only
        if forms:
            has_client_validation = 'required' in html_content or 'pattern=' in html_content
            if has_client_validation:
                self._add_finding(
                    category='insecure_design',
                    severity='medium',
                    title='Client-Side Validation Only',
                    description='Forms rely on client-side validation which can be bypassed.',
                    evidence={
                        'url': url,
                        'client_validation_only': True
                    },
                    fix_snippet=self._get_validation_fix_snippet(),
                    reproduce_command=f"curl '{url}' | grep -i required",
                    owasp_category="A04 - Insecure Design"
                )

    def _get_validation_fix_snippet(self) -> str:
        return """// Implement server-side validation
app.post('/submit', (req, res) => {
    const { email, password } = req.body;
    
    // Server-side validation
    if (!email || !isValidEmail(email)) {
        return res.status(400).json({ error: 'Invalid email' });
    }
    
    if (!password || password.length < 8) {
        return res.status(400).json({ error: 'Password too short' });
    }
    
    // Process form
});"""


def main():
    """Test the scanners"""
    
    scanners = [
        IntegrityScanner("test_run"),
        LoggingScanner("test_run"),
        SSRFScanner("test_run"),
        DesignScanner("test_run")
    ]
    
    test_pages = Path("test_pages.json")
    if test_pages.exists():
        for scanner in scanners:
            findings = scanner.scan_pages(test_pages)
            scanner.save_findings(Path("."))
            print(f"✅ {scanner.scanner_name} found {len(findings)} vulnerabilities")
    else:
        print("❌ No test_pages.json found. Run crawler first.")


if __name__ == "__main__":
    main()
