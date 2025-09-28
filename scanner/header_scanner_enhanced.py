import json
import uuid
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse
from base_scanner import BaseScanner, OWASP_CATEGORIES


class EnhancedHeaderScanner(BaseScanner):
    """Enhanced header scanner with context-aware analysis and reduced false positives"""

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
        """Scan pages for header security issues with enhanced accuracy"""

        print(f"🔍 Enhanced header scanning for run {self.run_id}")

        data = self._load_pages_data(pages_file)
        pages = data.get('pages', [])

        # Analyze each page with context awareness
        for page in pages:
            self._analyze_page_headers_enhanced(page)

        return self.findings

    def _analyze_page_headers_enhanced(self, page: Dict):
        """Enhanced header analysis with context awareness"""

        url = page['url']
        status_code = page.get('status_code', 0)
        headers = {k.lower(): v for k, v in page.get('headers', {}).items()}

        print(f"  🔍 Enhanced header analysis for {url}")

        # Context analysis
        context = self._analyze_page_context(url, headers, page)
        
        # Check for missing headers with context awareness
        self._check_security_headers_enhanced(url, headers, status_code, context)

        # Analyze existing headers for weaknesses
        self._analyze_existing_headers(url, headers, context)

    def _analyze_page_context(self, url: str, headers: Dict, page: Dict) -> Dict:
        """Analyze page context for better accuracy"""
        
        return {
            'is_https': url.startswith('https://'),
            'is_api': self._is_api_endpoint(url),
            'is_admin': self._is_admin_endpoint(url),
            'is_static': self._is_static_resource(url),
            'server_type': self._detect_server_type(headers),
            'has_forms': len(page.get('forms', [])) > 0,
            'has_scripts': len(page.get('scripts', [])) > 0,
            'content_type': headers.get('content-type', ''),
            'url_type': self._classify_url_type(url)
        }

    def _check_security_headers_enhanced(self, url: str, headers: Dict, status_code: int, context: Dict):
        """Enhanced security header checking with context awareness"""
        
        for header_name, config in self.SECURITY_HEADERS.items():
            if header_name not in headers:
                # Calculate context-aware severity
                severity = self._calculate_context_aware_severity(
                    header_name, config['severity'], url, headers, context
                )
                
                if severity:  # Only report if severity is significant
                    self._add_finding(
                        category='missing_headers',
                        severity=severity,
                        title=f'Missing {header_name.replace("-", " ").title()} Header',
                        description=self._generate_context_aware_description(
                            header_name, config['description'], url, context
                        ),
                        evidence={
                            'url': url,
                            'missing_header': header_name,
                            'context': context,
                            'all_headers': list(headers.keys()),
                            'status_code': status_code,
                            'recommended_action': self._get_header_recommendation(header_name, context)
                        },
                        fix_snippet=self._generate_context_aware_fix(header_name, context),
                        reproduce_command=f'curl -I {url} | grep -i {header_name}',
                        owasp_category='A05 - Security Misconfiguration'
                    )

    def _calculate_context_aware_severity(self, header_name: str, base_severity: str, url: str, 
                                        headers: Dict, context: Dict) -> str:
        """Calculate severity based on context and application type"""
        
        # Don't report HSTS for HTTP sites
        if not context['is_https'] and header_name == 'strict-transport-security':
            return None
            
        # Don't report CSP for static resources
        if context['is_static'] and header_name == 'content-security-policy':
            return None
            
        # Base severity scores
        severity_scores = {'critical': 100, 'high': 80, 'medium': 60, 'low': 40}
        base_score = severity_scores.get(base_severity, 40)
        
        # Context multipliers
        if context['is_admin']:
            base_score *= 1.3
        if context['is_api']:
            base_score *= 1.2
        if context['has_forms'] and header_name in ['content-security-policy', 'x-frame-options']:
            base_score *= 1.2
        if context['is_https'] and header_name == 'strict-transport-security':
            base_score *= 1.4
            
        # Determine final severity
        if base_score >= 90:
            return 'critical'
        elif base_score >= 70:
            return 'high'
        elif base_score >= 50:
            return 'medium'
        elif base_score >= 30:
            return 'low'
        else:
            return None

    def _is_api_endpoint(self, url: str) -> bool:
        """Check if URL appears to be an API endpoint"""
        api_indicators = ['/api/', '/v1/', '/v2/', '/rest/', '/graphql', '.json', '.xml']
        return any(indicator in url.lower() for indicator in api_indicators)

    def _is_admin_endpoint(self, url: str) -> bool:
        """Check if URL appears to be an admin endpoint"""
        admin_indicators = ['/admin', '/dashboard', '/manage', '/control', '/panel']
        return any(indicator in url.lower() for indicator in admin_indicators)

    def _is_static_resource(self, url: str) -> bool:
        """Check if URL appears to be a static resource"""
        static_extensions = ['.css', '.js', '.png', '.jpg', '.gif', '.svg', '.ico', '.woff', '.ttf']
        return any(url.lower().endswith(ext) for ext in static_extensions)

    def _classify_url_type(self, url: str) -> str:
        """Classify the type of URL for context-aware analysis"""
        if self._is_api_endpoint(url):
            return 'api'
        elif self._is_admin_endpoint(url):
            return 'admin'
        elif self._is_static_resource(url):
            return 'static'
        else:
            return 'webpage'

    def _detect_server_type(self, headers: Dict) -> str:
        """Detect server type from headers"""
        server_header = headers.get('server', '').lower()
        
        if 'nginx' in server_header:
            return 'nginx'
        elif 'apache' in server_header:
            return 'apache'
        elif 'iis' in server_header:
            return 'iis'
        else:
            return 'unknown'

    def _generate_context_aware_description(self, header_name: str, base_description: str, 
                                          url: str, context: Dict) -> str:
        """Generate context-aware description"""
        context_parts = []
        
        if context['is_api']:
            context_parts.append("API endpoint")
        if context['is_admin']:
            context_parts.append("admin interface")
        if context['is_https']:
            context_parts.append("HTTPS site")
            
        context_str = " on " + " ".join(context_parts) if context_parts else ""
        
        return f"{base_description}{context_str} at {url}"

    def _generate_context_aware_fix(self, header_name: str, context: Dict) -> str:
        """Generate context-aware fix snippet"""
        server_type = context['server_type']
        
        if server_type == 'nginx':
            return self._get_nginx_fix(header_name)
        elif server_type == 'apache':
            return self._get_apache_fix(header_name)
        else:
            return self._get_generic_fix(header_name)

    def _get_nginx_fix(self, header_name: str) -> str:
        """Get Nginx-specific fix for header"""
        fixes = {
            'x-frame-options': 'add_header X-Frame-Options "DENY" always;',
            'content-security-policy': 'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'" always;',
            'strict-transport-security': 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
            'x-content-type-options': 'add_header X-Content-Type-Options "nosniff" always;',
            'referrer-policy': 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
            'permissions-policy': 'add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;'
        }
        return fixes.get(header_name, f'add_header {header_name.replace("-", "_").upper()} "..." always;')

    def _get_apache_fix(self, header_name: str) -> str:
        """Get Apache-specific fix for header"""
        fixes = {
            'x-frame-options': 'Header always set X-Frame-Options "DENY"',
            'content-security-policy': 'Header always set Content-Security-Policy "default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'"',
            'strict-transport-security': 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"',
            'x-content-type-options': 'Header always set X-Content-Type-Options "nosniff"',
            'referrer-policy': 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
            'permissions-policy': 'Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"'
        }
        return fixes.get(header_name, f'Header always set {header_name.replace("-", "_").upper()} "..."')

    def _get_generic_fix(self, header_name: str) -> str:
        """Get generic fix for header"""
        return f"Set {header_name.replace('-', '_').upper()} header in your server configuration"

    def _get_header_recommendation(self, header_name: str, context: Dict) -> str:
        """Get specific recommendation based on context"""
        recommendations = {
            'content-security-policy': 'Implement CSP to prevent XSS attacks, especially important for pages with forms',
            'x-frame-options': 'Prevent clickjacking attacks by setting X-Frame-Options',
            'strict-transport-security': 'Force HTTPS connections and prevent downgrade attacks',
            'x-content-type-options': 'Prevent MIME type sniffing attacks'
        }
        
        base_rec = recommendations.get(header_name, 'Implement this security header')
        
        if context['is_admin']:
            return f"{base_rec} - Critical for admin interfaces"
        elif context['is_api']:
            return f"{base_rec} - Important for API security"
        else:
            return base_rec

    def _analyze_existing_headers(self, url: str, headers: Dict, context: Dict):
        """Analyze existing headers for weaknesses"""
        
        # Analyze CSP strength
        csp = headers.get('content-security-policy', '')
        if csp:
            self._analyze_csp_strength(csp, url, context)

        # Analyze HSTS strength
        hsts = headers.get('strict-transport-security', '')
        if hsts:
            self._analyze_hsts_strength(hsts, url, context)

        # Analyze X-Frame-Options strength
        frame_options = headers.get('x-frame-options', '')
        if frame_options:
            self._analyze_frame_options_strength(frame_options, url, context)

    def _analyze_csp_strength(self, csp_value: str, url: str, context: Dict):
        """Analyze Content Security Policy for weaknesses"""
        
        dangerous_patterns = [
            ("'unsafe-inline'", "unsafe-inline allows inline scripts", 'medium'),
            ("'unsafe-eval'", "unsafe-eval allows code evaluation", 'high'),
            ("*", "wildcard sources are too permissive", 'high'),
            ("data:", "data: URLs can be dangerous", 'medium'),
            ("blob:", "blob: URLs can be dangerous", 'medium')
        ]
        
        for pattern, description, severity in dangerous_patterns:
            if pattern in csp_value:
                self._add_finding(
                    category='weak_csp',
                    severity=severity,
                    title=f'Weak CSP Directive: {description}',
                    description=f'Content Security Policy contains potentially dangerous directive: {pattern}',
                    evidence={
                        'url': url,
                        'csp_value': csp_value,
                        'weak_directive': pattern,
                        'description': description,
                        'context': context
                    },
                    fix_snippet='Remove unsafe directives and use specific sources',
                    reproduce_command=f'curl -I {url} | grep -i content-security-policy',
                    owasp_category='A05 - Security Misconfiguration'
                )

    def _analyze_hsts_strength(self, hsts_value: str, url: str, context: Dict):
        """Analyze HSTS header for weaknesses"""
        
        # Check for missing includeSubDomains
        if 'includesubdomains' not in hsts_value.lower():
            self._add_finding(
                category='weak_hsts',
                severity='low',
                title='HSTS Missing includeSubDomains',
                description='Strict-Transport-Security header should include includeSubDomains directive',
                evidence={
                    'url': url,
                    'hsts_value': hsts_value,
                    'missing_directive': 'includeSubDomains',
                    'context': context
                },
                fix_snippet='add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";',
                reproduce_command=f'curl -I {url} | grep -i strict-transport-security',
                owasp_category='A05 - Security Misconfiguration'
            )

    def _analyze_frame_options_strength(self, frame_options_value: str, url: str, context: Dict):
        """Analyze X-Frame-Options header for weaknesses"""
        
        # Check for weak values
        if frame_options_value.upper() not in ['DENY', 'SAMEORIGIN']:
            self._add_finding(
                category='weak_frame_options',
                severity='medium',
                title='Weak X-Frame-Options Value',
                description=f'X-Frame-Options value "{frame_options_value}" may not provide adequate protection',
                evidence={
                    'url': url,
                    'frame_options_value': frame_options_value,
                    'recommended_values': ['DENY', 'SAMEORIGIN'],
                    'context': context
                },
                fix_snippet='add_header X-Frame-Options "DENY";',
                reproduce_command=f'curl -I {url} | grep -i x-frame-options',
                owasp_category='A05 - Security Misconfiguration'
            )


if __name__ == "__main__":
    # Test the enhanced header scanner
    scanner = EnhancedHeaderScanner("test_run")
    test_pages = Path("test_pages.json")
    if test_pages.exists():
        findings = scanner.scan_pages(test_pages)
        print(f"Enhanced header scanner found {len(findings)} issues")
        for finding in findings:
            print(f"  - {finding['title']} ({finding['severity']})")
    else:
        print("No test_pages.json found")
