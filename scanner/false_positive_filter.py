import json
import re
from typing import Dict, List, Set
from datetime import datetime
from pathlib import Path


class FalsePositiveFilter:
    """Advanced false positive filtering system for security findings"""

    def __init__(self):
        self.whitelist_patterns = self._load_whitelist_patterns()
        self.correlation_rules = self._load_correlation_rules()
        self.confidence_thresholds = self._load_confidence_thresholds()

    def filter_findings(self, findings: List[Dict], pages_data: Dict) -> List[Dict]:
        """Filter out false positives from findings list"""
        
        print(f"🔍 Filtering false positives from {len(findings)} findings")
        
        filtered_findings = []
        filtered_count = 0
        
        for finding in findings:
            # Apply various filtering techniques
            if self._should_keep_finding(finding, pages_data):
                filtered_findings.append(finding)
            else:
                filtered_count += 1
                print(f"  ❌ Filtered out: {finding['title']} - {finding.get('filter_reason', 'False positive')}")
        
        print(f"✅ Filtered out {filtered_count} false positives, kept {len(filtered_findings)} findings")
        return filtered_findings

    def _should_keep_finding(self, finding: Dict, pages_data: Dict) -> bool:
        """Determine if finding should be kept based on various criteria"""
        
        # Apply whitelist filtering
        if self._is_whitelisted(finding):
            return False
        
        # Apply confidence scoring
        confidence = self._calculate_confidence(finding, pages_data)
        if confidence < self.confidence_thresholds.get(finding['severity'], 0.5):
            finding['filter_reason'] = f'Low confidence: {confidence:.2f}'
            return False
        
        # Apply correlation rules
        if self._is_correlated_false_positive(finding, pages_data):
            finding['filter_reason'] = 'Correlated false positive'
            return False
        
        # Apply context-based filtering
        if self._is_context_irrelevant(finding, pages_data):
            finding['filter_reason'] = 'Context irrelevant'
            return False
        
        # Apply exploitability assessment
        if not self._is_exploitable(finding, pages_data):
            finding['filter_reason'] = 'Not exploitable'
            return False
        
        return True

    def _is_whitelisted(self, finding: Dict) -> bool:
        """Check if finding matches whitelist patterns"""
        
        url = finding.get('evidence', {}).get('url', '')
        category = finding.get('category', '')
        title = finding.get('title', '')
        
        # Check URL patterns
        for pattern in self.whitelist_patterns.get('urls', []):
            if re.search(pattern, url, re.IGNORECASE):
                return True
        
        # Check category patterns
        for pattern in self.whitelist_patterns.get('categories', []):
            if re.search(pattern, category, re.IGNORECASE):
                return True
        
        # Check title patterns
        for pattern in self.whitelist_patterns.get('titles', []):
            if re.search(pattern, title, re.IGNORECASE):
                return True
        
        return False

    def _calculate_confidence(self, finding: Dict, pages_data: Dict) -> float:
        """Calculate confidence score for finding"""
        
        confidence = 0.5  # Base confidence
        
        # Severity-based confidence adjustment
        severity_confidence = {
            'critical': 0.9,
            'high': 0.8,
            'medium': 0.6,
            'low': 0.4
        }
        confidence = severity_confidence.get(finding['severity'], 0.5)
        
        # Evidence quality assessment
        evidence = finding.get('evidence', {})
        
        # URL context confidence
        url = evidence.get('url', '')
        if self._is_sensitive_url(url):
            confidence += 0.2
        elif self._is_static_resource(url):
            confidence -= 0.3
        
        # Evidence completeness
        if len(evidence) > 3:
            confidence += 0.1
        
        # Scanner-specific confidence adjustments
        scanner = finding.get('scanner', '')
        if scanner == 'HeaderScanner':
            confidence = self._assess_header_finding_confidence(finding, pages_data)
        elif scanner == 'InjectionScanner':
            confidence = self._assess_injection_finding_confidence(finding, pages_data)
        
        return min(1.0, max(0.0, confidence))

    def _assess_header_finding_confidence(self, finding: Dict, pages_data: Dict) -> float:
        """Assess confidence for header-related findings"""
        
        confidence = 0.6  # Base confidence for header findings
        
        evidence = finding.get('evidence', {})
        url = evidence.get('url', '')
        missing_header = evidence.get('missing_header', '')
        context = evidence.get('context', {})
        
        # Context-aware confidence adjustments
        if context.get('is_admin', False):
            confidence += 0.2
        if context.get('is_api', False):
            confidence += 0.1
        if context.get('is_https', False) and missing_header == 'strict-transport-security':
            confidence += 0.2
        
        # Check if header is actually needed for this type of content
        content_type = context.get('content_type', '')
        if 'text/html' not in content_type and missing_header == 'content-security-policy':
            confidence -= 0.3
        
        return confidence

    def _assess_injection_finding_confidence(self, finding: Dict, pages_data: Dict) -> float:
        """Assess confidence for injection-related findings"""
        
        confidence = 0.5  # Base confidence for injection findings
        
        evidence = finding.get('evidence', {})
        category = finding.get('category', '')
        
        # Confidence based on evidence quality
        if 'test_payload' in evidence:
            confidence += 0.2
        if 'reflected_value' in evidence:
            confidence += 0.3
        if 'sql_indicators' in evidence and evidence['sql_indicators']:
            confidence += 0.2
        
        # Confidence based on vulnerability type
        if category == 'reflected_xss' and evidence.get('reflected_value'):
            confidence += 0.2
        elif category == 'potential_sql_injection':
            confidence += 0.1
        
        return confidence

    def _is_correlated_false_positive(self, finding: Dict, pages_data: Dict) -> bool:
        """Check if finding is a correlated false positive"""
        
        # Check correlation rules
        for rule in self.correlation_rules:
            if self._matches_correlation_rule(finding, rule, pages_data):
                return True
        
        return False

    def _matches_correlation_rule(self, finding: Dict, rule: Dict, pages_data: Dict) -> bool:
        """Check if finding matches a correlation rule"""
        
        # Example correlation rule: If CSP is present but weak, don't report missing CSP
        if rule.get('type') == 'csp_correlation':
            if finding.get('category') == 'missing_headers' and 'content-security-policy' in finding.get('title', ''):
                # Check if there's a weak CSP finding
                for page in pages_data.get('pages', []):
                    headers = page.get('headers', {})
                    if 'content-security-policy' in headers:
                        return True
        
        # Example correlation rule: If X-Frame-Options is present, don't report missing CSP frame-ancestors
        if rule.get('type') == 'frame_protection_correlation':
            if finding.get('category') == 'weak_csp' and 'frame-ancestors' in finding.get('evidence', {}).get('csp_value', ''):
                url = finding.get('evidence', {}).get('url', '')
                for page in pages_data.get('pages', []):
                    if page.get('url') == url:
                        headers = page.get('headers', {})
                        if 'x-frame-options' in headers:
                            return True
        
        return False

    def _is_context_irrelevant(self, finding: Dict, pages_data: Dict) -> bool:
        """Check if finding is irrelevant to the context"""
        
        evidence = finding.get('evidence', {})
        url = evidence.get('url', '')
        
        # Don't report HSTS for HTTP sites
        if finding.get('category') == 'missing_headers' and 'strict-transport-security' in finding.get('title', ''):
            if not url.startswith('https://'):
                return True
        
        # Don't report CSP for static resources
        if finding.get('category') == 'missing_headers' and 'content-security-policy' in finding.get('title', ''):
            if self._is_static_resource(url):
                return True
        
        # Don't report SQL injection for pages without database indicators
        if finding.get('category') == 'potential_sql_injection':
            if not self._has_database_context(url, pages_data):
                return True
        
        return False

    def _is_exploitable(self, finding: Dict, pages_data: Dict) -> bool:
        """Assess if finding is actually exploitable"""
        
        evidence = finding.get('evidence', {})
        url = evidence.get('url', '')
        
        # Check if URL is accessible
        if not self._is_accessible_url(url, pages_data):
            return False
        
        # Check if vulnerability is in a relevant context
        if finding.get('category') == 'reflected_xss':
            return self._is_xss_exploitable(finding, pages_data)
        elif finding.get('category') == 'potential_sql_injection':
            return self._is_sql_injection_exploitable(finding, pages_data)
        
        return True

    def _is_xss_exploitable(self, finding: Dict, pages_data: Dict) -> bool:
        """Check if XSS finding is actually exploitable"""
        
        evidence = finding.get('evidence', {})
        url = evidence.get('url', '')
        
        # Find the page data
        page_data = None
        for page in pages_data.get('pages', []):
            if page.get('url') == url:
                page_data = page
                break
        
        if not page_data:
            return False
        
        # Check if page has user input handling
        html_content = page_data.get('html_snippet', '')
        forms = page_data.get('forms', [])
        
        # Must have forms or input fields to be exploitable
        if not forms and not re.search(r'<input[^>]*>', html_content):
            return False
        
        return True

    def _is_sql_injection_exploitable(self, finding: Dict, pages_data: Dict) -> bool:
        """Check if SQL injection finding is actually exploitable"""
        
        evidence = finding.get('evidence', {})
        url = evidence.get('url', '')
        
        # Find the page data
        page_data = None
        for page in pages_data.get('pages', []):
            if page.get('url') == url:
                page_data = page
                break
        
        if not page_data:
            return False
        
        # Check for database-related indicators
        html_content = page_data.get('html_snippet', '')
        headers = page_data.get('headers', {})
        
        db_indicators = ['mysql', 'postgres', 'sqlite', 'oracle', 'sql server', 'database']
        content_lower = html_content.lower()
        headers_str = str(headers).lower()
        
        return any(indicator in content_lower or indicator in headers_str for indicator in db_indicators)

    def _is_sensitive_url(self, url: str) -> bool:
        """Check if URL is sensitive (admin, API, etc.)"""
        sensitive_patterns = [
            r'/admin', r'/api/', r'/dashboard', r'/manage',
            r'/control', r'/panel', r'/login', r'/auth'
        ]
        return any(re.search(pattern, url, re.IGNORECASE) for pattern in sensitive_patterns)

    def _is_static_resource(self, url: str) -> bool:
        """Check if URL is a static resource"""
        static_extensions = ['.css', '.js', '.png', '.jpg', '.gif', '.svg', '.ico', '.woff', '.ttf']
        return any(url.lower().endswith(ext) for ext in static_extensions)

    def _is_accessible_url(self, url: str, pages_data: Dict) -> bool:
        """Check if URL is accessible (status 200)"""
        for page in pages_data.get('pages', []):
            if page.get('url') == url:
                return page.get('status_code', 0) == 200
        return False

    def _has_database_context(self, url: str, pages_data: Dict) -> bool:
        """Check if URL has database-related context"""
        for page in pages_data.get('pages', []):
            if page.get('url') == url:
                html_content = page.get('html_snippet', '').lower()
                return any(indicator in html_content for indicator in ['mysql', 'postgres', 'sqlite', 'database', 'query'])

    def _load_whitelist_patterns(self) -> Dict:
        """Load whitelist patterns for false positive filtering"""
        return {
            'urls': [
                r'/favicon\.ico',
                r'/robots\.txt',
                r'/sitemap\.xml',
                r'\.(css|js|png|jpg|gif|svg|ico|woff|ttf)$'
            ],
            'categories': [
                r'info_disclosure',  # Often false positives for static resources
            ],
            'titles': [
                r'Missing.*on static resource',
                r'Information disclosure.*favicon',
            ]
        }

    def _load_correlation_rules(self) -> List[Dict]:
        """Load correlation rules for false positive detection"""
        return [
            {
                'type': 'csp_correlation',
                'description': 'If CSP is present but weak, don\'t report missing CSP'
            },
            {
                'type': 'frame_protection_correlation',
                'description': 'If X-Frame-Options is present, don\'t report missing CSP frame-ancestors'
            }
        ]

    def _load_confidence_thresholds(self) -> Dict:
        """Load confidence thresholds for different severity levels"""
        return {
            'critical': 0.8,
            'high': 0.7,
            'medium': 0.6,
            'low': 0.5
        }

    def generate_filtering_report(self, original_findings: List[Dict], filtered_findings: List[Dict]) -> Dict:
        """Generate a report on the filtering process"""
        
        filtered_count = len(original_findings) - len(filtered_findings)
        
        # Analyze filtering reasons
        filtering_reasons = {}
        for finding in original_findings:
            if finding not in filtered_findings:
                reason = finding.get('filter_reason', 'Unknown')
                filtering_reasons[reason] = filtering_reasons.get(reason, 0) + 1
        
        return {
            'original_count': len(original_findings),
            'filtered_count': len(filtered_findings),
            'false_positives_removed': filtered_count,
            'false_positive_rate': filtered_count / len(original_findings) if original_findings else 0,
            'filtering_reasons': filtering_reasons,
            'confidence_improvement': self._calculate_confidence_improvement(original_findings, filtered_findings)
        }

    def _calculate_confidence_improvement(self, original_findings: List[Dict], filtered_findings: List[Dict]) -> Dict:
        """Calculate confidence improvement after filtering"""
        
        if not original_findings:
            return {'average_confidence': 0, 'improvement': 0}
        
        # Calculate average confidence before filtering
        original_confidence = sum(self._calculate_confidence(f, {}) for f in original_findings) / len(original_findings)
        
        # Calculate average confidence after filtering
        if filtered_findings:
            filtered_confidence = sum(self._calculate_confidence(f, {}) for f in filtered_findings) / len(filtered_findings)
        else:
            filtered_confidence = 0
        
        return {
            'original_average_confidence': original_confidence,
            'filtered_average_confidence': filtered_confidence,
            'improvement': filtered_confidence - original_confidence
        }


if __name__ == "__main__":
    # Test the false positive filter
    filter_system = FalsePositiveFilter()
    
    # Sample findings for testing
    test_findings = [
        {
            'id': '1',
            'title': 'Missing Content Security Policy',
            'category': 'missing_headers',
            'severity': 'high',
            'evidence': {
                'url': 'https://example.com/admin',
                'missing_header': 'content-security-policy',
                'context': {'is_admin': True, 'is_https': True}
            },
            'scanner': 'HeaderScanner'
        },
        {
            'id': '2',
            'title': 'Missing HSTS on HTTPS Site',
            'category': 'missing_headers',
            'severity': 'medium',
            'evidence': {
                'url': 'http://example.com/static/style.css',
                'missing_header': 'strict-transport-security'
            },
            'scanner': 'HeaderScanner'
        }
    ]
    
    # Filter findings
    filtered = filter_system.filter_findings(test_findings, {'pages': []})
    
    # Generate report
    report = filter_system.generate_filtering_report(test_findings, filtered)
    print(f"Filtering Report: {report}")
