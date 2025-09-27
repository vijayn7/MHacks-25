import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
from abc import ABC, abstractmethod


class BaseScanner(ABC):
    """Base class for all security scanners"""

    def __init__(self, run_id: str):
        self.run_id = run_id
        self.findings: List[Dict] = []
        self.scanner_name = self.__class__.__name__

    @abstractmethod
    def scan_pages(self, pages_file: Path) -> List[Dict]:
        """Scan pages.json file for security issues - must be implemented by subclasses"""
        pass

    def _load_pages_data(self, pages_file: Path) -> Dict:
        """Load and return pages data from JSON file"""
        try:
            print(f"    📖 Loading pages data from {pages_file}")
            with open(pages_file, 'r') as f:
                data = json.load(f)
            
            pages_count = len(data.get('pages', []))
            print(f"    📄 Loaded {pages_count} pages")
            
            if pages_count > 0:
                sample_page = data['pages'][0]
                print(f"    🔍 Sample page: {sample_page.get('url', 'N/A')}")
                print(f"    📊 Sample page data keys: {list(sample_page.keys())}")
            
            return data
        except Exception as e:
            print(f"    ❌ Error loading pages data: {str(e)}")
            import traceback
            traceback.print_exc()
            return {"pages": []}

    def _add_finding(self, category: str, severity: str, title: str, description: str,
                     evidence: Dict, fix_snippet: str, reproduce_command: str,
                     owasp_category: str = None):
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
            'owasp_category': owasp_category,
            'scanner': self.scanner_name,
            'timestamp': datetime.now().isoformat()
        }

        self.findings.append(finding)
        print(f"    🚨 {self.scanner_name} found: {title} ({severity})")

    def _calculate_priority_score(self, severity: str, category: str) -> int:
        """Calculate priority score based on severity and fix ease"""

        severity_scores = {
            'critical': 90,
            'high': 70,
            'medium': 50,
            'low': 30
        }

        # Adjust for fix difficulty - these are easier to fix
        easy_fixes = [
            'missing_headers', 'insecure_cookies', 'weak_csp',
            'info_disclosure', 'missing_hsts'
        ]
        
        # These are harder to fix
        hard_fixes = [
            'sql_injection', 'xss', 'access_control',
            'authentication', 'insecure_design'
        ]

        base_score = severity_scores.get(severity, 30)
        
        if category in easy_fixes:
            return base_score + 10
        elif category in hard_fixes:
            return base_score - 5
        else:
            return base_score

    def _is_same_origin(self, url1: str, url2: str) -> bool:
        """Check if two URLs are from the same origin"""
        try:
            parsed1 = urlparse(url1)
            parsed2 = urlparse(url2)
            return (parsed1.scheme == parsed2.scheme and 
                   parsed1.netloc == parsed2.netloc)
        except:
            return False

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            return urlparse(url).netloc
        except:
            return ""

    def _is_https(self, url: str) -> bool:
        """Check if URL uses HTTPS"""
        return url.startswith('https://')

    def _normalize_header_name(self, header: str) -> str:
        """Normalize header name for consistent comparison"""
        return header.lower().strip()

    def _extract_forms_from_page(self, page: Dict) -> List[Dict]:
        """Extract forms from page data"""
        return page.get('forms', [])

    def _extract_scripts_from_page(self, page: Dict) -> List[Dict]:
        """Extract scripts from page data"""
        return page.get('scripts', [])

    def _extract_cookies_from_page(self, page: Dict) -> List[Dict]:
        """Extract cookies from page data"""
        return page.get('cookies', [])

    def _extract_meta_tags_from_page(self, page: Dict) -> Dict:
        """Extract meta tags from page data"""
        return page.get('meta_tags', {})

    def save_findings(self, output_dir: Path):
        """Save findings to file"""
        findings_file = output_dir / f"{self.scanner_name.lower()}_findings.json"

        output = {
            'run_id': self.run_id,
            'scanner': self.scanner_name,
            'findings': self.findings,
            'summary': {
                'total_findings': len(self.findings),
                'by_severity': {
                    'critical': len([f for f in self.findings if f['severity'] == 'critical']),
                    'high': len([f for f in self.findings if f['severity'] == 'high']),
                    'medium': len([f for f in self.findings if f['severity'] == 'medium']),
                    'low': len([f for f in self.findings if f['severity'] == 'low'])
                },
                'by_owasp_category': {}
            },
            'timestamp': datetime.now().isoformat()
        }

        # Count by OWASP category
        for finding in self.findings:
            owasp_cat = finding.get('owasp_category', 'Other')
            output['summary']['by_owasp_category'][owasp_cat] = \
                output['summary']['by_owasp_category'].get(owasp_cat, 0) + 1

        with open(findings_file, 'w') as f:
            json.dump(output, f, indent=2)

        print(f"  💾 {self.scanner_name} saved {len(self.findings)} findings to {findings_file}")

    def get_findings(self) -> List[Dict]:
        """Return all findings from this scanner"""
        return self.findings.copy()

    def clear_findings(self):
        """Clear all findings"""
        self.findings.clear()


# OWASP Top 10 Categories for reference
OWASP_CATEGORIES = {
    'A01': 'Broken Access Control',
    'A02': 'Cryptographic Failures', 
    'A03': 'Injection',
    'A04': 'Insecure Design',
    'A05': 'Security Misconfiguration',
    'A06': 'Vulnerable and Outdated Components',
    'A07': 'Identification and Authentication Failures',
    'A08': 'Software and Data Integrity Failures',
    'A09': 'Security Logging and Monitoring Failures',
    'A10': 'Server-Side Request Forgery'
}

# Severity levels
SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low']

# Common vulnerability categories
VULNERABILITY_CATEGORIES = {
    'missing_headers': 'Security Misconfiguration',
    'weak_csp': 'Security Misconfiguration',
    'insecure_cookies': 'Security Misconfiguration',
    'clickjacking': 'Security Misconfiguration',
    'info_disclosure': 'Security Misconfiguration',
    'xss': 'Injection',
    'sql_injection': 'Injection',
    'command_injection': 'Injection',
    'access_control': 'Broken Access Control',
    'authentication': 'Identification and Authentication Failures',
    'weak_crypto': 'Cryptographic Failures',
    'vulnerable_components': 'Vulnerable and Outdated Components',
    'insecure_design': 'Insecure Design',
    'integrity_failures': 'Software and Data Integrity Failures',
    'logging_failures': 'Security Logging and Monitoring Failures',
    'ssrf': 'Server-Side Request Forgery'
}

