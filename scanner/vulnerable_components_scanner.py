import json
import uuid
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse
from base_scanner import BaseScanner


class VulnerableComponentsScanner(BaseScanner):
    """Analyzes vulnerable and outdated components (OWASP A06)"""

    # Common vulnerable libraries and versions
    VULNERABLE_LIBRARIES = {
        'jquery': {
            'vulnerable_versions': ['1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '1.7', '1.8', '1.9', '1.10', '1.11', '2.0', '2.1', '2.2'],
            'min_safe_version': '3.0.0'
        },
        'bootstrap': {
            'vulnerable_versions': ['3.0', '3.1', '3.2', '3.3', '4.0', '4.1', '4.2', '4.3', '4.4'],
            'min_safe_version': '4.5.0'
        },
        'angular': {
            'vulnerable_versions': ['1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '2.0', '2.1', '2.2', '2.3', '2.4'],
            'min_safe_version': '2.5.0'
        },
        'react': {
            'vulnerable_versions': ['0.14', '15.0', '15.1', '15.2', '15.3', '15.4', '15.5', '15.6', '16.0', '16.1', '16.2'],
            'min_safe_version': '16.3.0'
        },
        'lodash': {
            'vulnerable_versions': ['4.0', '4.1', '4.2', '4.3', '4.4', '4.5', '4.6', '4.7', '4.8', '4.9', '4.10', '4.11', '4.12', '4.13', '4.14', '4.15', '4.16', '4.17'],
            'min_safe_version': '4.17.12'
        }
    }

    # Common vulnerable server technologies
    VULNERABLE_SERVERS = {
        'apache': {
            'vulnerable_versions': ['2.0', '2.1', '2.2', '2.3', '2.4.0', '2.4.1', '2.4.2', '2.4.3', '2.4.4', '2.4.5', '2.4.6', '2.4.7', '2.4.8', '2.4.9', '2.4.10', '2.4.11', '2.4.12', '2.4.13', '2.4.14', '2.4.15', '2.4.16', '2.4.17', '2.4.18', '2.4.19', '2.4.20', '2.4.21', '2.4.22', '2.4.23', '2.4.24', '2.4.25', '2.4.26', '2.4.27', '2.4.28', '2.4.29', '2.4.30', '2.4.31', '2.4.32', '2.4.33', '2.4.34', '2.4.35', '2.4.36', '2.4.37', '2.4.38', '2.4.39', '2.4.40', '2.4.41', '2.4.42', '2.4.43', '2.4.44', '2.4.45', '2.4.46', '2.4.47', '2.4.48', '2.4.49', '2.4.50', '2.4.51', '2.4.52', '2.4.53', '2.4.54', '2.4.55', '2.4.56', '2.4.57'],
            'min_safe_version': '2.4.58'
        },
        'nginx': {
            'vulnerable_versions': ['1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '1.7', '1.8', '1.9', '1.10', '1.11', '1.12', '1.13', '1.14', '1.15', '1.16', '1.17', '1.18', '1.19', '1.20', '1.21', '1.22', '1.23', '1.24'],
            'min_safe_version': '1.25.0'
        },
        'php': {
            'vulnerable_versions': ['5.0', '5.1', '5.2', '5.3', '5.4', '5.5', '5.6', '7.0', '7.1', '7.2', '7.3', '7.4'],
            'min_safe_version': '8.0.0'
        }
    }

    def __init__(self, run_id: str):
        super().__init__(run_id)

    def scan_pages(self, pages_file: Path) -> List[Dict]:
        """Scan pages for vulnerable components"""

        print(f"🔍 Scanning for vulnerable components for run {self.run_id}")

        data = self._load_pages_data(pages_file)
        pages = data.get('pages', [])

        for page in pages:
            self._analyze_page_components(page)

        return self.findings

    def _analyze_page_components(self, page: Dict):
        """Analyze a single page for vulnerable components"""

        url = page['url']
        headers = {k.lower(): v for k, v in page.get('headers', {}).items()}
        html_content = page.get('html_snippet', '')
        scripts = self._extract_scripts_from_page(page)

        print(f"  📦 Analyzing components for {url}")

        # Check server headers for version disclosure
        self._check_server_versions(url, headers)

        # Check JavaScript libraries
        self._check_javascript_libraries(url, scripts, html_content)

        # Check for known vulnerable patterns
        self._check_vulnerable_patterns(url, html_content)

    def _check_server_versions(self, url: str, headers: Dict):
        """Check server headers for version disclosure"""

        server_header = headers.get('server', '')
        x_powered_by = headers.get('x-powered-by', '')

        # Check Apache version
        if 'apache' in server_header.lower():
            version_match = re.search(r'apache/(\d+\.\d+\.\d+)', server_header.lower())
            if version_match:
                version = version_match.group(1)
                if self._is_vulnerable_version('apache', version):
                    self._add_finding(
                        category='vulnerable_components',
                        severity='high',
                        title=f'Vulnerable Apache Version: {version}',
                        description=f'Apache server version {version} has known security vulnerabilities.',
                        evidence={
                            'url': url,
                            'component': 'apache',
                            'version': version,
                            'server_header': server_header
                        },
                        fix_snippet=self._get_server_update_fix_snippet(),
                        reproduce_command=f"curl -I '{url}' | grep -i server",
                        owasp_category="A06 - Vulnerable and Outdated Components"
                    )

        # Check Nginx version
        if 'nginx' in server_header.lower():
            version_match = re.search(r'nginx/(\d+\.\d+\.\d+)', server_header.lower())
            if version_match:
                version = version_match.group(1)
                if self._is_vulnerable_version('nginx', version):
                    self._add_finding(
                        category='vulnerable_components',
                        severity='high',
                        title=f'Vulnerable Nginx Version: {version}',
                        description=f'Nginx server version {version} has known security vulnerabilities.',
                        evidence={
                            'url': url,
                            'component': 'nginx',
                            'version': version,
                            'server_header': server_header
                        },
                        fix_snippet=self._get_server_update_fix_snippet(),
                        reproduce_command=f"curl -I '{url}' | grep -i server",
                        owasp_category="A06 - Vulnerable and Outdated Components"
                    )

        # Check PHP version
        if 'php' in x_powered_by.lower():
            version_match = re.search(r'php/(\d+\.\d+\.\d+)', x_powered_by.lower())
            if version_match:
                version = version_match.group(1)
                if self._is_vulnerable_version('php', version):
                    self._add_finding(
                        category='vulnerable_components',
                        severity='high',
                        title=f'Vulnerable PHP Version: {version}',
                        description=f'PHP version {version} has known security vulnerabilities.',
                        evidence={
                            'url': url,
                            'component': 'php',
                            'version': version,
                            'x_powered_by': x_powered_by
                        },
                        fix_snippet=self._get_php_update_fix_snippet(),
                        reproduce_command=f"curl -I '{url}' | grep -i x-powered",
                        owasp_category="A06 - Vulnerable and Outdated Components"
                    )

    def _check_javascript_libraries(self, url: str, scripts: List[Dict], html_content: str):
        """Check JavaScript libraries for vulnerabilities"""

        # Check external scripts
        for script in scripts:
            if script.get('type') == 'external':
                src = script.get('src', '')
                self._check_script_library(url, src)

        # Check inline scripts for library references
        for script in scripts:
            if script.get('type') == 'inline':
                content = script.get('content', '')
                self._check_inline_library_references(url, content)

        # Check HTML for CDN references
        self._check_cdn_references(url, html_content)

    def _check_script_library(self, url: str, script_src: str):
        """Check individual script for library vulnerabilities"""

        # Extract library name and version from CDN URLs
        cdn_patterns = [
            r'jquery/(\d+\.\d+\.\d+)/jquery',
            r'bootstrap/(\d+\.\d+\.\d+)/css/bootstrap',
            r'angular/(\d+\.\d+\.\d+)/angular',
            r'react/(\d+\.\d+\.\d+)/react',
            r'lodash/(\d+\.\d+\.\d+)/lodash'
        ]

        for pattern in cdn_patterns:
            match = re.search(pattern, script_src.lower())
            if match:
                version = match.group(1)
                library = pattern.split('/')[0]
                
                if library in self.VULNERABLE_LIBRARIES and self._is_vulnerable_library_version(library, version):
                    self._add_finding(
                        category='vulnerable_components',
                        severity='medium',
                        title=f'Vulnerable {library.title()} Version: {version}',
                        description=f'{library.title()} library version {version} has known security vulnerabilities.',
                        evidence={
                            'url': url,
                            'component': library,
                            'version': version,
                            'script_src': script_src,
                            'min_safe_version': self.VULNERABLE_LIBRARIES[library]['min_safe_version']
                        },
                        fix_snippet=self._get_library_update_fix_snippet(),
                        reproduce_command=f"curl '{url}' | grep -i {library}",
                        owasp_category="A06 - Vulnerable and Outdated Components"
                    )

    def _check_inline_library_references(self, url: str, script_content: str):
        """Check inline scripts for library version references"""

        # Look for version comments or variables
        version_patterns = [
            r'jQuery\s+v(\d+\.\d+\.\d+)',
            r'Bootstrap\s+v(\d+\.\d+\.\d+)',
            r'AngularJS\s+v(\d+\.\d+\.\d+)',
            r'React\s+v(\d+\.\d+\.\d+)',
            r'Lodash\s+v(\d+\.\d+\.\d+)'
        ]

        for pattern in version_patterns:
            match = re.search(pattern, script_content, re.IGNORECASE)
            if match:
                version = match.group(1)
                library = pattern.split('\\')[0].lower()
                
                if library in self.VULNERABLE_LIBRARIES and self._is_vulnerable_library_version(library, version):
                    self._add_finding(
                        category='vulnerable_components',
                        severity='medium',
                        title=f'Vulnerable {library.title()} Version in Script: {version}',
                        description=f'Inline script references vulnerable {library.title()} version {version}.',
                        evidence={
                            'url': url,
                            'component': library,
                            'version': version,
                            'location': 'inline_script',
                            'min_safe_version': self.VULNERABLE_LIBRARIES[library]['min_safe_version']
                        },
                        fix_snippet=self._get_library_update_fix_snippet(),
                        reproduce_command=f"curl '{url}' | grep -i {library}",
                        owasp_category="A06 - Vulnerable and Outdated Components"
                    )

    def _check_cdn_references(self, url: str, html_content: str):
        """Check HTML for CDN references to vulnerable libraries"""

        # Common CDN patterns
        cdn_patterns = [
            r'cdnjs\.cloudflare\.com/ajax/libs/jquery/(\d+\.\d+\.\d+)',
            r'cdnjs\.cloudflare\.com/ajax/libs/bootstrap/(\d+\.\d+\.\d+)',
            r'cdnjs\.cloudflare\.com/ajax/libs/angularjs/(\d+\.\d+\.\d+)',
            r'cdnjs\.cloudflare\.com/ajax/libs/react/(\d+\.\d+\.\d+)',
            r'cdnjs\.cloudflare\.com/ajax/libs/lodash\.js/(\d+\.\d+\.\d+)'
        ]

        for pattern in cdn_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for version in matches:
                library = pattern.split('/')[4].split('.')[0]
                
                if library in self.VULNERABLE_LIBRARIES and self._is_vulnerable_library_version(library, version):
                    self._add_finding(
                        category='vulnerable_components',
                        severity='medium',
                        title=f'Vulnerable {library.title()} CDN Version: {version}',
                        description=f'CDN reference to vulnerable {library.title()} version {version}.',
                        evidence={
                            'url': url,
                            'component': library,
                            'version': version,
                            'source': 'cdn',
                            'min_safe_version': self.VULNERABLE_LIBRARIES[library]['min_safe_version']
                        },
                        fix_snippet=self._get_cdn_update_fix_snippet(),
                        reproduce_command=f"curl '{url}' | grep -i cdnjs",
                        owasp_category="A06 - Vulnerable and Outdated Components"
                    )

    def _check_vulnerable_patterns(self, url: str, html_content: str):
        """Check for known vulnerable patterns"""

        # Check for old jQuery patterns that might indicate vulnerable versions
        old_jquery_patterns = [
            r'jQuery\s*\(\s*["\']\s*#',
            r'\$\(["\']\s*#',
            r'jQuery\s*\(\s*["\']\s*\.',
            r'\$\(["\']\s*\.'
        ]

        for pattern in old_jquery_patterns:
            if re.search(pattern, html_content):
                self._add_finding(
                    category='vulnerable_components',
                    severity='low',
                    title='Potential Old jQuery Usage Pattern',
                    description='Page contains jQuery usage patterns that may indicate an old, vulnerable version.',
                    evidence={
                        'url': url,
                        'pattern': pattern,
                        'component': 'jquery',
                        'indication': 'old_usage_pattern'
                    },
                    fix_snippet=self._get_library_update_fix_snippet(),
                    reproduce_command=f"curl '{url}' | grep -i jquery",
                    owasp_category="A06 - Vulnerable and Outdated Components"
                )

    def _is_vulnerable_version(self, component: str, version: str) -> bool:
        """Check if a component version is vulnerable"""
        
        if component not in self.VULNERABLE_SERVERS:
            return False
            
        vulnerable_versions = self.VULNERABLE_SERVERS[component]['vulnerable_versions']
        return version in vulnerable_versions

    def _is_vulnerable_library_version(self, library: str, version: str) -> bool:
        """Check if a library version is vulnerable"""
        
        if library not in self.VULNERABLE_LIBRARIES:
            return False
            
        vulnerable_versions = self.VULNERABLE_LIBRARIES[library]['vulnerable_versions']
        return version in vulnerable_versions

    def _get_server_update_fix_snippet(self) -> str:
        """Get server update fix code snippet"""
        
        return """// Update server software to latest version
// 1. Apache update
sudo apt update
sudo apt upgrade apache2

// 2. Nginx update
sudo apt update
sudo apt upgrade nginx

// 3. Hide server version information
// Apache: Add to httpd.conf
ServerTokens Prod
ServerSignature Off

// Nginx: Add to nginx.conf
server_tokens off;

// 4. Regular security updates
sudo apt update && sudo apt upgrade
sudo yum update
sudo dnf update"""

    def _get_php_update_fix_snippet(self) -> str:
        """Get PHP update fix code snippet"""
        
        return """// Update PHP to latest version
// 1. Ubuntu/Debian
sudo apt update
sudo apt install php8.2 php8.2-cli php8.2-fpm

// 2. CentOS/RHEL
sudo yum install php82

// 3. Hide PHP version
// Add to php.ini
expose_php = Off

// 4. Remove X-Powered-By header
// Add to .htaccess
Header unset X-Powered-By

// 5. Regular updates
sudo apt update && sudo apt upgrade php"""

    def _get_library_update_fix_snippet(self) -> str:
        """Get library update fix code snippet"""
        
        return """// Update JavaScript libraries
// 1. Update CDN references
// OLD: <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
// NEW: <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>

// 2. Update package.json dependencies
{
  "dependencies": {
    "jquery": "^3.7.1",
    "bootstrap": "^5.3.2",
    "react": "^18.2.0",
    "lodash": "^4.17.21"
  }
}

// 3. Update npm packages
npm update
npm audit fix

// 4. Use automated dependency scanning
npm audit
yarn audit

// 5. Set up automated security updates
// GitHub Dependabot
// Renovate bot
// Snyk"""

    def _get_cdn_update_fix_snippet(self) -> str:
        """Get CDN update fix code snippet"""
        
        return """// Update CDN references to latest versions
// 1. jQuery CDN update
// OLD: https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.4/jquery.min.js
// NEW: https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js

// 2. Bootstrap CDN update
// OLD: https://cdnjs.cloudflare.com/ajax/libs/bootstrap/4.6.2/css/bootstrap.min.css
// NEW: https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.2/css/bootstrap.min.css

// 3. Use version pinning
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js" 
        integrity="sha384-..." 
        crossorigin="anonymous"></script>

// 4. Subresource Integrity (SRI)
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js" 
        integrity="sha384-..." 
        crossorigin="anonymous"></script>

// 5. Automated CDN updates
// Use tools like:
// - Renovate
// - Dependabot
// - Greenkeeper"""


def main():
    """Test the vulnerable components scanner"""
    
    scanner = VulnerableComponentsScanner("test_run")
    
    test_pages = Path("test_pages.json")
    if test_pages.exists():
        findings = scanner.scan_pages(test_pages)
        scanner.save_findings(Path("."))
        print(f"✅ Found {len(findings)} vulnerable components")
    else:
        print("❌ No test_pages.json found. Run crawler first.")


if __name__ == "__main__":
    main()
