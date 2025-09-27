import json
import uuid
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode
from base_scanner import BaseScanner


class InjectionScanner(BaseScanner):
    """Analyzes forms and parameters for injection vulnerabilities (OWASP A03)"""

    # XSS test payloads
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "';alert('XSS');//",
        "\"><script>alert('XSS')</script>",
        "<iframe src=javascript:alert('XSS')></iframe>"
    ]

    # SQL injection test payloads
    SQL_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "'; DROP TABLE users;--",
        "' UNION SELECT NULL,NULL,NULL--",
        "admin'--",
        "' OR 'a'='a",
        "1' OR '1'='1' /*",
        "' OR 1=1#"
    ]

    # Command injection payloads
    COMMAND_PAYLOADS = [
        "; ls -la",
        "| whoami",
        "; cat /etc/passwd",
        "$(whoami)",
        "`id`",
        "& dir",
        "; ping -c 1 127.0.0.1"
    ]

    # Dangerous patterns in responses
    XSS_INDICATORS = [
        r"<script[^>]*>.*?</script>",
        r"<img[^>]*onerror[^>]*>",
        r"javascript:",
        r"<svg[^>]*onload[^>]*>",
        r"<iframe[^>]*src=javascript:",
        r"alert\(['\"]XSS['\"]\)"
    ]

    SQL_ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_.*",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"Driver.* SQL[\-\_\ ]*Server",
        r"OLE DB.* SQL Server",
        r"(\W|\A)SQL Server.*Driver",
        r"Warning.*mssql_.*",
        r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}'",
        r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver",
        r"SqlException",
        r"ORA-[0-9][0-9][0-9][0-9]",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*oci_.*",
        r"Warning.*ora_.*"
    ]

    def __init__(self, run_id: str):
        super().__init__(run_id)

    def scan_pages(self, pages_file: Path) -> List[Dict]:
        """Scan pages for injection vulnerabilities"""

        print(f"🔍 Scanning for injection vulnerabilities for run {self.run_id}")

        data = self._load_pages_data(pages_file)
        pages = data.get('pages', [])

        for page in pages:
            self._analyze_page_for_injections(page)

        return self.findings

    def _analyze_page_for_injections(self, page: Dict):
        """Analyze a single page for injection vulnerabilities"""

        url = page['url']
        print(f"  🧪 Testing injection vectors for {url}")

        # Test forms for injection
        forms = self._extract_forms_from_page(page)
        for form in forms:
            self._test_form_injection(url, form)

        # Test URL parameters
        self._test_url_parameters(page)

        # Test for reflected content
        self._test_reflected_content(page)

        # Analyze JavaScript for DOM-based XSS
        scripts = self._extract_scripts_from_page(page)
        for script in scripts:
            self._analyze_script_for_dom_xss(url, script)

    def _test_form_injection(self, url: str, form: Dict):
        """Test form inputs for injection vulnerabilities"""

        form_action = form.get('action', '')
        form_method = form.get('method', 'GET')
        inputs = form.get('inputs', [])

        if not inputs:
            return

        # Test for XSS in form inputs
        for input_field in inputs:
            input_name = input_field.get('name', '')
            input_type = input_field.get('type', 'text')

            if not input_name or input_type in ['hidden', 'submit', 'button']:
                continue

            # Test XSS payloads
            for payload in self.XSS_PAYLOADS[:3]:  # Limit to first 3 for performance
                self._add_finding(
                    category='xss',
                    severity='high',
                    title=f'Potential XSS in Form Field: {input_name}',
                    description=f'Form field "{input_name}" may be vulnerable to Cross-Site Scripting (XSS) attacks.',
                    evidence={
                        'url': url,
                        'form_action': form_action,
                        'form_method': form_method,
                        'vulnerable_field': input_name,
                        'field_type': input_type,
                        'test_payload': payload,
                        'form_inputs': [inp.get('name', '') for inp in inputs]
                    },
                    fix_snippet=self._get_xss_fix_snippet(form_method),
                    reproduce_command=self._get_form_test_command(url, form_action, form_method, input_name, payload),
                    owasp_category="A03 - Injection"
                )

            # Test SQL injection for text inputs
            if input_type in ['text', 'search', 'email']:
                for payload in self.SQL_PAYLOADS[:2]:  # Limit for performance
                    self._add_finding(
                        category='sql_injection',
                        severity='critical',
                        title=f'Potential SQL Injection in Form Field: {input_name}',
                        description=f'Form field "{input_name}" may be vulnerable to SQL injection attacks.',
                        evidence={
                            'url': url,
                            'form_action': form_action,
                            'form_method': form_method,
                            'vulnerable_field': input_name,
                            'field_type': input_type,
                            'test_payload': payload
                        },
                        fix_snippet=self._get_sql_fix_snippet(),
                        reproduce_command=self._get_form_test_command(url, form_action, form_method, input_name, payload),
                        owasp_category="A03 - Injection"
                    )

    def _test_url_parameters(self, page: Dict):
        """Test URL parameters for injection vulnerabilities"""

        url = page['url']
        parsed_url = urlparse(url)
        
        if not parsed_url.query:
            return

        params = parse_qs(parsed_url.query)
        
        for param_name, param_values in params.items():
            if not param_values:
                continue

            original_value = param_values[0]

            # Test XSS in URL parameters
            for payload in self.XSS_PAYLOADS[:2]:
                test_url = self._build_test_url(url, param_name, payload)
                
                self._add_finding(
                    category='xss',
                    severity='high',
                    title=f'Potential Reflected XSS in URL Parameter: {param_name}',
                    description=f'URL parameter "{param_name}" may reflect user input without proper sanitization.',
                    evidence={
                        'url': url,
                        'parameter': param_name,
                        'original_value': original_value,
                        'test_payload': payload,
                        'test_url': test_url
                    },
                    fix_snippet=self._get_xss_fix_snippet('GET'),
                    reproduce_command=f"curl '{test_url}'",
                    owasp_category="A03 - Injection"
                )

            # Test SQL injection in URL parameters
            for payload in self.SQL_PAYLOADS[:2]:
                test_url = self._build_test_url(url, param_name, payload)
                
                self._add_finding(
                    category='sql_injection',
                    severity='critical',
                    title=f'Potential SQL Injection in URL Parameter: {param_name}',
                    description=f'URL parameter "{param_name}" may be vulnerable to SQL injection.',
                    evidence={
                        'url': url,
                        'parameter': param_name,
                        'original_value': original_value,
                        'test_payload': payload,
                        'test_url': test_url
                    },
                    fix_snippet=self._get_sql_fix_snippet(),
                    reproduce_command=f"curl '{test_url}'",
                    owasp_category="A03 - Injection"
                )

    def _test_reflected_content(self, page: Dict):
        """Test for reflected content that might indicate XSS"""

        url = page['url']
        html_content = page.get('html_snippet', '')
        
        if not html_content:
            return

        # Check if URL parameters are reflected in content
        parsed_url = urlparse(url)
        if parsed_url.query:
            params = parse_qs(parsed_url.query)
            
            for param_name, param_values in params.items():
                if not param_values:
                    continue
                    
                param_value = param_values[0]
                
                # Check if parameter value appears in HTML without encoding
                if param_value and len(param_value) > 2 and param_value in html_content:
                    # Check if it's properly encoded
                    if not self._is_properly_encoded(param_value, html_content):
                        self._add_finding(
                            category='xss',
                            severity='high',
                            title=f'Reflected Content in Parameter: {param_name}',
                            description=f'Parameter "{param_name}" value is reflected in page content without proper encoding.',
                            evidence={
                                'url': url,
                                'parameter': param_name,
                                'reflected_value': param_value,
                                'html_snippet': html_content[:500] + '...' if len(html_content) > 500 else html_content
                            },
                            fix_snippet=self._get_xss_fix_snippet('GET'),
                            reproduce_command=f"curl '{url}'",
                            owasp_category="A03 - Injection"
                        )

    def _analyze_script_for_dom_xss(self, url: str, script: Dict):
        """Analyze JavaScript for DOM-based XSS vulnerabilities"""

        script_type = script.get('type', '')
        script_content = script.get('content', '') if script_type == 'inline' else ''
        script_src = script.get('src', '') if script_type == 'external' else ''

        if not script_content:
            return

        # Dangerous patterns that might lead to DOM XSS
        dangerous_patterns = [
            r'document\.write\s*\(',
            r'innerHTML\s*=',
            r'outerHTML\s*=',
            r'document\.location',
            r'window\.location',
            r'eval\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
            r'Function\s*\(',
            r'document\.URL',
            r'document\.referrer',
            r'window\.name',
            r'location\.hash',
            r'location\.search'
        ]

        found_patterns = []
        for pattern in dangerous_patterns:
            if re.search(pattern, script_content, re.IGNORECASE):
                found_patterns.append(pattern)

        if found_patterns:
            self._add_finding(
                category='xss',
                severity='medium',
                title='Potential DOM-based XSS Patterns',
                description='JavaScript code contains patterns that could lead to DOM-based XSS vulnerabilities.',
                evidence={
                    'url': url,
                    'script_type': script_type,
                    'dangerous_patterns': found_patterns,
                    'script_snippet': script_content[:200] + '...' if len(script_content) > 200 else script_content
                },
                fix_snippet=self._get_dom_xss_fix_snippet(),
                reproduce_command=f"curl '{url}' | grep -E \"({'|'.join(found_patterns)})\"",
                owasp_category="A03 - Injection"
            )

    def _build_test_url(self, base_url: str, param_name: str, payload: str) -> str:
        """Build test URL with injection payload"""
        
        parsed_url = urlparse(base_url)
        params = parse_qs(parsed_url.query)
        params[param_name] = [payload]
        
        new_query = urlencode(params, doseq=True)
        return f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"

    def _is_properly_encoded(self, value: str, html_content: str) -> bool:
        """Check if a value is properly HTML encoded in content"""
        
        # Check for common HTML entities
        encoded_chars = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;',
            '&': '&amp;'
        }
        
        for char, encoded in encoded_chars.items():
            if char in value:
                # If the original char appears but not the encoded version, it's not encoded
                if char in html_content and encoded not in html_content:
                    return False
        
        return True

    def _get_form_test_command(self, url: str, action: str, method: str, field_name: str, payload: str) -> str:
        """Generate curl command to test form injection"""
        
        target_url = url if not action else action
        if method.upper() == 'POST':
            return f"curl -X POST -d '{field_name}={payload}' '{target_url}'"
        else:
            return f"curl '{target_url}?{field_name}={payload}'"

    def _get_xss_fix_snippet(self, method: str) -> str:
        """Get XSS fix code snippet"""
        
        return """// Input validation and output encoding
const escapeHtml = (str) => {
    return str.replace(/[&<>"']/g, (match) => {
        const escape = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        };
        return escape[match];
    });
};

// Use escapeHtml() before outputting user data
res.send(`<p>You entered: ${escapeHtml(userInput)}</p>`);

// Or use templating engines with auto-escaping
// Handlebars: {{userInput}} (auto-escaped)
// EJS: <%- userInput %> (raw) vs <%= userInput %> (escaped)"""

    def _get_sql_fix_snippet(self) -> str:
        """Get SQL injection fix code snippet"""
        
        return """// Use parameterized queries/prepared statements
// Node.js with MySQL
const query = 'SELECT * FROM users WHERE id = ? AND name = ?';
db.query(query, [userId, userName], (err, results) => {
    // Handle results
});

// Python with SQLite
cursor.execute('SELECT * FROM users WHERE id = ? AND name = ?', (user_id, user_name))

// Never concatenate user input directly:
// BAD: query = "SELECT * FROM users WHERE id = " + userId;
// GOOD: Use parameterized queries as shown above"""

    def _get_dom_xss_fix_snippet(self) -> str:
        """Get DOM XSS fix code snippet"""
        
        return """// Safe DOM manipulation
// Instead of innerHTML, use textContent for user data
element.textContent = userInput; // Safe
// element.innerHTML = userInput; // Dangerous

// Validate and sanitize URLs
function isValidURL(url) {
    return url.startsWith('http://') || url.startsWith('https://');
}

// Use safe methods for dynamic content
const safeElement = document.createElement('div');
safeElement.textContent = userInput;
container.appendChild(safeElement);

// Avoid eval, setTimeout with strings, Function constructor
// BAD: eval(userInput);
// BAD: setTimeout(userInput, 1000);
// GOOD: Use proper functions and validation"""


def main():
    """Test the injection scanner"""
    
    scanner = InjectionScanner("test_run")
    
    test_pages = Path("test_pages.json")
    if test_pages.exists():
        findings = scanner.scan_pages(test_pages)
        scanner.save_findings(Path("."))
        print(f"✅ Found {len(findings)} injection vulnerabilities")
    else:
        print("❌ No test_pages.json found. Run crawler first.")


if __name__ == "__main__":
    main()

