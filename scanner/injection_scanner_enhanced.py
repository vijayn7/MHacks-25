import json
import uuid
import re
import random
import string
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode
from base_scanner import BaseScanner


class EnhancedInjectionScanner(BaseScanner):
    """Enhanced injection scanner with dynamic testing and reduced false positives"""

    # More sophisticated XSS payloads with encoding variations
    XSS_PAYLOADS = [
        # Basic XSS
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        
        # Encoded XSS
        "&lt;script&gt;alert('XSS')&lt;/script&gt;",
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
        "&#60;script&#62;alert('XSS')&#60;/script&#62;",
        
        # Context-specific XSS
        "javascript:alert('XSS')",
        "'\"><script>alert('XSS')</script>",
        "\"><script>alert('XSS')</script>",
        "';alert('XSS');//",
        
        # DOM-based XSS indicators
        "document.cookie",
        "window.location",
        "eval(",
        
        # Filter bypass attempts
        "<ScRiPt>alert('XSS')</ScRiPt>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<iframe src=javascript:alert('XSS')></iframe>"
    ]

    # SQL injection payloads with different techniques
    SQL_PAYLOADS = [
        # Basic SQL injection
        "' OR '1'='1",
        "' OR 1=1--",
        "'; DROP TABLE users;--",
        "' UNION SELECT NULL,NULL,NULL--",
        
        # Time-based blind SQL injection
        "'; WAITFOR DELAY '00:00:05';--",
        "' OR SLEEP(5)--",
        "' OR pg_sleep(5)--",
        
        # Error-based SQL injection
        "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        
        # Boolean-based blind SQL injection
        "' AND 1=1--",
        "' AND 1=2--",
        "admin'--",
        "admin'/*",
        
        # Union-based SQL injection
        "' UNION SELECT 1,2,3--",
        "' UNION ALL SELECT NULL,NULL,NULL--"
    ]

    # Command injection payloads
    COMMAND_PAYLOADS = [
        "; ls -la",
        "| whoami",
        "; cat /etc/passwd",
        "$(whoami)",
        "`id`",
        "& dir",
        "; ping -c 1 127.0.0.1",
        "| ping -n 1 127.0.0.1",
        "; sleep 5",
        "& sleep 5"
    ]

    # Enhanced error patterns with confidence scoring
    SQL_ERROR_PATTERNS = [
        # MySQL errors
        (r"SQL syntax.*MySQL", 0.9),
        (r"Warning.*mysql_.*", 0.8),
        (r"valid MySQL result", 0.9),
        (r"MySqlClient\.", 0.8),
        
        # PostgreSQL errors
        (r"PostgreSQL.*ERROR", 0.9),
        (r"Warning.*pg_.*", 0.8),
        (r"valid PostgreSQL result", 0.9),
        (r"Npgsql\.", 0.8),
        
        # SQL Server errors
        (r"Driver.* SQL[\-\_\ ]*Server", 0.9),
        (r"OLE DB.* SQL Server", 0.9),
        (r"(\W|\A)SQL Server.*Driver", 0.9),
        (r"Warning.*mssql_.*", 0.8),
        (r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}'", 0.9),
        (r"ODBC SQL Server Driver", 0.9),
        (r"SqlException", 0.8),
        
        # Oracle errors
        (r"ORA-[0-9][0-9][0-9][0-9]", 0.9),
        (r"Oracle error", 0.8),
        (r"Oracle.*Driver", 0.8),
        (r"Warning.*oci_.*", 0.8),
        (r"Warning.*ora_.*", 0.8)
    ]

    def __init__(self, run_id: str):
        super().__init__(run_id)
        self.test_seed = str(uuid.uuid4())[:8]

    def scan_pages(self, pages_file: Path) -> List[Dict]:
        """Enhanced injection scanning with dynamic testing"""

        print(f"🔍 Enhanced injection scanning for run {self.run_id}")

        data = self._load_pages_data(pages_file)
        pages = data.get('pages', [])

        # Analyze each page for injection vulnerabilities
        for page in pages:
            self._analyze_page_injections_enhanced(page)

        return self.findings

    def _analyze_page_injections_enhanced(self, page: Dict):
        """Enhanced injection analysis with dynamic testing"""

        url = page['url']
        status_code = page.get('status_code', 0)
        headers = {k.lower(): v for k, v in page.get('headers', {}).items()}
        html_content = page.get('html_snippet', '')
        forms = page.get('forms', [])
        scripts = page.get('scripts', [])

        print(f"  🔍 Enhanced injection analysis for {url}")

        # Context analysis
        context = self._analyze_injection_context(url, headers, html_content, forms, scripts)
        
        # Only test pages that are likely to be vulnerable
        if self._should_test_page(context):
            # Test for XSS vulnerabilities
            self._test_xss_vulnerabilities(url, html_content, forms, context)
            
            # Test for SQL injection vulnerabilities
            self._test_sql_injection(url, html_content, forms, context)
            
            # Test for command injection vulnerabilities
            self._test_command_injection(url, html_content, forms, context)
            
            # Analyze reflected content for injection indicators
            self._analyze_reflected_content(url, html_content, context)

    def _analyze_injection_context(self, url: str, headers: Dict, html_content: str, 
                                 forms: List, scripts: List) -> Dict:
        """Analyze context to determine injection testing strategy"""
        
        return {
            'is_api': self._is_api_endpoint(url),
            'has_forms': len(forms) > 0,
            'has_scripts': len(scripts) > 0,
            'has_user_input': self._has_user_input_indicators(html_content),
            'content_type': headers.get('content-type', ''),
            'is_dynamic': self._is_dynamic_content(html_content),
            'has_database_indicators': self._has_database_indicators(html_content, headers),
            'has_command_indicators': self._has_command_indicators(html_content),
            'url_params': self._extract_url_parameters(url),
            'form_fields': self._extract_form_fields(forms)
        }

    def _should_test_page(self, context: Dict) -> bool:
        """Determine if page should be tested for injections"""
        
        # Don't test static resources
        if 'text/html' not in context['content_type'] and context['content_type']:
            return False
            
        # Don't test pages without user input indicators
        if not (context['has_forms'] or context['has_user_input'] or context['url_params']):
            return False
            
        return True

    def _test_xss_vulnerabilities(self, url: str, html_content: str, forms: List, context: Dict):
        """Test for XSS vulnerabilities with enhanced detection"""
        
        # Test URL parameters for reflected XSS
        if context['url_params']:
            self._test_reflected_xss_url(url, context['url_params'])
        
        # Test form fields for stored/persistent XSS indicators
        if context['has_forms']:
            self._test_form_xss(url, forms, context)
        
        # Analyze existing content for XSS indicators
        self._analyze_xss_indicators(url, html_content, context)

    def _test_reflected_xss_url(self, url: str, url_params: Dict):
        """Test URL parameters for reflected XSS"""
        
        for param_name, param_values in url_params.items():
            # Use a unique test payload
            test_payload = f"XSS_TEST_{self.test_seed}_INJECTION"
            
            # Check if the parameter value is reflected in the URL or likely to be in response
            for param_value in param_values:
                if test_payload in param_value:
                    # This indicates potential reflection - check for proper encoding
                    if self._check_xss_reflection(test_payload, param_value):
                        self._add_finding(
                            category='reflected_xss',
                            severity=self._calculate_xss_severity(param_name, url),
                            title=f'Potential Reflected XSS in Parameter: {param_name}',
                            description=f'Parameter {param_name} appears to reflect user input without proper encoding',
                            evidence={
                                'url': url,
                                'parameter': param_name,
                                'reflected_value': param_value,
                                'test_payload': test_payload,
                                'vulnerability_type': 'reflected_xss'
                            },
                            fix_snippet='Encode user input using HTML entity encoding or use a templating engine with auto-escaping',
                            reproduce_command=f'curl "{url}" | grep -i "{test_payload}"',
                            owasp_category='A03 - Injection'
                        )

    def _test_form_xss(self, url: str, forms: List, context: Dict):
        """Test forms for XSS vulnerabilities"""
        
        for form in forms:
            form_action = form.get('action', '')
            form_method = form.get('method', 'GET').upper()
            form_fields = form.get('fields', [])
            
            # Look for dangerous form fields
            dangerous_fields = ['search', 'query', 'comment', 'message', 'content', 'name', 'email']
            
            for field in form_fields:
                field_name = field.get('name', '').lower()
                field_type = field.get('type', 'text')
                
                if any(danger in field_name for danger in dangerous_fields):
                    self._add_finding(
                        category='potential_xss',
                        severity='medium',
                        title=f'Potential XSS in Form Field: {field_name}',
                        description=f'Form field {field_name} may be vulnerable to XSS attacks',
                        evidence={
                            'url': url,
                            'form_action': form_action,
                            'form_method': form_method,
                            'field_name': field_name,
                            'field_type': field_type,
                            'dangerous_pattern': next(danger for danger in dangerous_fields if danger in field_name)
                        },
                        fix_snippet='Validate and encode all user input from form fields',
                        reproduce_command=f'Test form submission with XSS payloads',
                        owasp_category='A03 - Injection'
                    )

    def _test_sql_injection(self, url: str, html_content: str, forms: List, context: Dict):
        """Test for SQL injection vulnerabilities"""
        
        # Only test if there are database indicators
        if not context['has_database_indicators']:
            return
            
        # Check for SQL error patterns in existing content
        self._analyze_sql_errors(url, html_content)
        
        # Test URL parameters for SQL injection
        if context['url_params']:
            self._test_sql_injection_params(url, context['url_params'])

    def _test_sql_injection_params(self, url: str, url_params: Dict):
        """Test URL parameters for SQL injection"""
        
        # Look for database-related parameters
        db_params = ['id', 'user_id', 'category', 'search', 'query', 'page', 'limit', 'offset']
        
        for param_name, param_values in url_params.items():
            if any(db_param in param_name.lower() for db_param in db_params):
                # Check if parameter values look like they might be used in SQL
                for param_value in param_values:
                    if self._looks_like_sql_input(param_value):
                        self._add_finding(
                            category='potential_sql_injection',
                            severity='high',
                            title=f'Potential SQL Injection in Parameter: {param_name}',
                            description=f'Parameter {param_name} with value {param_value} may be vulnerable to SQL injection',
                            evidence={
                                'url': url,
                                'parameter': param_name,
                                'parameter_value': param_value,
                                'sql_indicators': self._identify_sql_indicators(param_value)
                            },
                            fix_snippet='Use parameterized queries or prepared statements',
                            reproduce_command=f'Test parameter with SQL injection payloads',
                            owasp_category='A03 - Injection'
                        )

    def _test_command_injection(self, url: str, html_content: str, forms: List, context: Dict):
        """Test for command injection vulnerabilities"""
        
        # Only test if there are command execution indicators
        if not context['has_command_indicators']:
            return
            
        # Look for system-related parameters
        system_params = ['cmd', 'command', 'exec', 'system', 'shell', 'ping', 'traceroute']
        
        if context['url_params']:
            for param_name, param_values in url_params.items():
                if any(sys_param in param_name.lower() for sys_param in system_params):
                    self._add_finding(
                        category='potential_command_injection',
                        severity='critical',
                        title=f'Potential Command Injection in Parameter: {param_name}',
                        description=f'Parameter {param_name} may allow command injection',
                        evidence={
                            'url': url,
                            'parameter': param_name,
                            'parameter_values': param_values,
                            'system_indicators': [param for param in system_params if param in param_name.lower()]
                        },
                        fix_snippet='Validate input and avoid direct system command execution',
                        reproduce_command=f'Test parameter with command injection payloads',
                        owasp_category='A03 - Injection'
                    )

    def _analyze_sql_errors(self, url: str, html_content: str):
        """Analyze HTML content for SQL error patterns"""
        
        for pattern, confidence in self.SQL_ERROR_PATTERNS:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            if matches:
                self._add_finding(
                    category='sql_error_disclosure',
                    severity='medium' if confidence > 0.8 else 'low',
                    title=f'SQL Error Disclosure Detected',
                    description=f'SQL error messages detected in response (confidence: {confidence:.1%})',
                    evidence={
                        'url': url,
                        'error_pattern': pattern,
                        'matches': matches[:3],  # Show first 3 matches
                        'confidence': confidence,
                        'error_type': self._classify_sql_error(pattern)
                    },
                    fix_snippet='Configure application to not display SQL errors to users',
                    reproduce_command=f'curl "{url}" | grep -i "sql\\|mysql\\|postgres"',
                    owasp_category='A03 - Injection'
                )

    def _analyze_xss_indicators(self, url: str, html_content: str, context: Dict):
        """Analyze content for XSS indicators"""
        
        # Look for dangerous JavaScript patterns
        dangerous_js_patterns = [
            r'eval\s*\(',
            r'innerHTML\s*=',
            r'document\.write\s*\(',
            r'setTimeout\s*\(\s*["\'].*["\']',
            r'setInterval\s*\(\s*["\'].*["\']',
            r'Function\s*\(',
            r'new\s+Function\s*\('
        ]
        
        for pattern in dangerous_js_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            if matches:
                self._add_finding(
                    category='dangerous_javascript',
                    severity='medium',
                    title=f'Dangerous JavaScript Pattern Detected',
                    description=f'Potentially dangerous JavaScript pattern detected: {pattern}',
                    evidence={
                        'url': url,
                        'pattern': pattern,
                        'matches': matches[:3],
                        'context': context
                    },
                    fix_snippet='Avoid dangerous JavaScript functions and use safer alternatives',
                    reproduce_command=f'curl "{url}" | grep -i "{pattern}"',
                    owasp_category='A03 - Injection'
                )

    def _is_api_endpoint(self, url: str) -> bool:
        """Check if URL appears to be an API endpoint"""
        api_indicators = ['/api/', '/v1/', '/v2/', '/rest/', '/graphql', '.json', '.xml']
        return any(indicator in url.lower() for indicator in api_indicators)

    def _has_user_input_indicators(self, html_content: str) -> bool:
        """Check if HTML content indicates user input handling"""
        input_indicators = [
            r'<input[^>]*>',
            r'<textarea[^>]*>',
            r'<select[^>]*>',
            r'name\s*=\s*["\'][^"\']*["\']',
            r'id\s*=\s*["\'][^"\']*["\']'
        ]
        
        for pattern in input_indicators:
            if re.search(pattern, html_content, re.IGNORECASE):
                return True
        return False

    def _is_dynamic_content(self, html_content: str) -> bool:
        """Check if content appears to be dynamically generated"""
        dynamic_indicators = [
            r'{{.*?}}',  # Template variables
            r'<%.*?%>',  # Server-side includes
            r'\$\{.*?\}',  # Variable substitution
            r'Response\.Write',  # ASP.NET
            r'echo\s+',  # PHP
            r'print\s+'  # PHP/Python
        ]
        
        for pattern in dynamic_indicators:
            if re.search(pattern, html_content, re.IGNORECASE):
                return True
        return False

    def _has_database_indicators(self, html_content: str, headers: Dict) -> bool:
        """Check for database-related indicators"""
        db_indicators = [
            'mysql', 'postgres', 'sqlite', 'oracle', 'sql server',
            'database', 'query', 'select', 'insert', 'update', 'delete'
        ]
        
        content_lower = html_content.lower()
        headers_lower = str(headers).lower()
        
        return any(indicator in content_lower or indicator in headers_lower for indicator in db_indicators)

    def _has_command_indicators(self, html_content: str) -> bool:
        """Check for command execution indicators"""
        cmd_indicators = [
            'system', 'exec', 'shell_exec', 'passthru', 'popen',
            'proc_open', 'cmd', 'command', 'ping', 'traceroute'
        ]
        
        content_lower = html_content.lower()
        return any(indicator in content_lower for indicator in cmd_indicators)

    def _extract_url_parameters(self, url: str) -> Dict:
        """Extract URL parameters"""
        try:
            parsed = urlparse(url)
            return parse_qs(parsed.query)
        except:
            return {}

    def _extract_form_fields(self, forms: List) -> List:
        """Extract form fields from forms"""
        all_fields = []
        for form in forms:
            all_fields.extend(form.get('fields', []))
        return all_fields

    def _check_xss_reflection(self, test_payload: str, reflected_value: str) -> bool:
        """Check if XSS payload is reflected without proper encoding"""
        # Simple check - in real implementation, this would be more sophisticated
        return test_payload in reflected_value and '<' not in reflected_value

    def _calculate_xss_severity(self, param_name: str, url: str) -> str:
        """Calculate XSS severity based on context"""
        if 'admin' in param_name.lower() or 'admin' in url.lower():
            return 'high'
        elif any(danger in param_name.lower() for danger in ['search', 'query', 'comment']):
            return 'medium'
        else:
            return 'low'

    def _looks_like_sql_input(self, value: str) -> bool:
        """Check if parameter value looks like it might be used in SQL"""
        sql_indicators = ['select', 'insert', 'update', 'delete', 'union', 'where', 'order by']
        value_lower = value.lower()
        return any(indicator in value_lower for indicator in sql_indicators)

    def _identify_sql_indicators(self, value: str) -> List[str]:
        """Identify SQL-related indicators in parameter value"""
        sql_indicators = ['select', 'insert', 'update', 'delete', 'union', 'where', 'order by', 'group by']
        value_lower = value.lower()
        return [indicator for indicator in sql_indicators if indicator in value_lower]

    def _classify_sql_error(self, pattern: str) -> str:
        """Classify the type of SQL error"""
        if 'mysql' in pattern.lower():
            return 'MySQL'
        elif 'postgres' in pattern.lower():
            return 'PostgreSQL'
        elif 'sql server' in pattern.lower() or 'mssql' in pattern.lower():
            return 'SQL Server'
        elif 'ora-' in pattern.lower():
            return 'Oracle'
        else:
            return 'Unknown'


if __name__ == "__main__":
    # Test the enhanced injection scanner
    scanner = EnhancedInjectionScanner("test_run")
    test_pages = Path("test_pages.json")
    if test_pages.exists():
        findings = scanner.scan_pages(test_pages)
        print(f"Enhanced injection scanner found {len(findings)} issues")
        for finding in findings:
            print(f"  - {finding['title']} ({finding['severity']})")
    else:
        print("No test_pages.json found")
