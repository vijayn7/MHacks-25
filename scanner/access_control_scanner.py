import json
import uuid
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse, urljoin
from base_scanner import BaseScanner


class AccessControlScanner(BaseScanner):
    """Analyzes access control vulnerabilities (OWASP A01)"""

    # Common admin/sensitive paths
    ADMIN_PATHS = [
        '/admin', '/administrator', '/admin.php', '/admin.html',
        '/wp-admin', '/phpmyadmin', '/phpMyAdmin', '/pma',
        '/manager', '/management', '/control', '/dashboard',
        '/api/admin', '/api/v1/admin', '/api/admin/v1',
        '/backend', '/backoffice', '/cms', '/panel',
        '/user', '/users', '/account', '/accounts',
        '/profile', '/profiles', '/settings', '/config',
        '/database', '/db', '/sql', '/mysql',
        '/logs', '/log', '/debug', '/test',
        '/dev', '/development', '/staging', '/beta'
    ]

    # Sensitive file extensions
    SENSITIVE_EXTENSIONS = [
        '.env', '.config', '.conf', '.ini', '.xml', '.json',
        '.sql', '.db', '.sqlite', '.log', '.txt', '.bak',
        '.backup', '.old', '.orig', '.tmp', '.temp',
        '.key', '.pem', '.crt', '.p12', '.pfx'
    ]

    # Common sensitive files
    SENSITIVE_FILES = [
        'robots.txt', 'sitemap.xml', 'crossdomain.xml',
        'phpinfo.php', 'info.php', 'test.php', 'test.html',
        'admin.php', 'login.php', 'config.php', 'settings.php',
        '.htaccess', '.htpasswd', 'web.config', 'app.config',
        'package.json', 'composer.json', 'requirements.txt',
        'Dockerfile', 'docker-compose.yml', '.git/config',
        'README.md', 'CHANGELOG.md', 'LICENSE', 'LICENSE.txt'
    ]

    def __init__(self, run_id: str):
        super().__init__(run_id)

    def scan_pages(self, pages_file: Path) -> List[Dict]:
        """Scan pages for access control vulnerabilities"""

        print(f"🔍 Scanning for access control vulnerabilities for run {self.run_id}")

        data = self._load_pages_data(pages_file)
        pages = data.get('pages', [])

        for page in pages:
            self._analyze_page_access_control(page)

        # Check for directory traversal patterns
        self._check_directory_traversal(pages)

        # Check for IDOR patterns
        self._check_idor_patterns(pages)

        return self.findings

    def _analyze_page_access_control(self, page: Dict):
        """Analyze a single page for access control issues"""

        url = page['url']
        status_code = page.get('status_code', 0)
        headers = {k.lower(): v for k, v in page.get('headers', {}).items()}

        print(f"  🔐 Analyzing access control for {url}")

        # Check for admin/sensitive paths
        self._check_sensitive_paths(url, status_code)

        # Check for missing authentication headers
        self._check_auth_headers(url, headers)

        # Check for information disclosure
        self._check_info_disclosure(url, page)

        # Check for weak authorization
        self._check_weak_authorization(url, headers)

    def _check_sensitive_paths(self, url: str, status_code: int):
        """Check if sensitive paths are accessible"""

        parsed_url = urlparse(url)
        path = parsed_url.path.lower()

        # Check for admin paths
        for admin_path in self.ADMIN_PATHS:
            if admin_path in path:
                if status_code == 200:
                    self._add_finding(
                        category='access_control',
                        severity='high',
                        title=f'Admin Path Accessible: {admin_path}',
                        description=f'Sensitive admin path "{admin_path}" is accessible without proper authentication.',
                        evidence={
                            'url': url,
                            'sensitive_path': admin_path,
                            'status_code': status_code,
                            'path_type': 'admin'
                        },
                        fix_snippet=self._get_access_control_fix_snippet(),
                        reproduce_command=f"curl -I '{url}'",
                        owasp_category="A01 - Broken Access Control"
                    )
                elif status_code in [401, 403]:
                    # This is actually good - path exists but is protected
                    pass
                else:
                    # Other status codes might indicate issues
                    self._add_finding(
                        category='access_control',
                        severity='medium',
                        title=f'Admin Path Returns Unexpected Status: {admin_path}',
                        description=f'Admin path "{admin_path}" returns status {status_code}, which may indicate misconfiguration.',
                        evidence={
                            'url': url,
                            'sensitive_path': admin_path,
                            'status_code': status_code,
                            'expected_status': '401 or 403'
                        },
                        fix_snippet=self._get_access_control_fix_snippet(),
                        reproduce_command=f"curl -I '{url}'",
                        owasp_category="A01 - Broken Access Control"
                    )

        # Check for sensitive file extensions
        for ext in self.SENSITIVE_EXTENSIONS:
            if path.endswith(ext):
                if status_code == 200:
                    self._add_finding(
                        category='access_control',
                        severity='high',
                        title=f'Sensitive File Accessible: {ext}',
                        description=f'File with sensitive extension "{ext}" is accessible without proper protection.',
                        evidence={
                            'url': url,
                            'sensitive_extension': ext,
                            'status_code': status_code,
                            'file_type': 'sensitive'
                        },
                        fix_snippet=self._get_file_protection_fix_snippet(),
                        reproduce_command=f"curl '{url}'",
                        owasp_category="A01 - Broken Access Control"
                    )

        # Check for sensitive files
        filename = path.split('/')[-1].lower()
        for sensitive_file in self.SENSITIVE_FILES:
            if filename == sensitive_file.lower():
                if status_code == 200:
                    self._add_finding(
                        category='access_control',
                        severity='medium',
                        title=f'Sensitive File Accessible: {sensitive_file}',
                        description=f'Sensitive file "{sensitive_file}" is accessible and may contain sensitive information.',
                        evidence={
                            'url': url,
                            'sensitive_file': sensitive_file,
                            'status_code': status_code,
                            'file_type': 'sensitive'
                        },
                        fix_snippet=self._get_file_protection_fix_snippet(),
                        reproduce_command=f"curl '{url}'",
                        owasp_category="A01 - Broken Access Control"
                    )

    def _check_auth_headers(self, url: str, headers: Dict):
        """Check for missing authentication/authorization headers"""

        # Check for missing WWW-Authenticate header on 401 responses
        if 'www-authenticate' not in headers:
            # This might be intentional, but worth noting
            pass

        # Check for weak authentication methods
        auth_header = headers.get('www-authenticate', '')
        if auth_header:
            if 'Basic' in auth_header and 'Digest' not in auth_header:
                self._add_finding(
                    category='access_control',
                    severity='medium',
                    title='Weak Authentication Method: Basic Auth',
                    description='Server uses Basic authentication without Digest, which transmits credentials in base64.',
                    evidence={
                        'url': url,
                        'auth_header': auth_header,
                        'auth_method': 'Basic'
                    },
                    fix_snippet=self._get_auth_fix_snippet(),
                    reproduce_command=f"curl -I '{url}'",
                    owasp_category="A01 - Broken Access Control"
                )

    def _check_info_disclosure(self, url: str, page: Dict):
        """Check for information disclosure vulnerabilities"""

        html_content = page.get('html_snippet', '')
        headers = {k.lower(): v for k, v in page.get('headers', {}).items()}

        # Check for debug information in HTML
        debug_patterns = [
            r'debug\s*[:=]\s*true',
            r'development\s*[:=]\s*true',
            r'console\.log\(',
            r'var_dump\(',
            r'print_r\(',
            r'<!--.*debug.*-->',
            r'<!--.*development.*-->',
            r'error_reporting\(',
            r'ini_set\(',
            r'phpinfo\('
        ]

        found_debug = []
        for pattern in debug_patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                found_debug.append(pattern)

        if found_debug:
            self._add_finding(
                category='access_control',
                severity='medium',
                title='Debug Information Disclosure',
                description='Page contains debug or development information that should not be exposed in production.',
                evidence={
                    'url': url,
                    'debug_patterns': found_debug,
                    'html_snippet': html_content[:300] + '...' if len(html_content) > 300 else html_content
                },
                fix_snippet=self._get_debug_fix_snippet(),
                reproduce_command=f"curl '{url}' | grep -i debug",
                owasp_category="A01 - Broken Access Control"
            )

        # Check for sensitive information in headers
        sensitive_headers = ['x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'server']
        for header in sensitive_headers:
            if header in headers and headers[header]:
                self._add_finding(
                    category='access_control',
                    severity='low',
                    title=f'Information Disclosure: {header}',
                    description=f'Header "{header}" reveals server technology information.',
                    evidence={
                        'url': url,
                        'disclosed_header': header,
                        'header_value': headers[header]
                    },
                    fix_snippet=self._get_header_hiding_fix_snippet(),
                    reproduce_command=f"curl -I '{url}'",
                    owasp_category="A01 - Broken Access Control"
                )

    def _check_weak_authorization(self, url: str, headers: Dict):
        """Check for weak authorization mechanisms"""

        # Check for missing rate limiting headers
        if 'x-ratelimit-limit' not in headers and 'x-rate-limit-limit' not in headers:
            # This is not necessarily a vulnerability, but worth noting for API endpoints
            if '/api/' in url or url.endswith('.json') or url.endswith('.xml'):
                self._add_finding(
                    category='access_control',
                    severity='low',
                    title='Missing Rate Limiting Headers',
                    description='API endpoint does not indicate rate limiting in response headers.',
                    evidence={
                        'url': url,
                        'endpoint_type': 'api',
                        'missing_headers': ['x-ratelimit-limit', 'x-rate-limit-limit']
                    },
                    fix_snippet=self._get_rate_limiting_fix_snippet(),
                    reproduce_command=f"curl -I '{url}'",
                    owasp_category="A01 - Broken Access Control"
                )

    def _check_directory_traversal(self, pages: List[Dict]):
        """Check for directory traversal vulnerabilities"""

        # Look for URLs with directory traversal patterns
        traversal_patterns = [
            r'\.\./', r'\.\.\\', r'%2e%2e%2f', r'%2e%2e%5c',
            r'\.\.%2f', r'\.\.%5c', r'%252e%252e%252f'
        ]

        for page in pages:
            url = page['url']
            for pattern in traversal_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    self._add_finding(
                        category='access_control',
                        severity='high',
                        title='Potential Directory Traversal',
                        description=f'URL contains directory traversal pattern: {pattern}',
                        evidence={
                            'url': url,
                            'traversal_pattern': pattern,
                            'status_code': page.get('status_code', 0)
                        },
                        fix_snippet=self._get_directory_traversal_fix_snippet(),
                        reproduce_command=f"curl '{url}'",
                        owasp_category="A01 - Broken Access Control"
                    )

    def _check_idor_patterns(self, pages: List[Dict]):
        """Check for Insecure Direct Object Reference patterns"""

        # Look for URLs with numeric IDs that might be predictable
        id_patterns = [
            r'/user/\d+', r'/profile/\d+', r'/account/\d+',
            r'/id=\d+', r'/userId=\d+', r'/accountId=\d+',
            r'/file/\d+', r'/document/\d+', r'/order/\d+'
        ]

        for page in pages:
            url = page['url']
            for pattern in id_patterns:
                if re.search(pattern, url):
                    # Check if the ID is sequential or predictable
                    match = re.search(r'(\d+)', url)
                    if match:
                        id_value = int(match.group(1))
                        if id_value < 1000:  # Small IDs are more predictable
                            self._add_finding(
                                category='access_control',
                                severity='medium',
                                title='Potential Insecure Direct Object Reference',
                                description=f'URL contains predictable numeric ID ({id_value}) that might be vulnerable to IDOR attacks.',
                                evidence={
                                    'url': url,
                                    'id_pattern': pattern,
                                    'id_value': id_value,
                                    'status_code': page.get('status_code', 0)
                                },
                                fix_snippet=self._get_idor_fix_snippet(),
                                reproduce_command=f"curl '{url}'",
                                owasp_category="A01 - Broken Access Control"
                            )

    def _get_access_control_fix_snippet(self) -> str:
        """Get access control fix code snippet"""
        
        return """// Implement proper access control
// 1. Authentication check
function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    next();
}

// 2. Authorization check
function requireRole(role) {
    return (req, res, next) => {
        if (!req.session.user || !req.session.user.roles.includes(role)) {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }
        next();
    };
}

// 3. Resource ownership check
function requireOwnership(req, res, next) {
    const resourceId = req.params.id;
    const userId = req.session.userId;
    
    if (!isOwner(userId, resourceId)) {
        return res.status(403).json({ error: 'Access denied' });
    }
    next();
}

// Usage
app.get('/admin', requireAuth, requireRole('admin'), adminHandler);
app.get('/user/:id', requireAuth, requireOwnership, userHandler);"""

    def _get_file_protection_fix_snippet(self) -> str:
        """Get file protection fix code snippet"""
        
        return """// Protect sensitive files
// 1. Nginx configuration
location ~* \\.(env|config|conf|ini|sql|log|bak)$ {
    deny all;
    return 404;
}

// 2. Apache .htaccess
<FilesMatch "\\.(env|config|conf|ini|sql|log|bak)$">
    Order allow,deny
    Deny from all
</FilesMatch>

// 3. Node.js middleware
app.use('/admin', (req, res, next) => {
    if (!req.session.isAdmin) {
        return res.status(403).send('Access denied');
    }
    next();
});"""

    def _get_auth_fix_snippet(self) -> str:
        """Get authentication fix code snippet"""
        
        return """// Use strong authentication methods
// 1. JWT with proper validation
const jwt = require('jsonwebtoken');

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }
    
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
}

// 2. Session-based auth with secure settings
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true,
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));"""

    def _get_debug_fix_snippet(self) -> str:
        """Get debug information fix code snippet"""
        
        return """// Remove debug information from production
// 1. Environment-based configuration
const isProduction = process.env.NODE_ENV === 'production';

if (!isProduction) {
    console.log('Debug info:', debugData);
}

// 2. Remove debug routes in production
if (!isProduction) {
    app.get('/debug', debugHandler);
}

// 3. Disable error details in production
app.use((err, req, res, next) => {
    if (isProduction) {
        res.status(500).json({ error: 'Internal server error' });
    } else {
        res.status(500).json({ error: err.message, stack: err.stack });
    }
});"""

    def _get_header_hiding_fix_snippet(self) -> str:
        """Get header hiding fix code snippet"""
        
        return """// Hide server information headers
// 1. Nginx
server_tokens off;
more_clear_headers 'Server';
more_clear_headers 'X-Powered-By';

// 2. Apache
ServerTokens Prod
Header unset X-Powered-By
Header unset Server

// 3. Express.js
app.disable('x-powered-by');
app.use((req, res, next) => {
    res.removeHeader('X-Powered-By');
    next();
});"""

    def _get_rate_limiting_fix_snippet(self) -> str:
        """Get rate limiting fix code snippet"""
        
        return """// Implement rate limiting
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP',
    standardHeaders: true,
    legacyHeaders: false,
});

app.use('/api/', limiter);

// Custom rate limiting
const slowDown = require('express-slow-down');
const speedLimiter = slowDown({
    windowMs: 15 * 60 * 1000,
    delayAfter: 2,
    delayMs: 500
});

app.use(speedLimiter);"""

    def _get_directory_traversal_fix_snippet(self) -> str:
        """Get directory traversal fix code snippet"""
        
        return """// Prevent directory traversal attacks
const path = require('path');

function safePath(userInput) {
    // Normalize and resolve the path
    const normalizedPath = path.normalize(userInput);
    
    // Check if path is within allowed directory
    const allowedDir = path.resolve('./uploads');
    const resolvedPath = path.resolve(allowedDir, normalizedPath);
    
    if (!resolvedPath.startsWith(allowedDir)) {
        throw new Error('Path traversal detected');
    }
    
    return resolvedPath;
}

// Usage
app.get('/file/:filename', (req, res) => {
    try {
        const safeFilePath = safePath(req.params.filename);
        res.sendFile(safeFilePath);
    } catch (error) {
        res.status(400).json({ error: 'Invalid file path' });
    }
});"""

    def _get_idor_fix_snippet(self) -> str:
        """Get IDOR fix code snippet"""
        
        return """// Prevent Insecure Direct Object References
// 1. Use UUIDs instead of sequential IDs
const { v4: uuidv4 } = require('uuid');

// Generate UUID for new resources
const resourceId = uuidv4();

// 2. Implement proper authorization checks
function checkResourceAccess(userId, resourceId) {
    // Check if user owns the resource
    return db.query(
        'SELECT id FROM resources WHERE id = ? AND owner_id = ?',
        [resourceId, userId]
    ).then(result => result.length > 0);
}

// 3. Use indirect object references
const resourceMap = new Map(); // Map public IDs to internal IDs

function getPublicId(internalId) {
    const publicId = uuidv4();
    resourceMap.set(publicId, internalId);
    return publicId;
}

function getInternalId(publicId) {
    return resourceMap.get(publicId);
}

// Usage
app.get('/resource/:publicId', authenticateToken, async (req, res) => {
    const internalId = getInternalId(req.params.publicId);
    if (!internalId || !await checkResourceAccess(req.user.id, internalId)) {
        return res.status(403).json({ error: 'Access denied' });
    }
    // Return resource data
});"""


def main():
    """Test the access control scanner"""
    
    scanner = AccessControlScanner("test_run")
    
    test_pages = Path("test_pages.json")
    if test_pages.exists():
        findings = scanner.scan_pages(test_pages)
        scanner.save_findings(Path("."))
        print(f"✅ Found {len(findings)} access control vulnerabilities")
    else:
        print("❌ No test_pages.json found. Run crawler first.")


if __name__ == "__main__":
    main()
