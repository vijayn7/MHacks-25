import json
import uuid
import re
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs
from base_scanner import BaseScanner


class AuthScanner(BaseScanner):
    """Analyzes authentication and session management vulnerabilities (OWASP A07)"""

    # Common weak password patterns
    WEAK_PASSWORD_PATTERNS = [
        r'password', r'123456', r'admin', r'qwerty', r'letmein',
        r'welcome', r'monkey', r'dragon', r'master', r'hello',
        r'login', r'pass', r'secret', r'test', r'guest'
    ]

    # Common authentication endpoints
    AUTH_ENDPOINTS = [
        '/login', '/signin', '/auth', '/authenticate',
        '/signup', '/register', '/signout', '/logout',
        '/password', '/reset', '/forgot', '/change-password',
        '/profile', '/account', '/user', '/admin'
    ]

    # Session-related headers
    SESSION_HEADERS = [
        'set-cookie', 'cookie', 'authorization', 'x-auth-token',
        'x-session-id', 'x-csrf-token', 'x-xsrf-token'
    ]

    # Weak session patterns
    WEAK_SESSION_PATTERNS = [
        r'sessionid=\d+',  # Sequential session IDs
        r'token=\w{1,10}',  # Short tokens
        r'auth=\d+',  # Numeric auth tokens
        r'userid=\d+',  # User ID in session
        r'admin=true',  # Admin flag in session
        r'loggedin=true'  # Simple boolean flags
    ]

    def __init__(self, run_id: str):
        super().__init__(run_id)

    def scan_pages(self, pages_file: Path) -> List[Dict]:
        """Scan pages for authentication vulnerabilities"""

        print(f"🔍 Scanning for authentication vulnerabilities for run {self.run_id}")

        data = self._load_pages_data(pages_file)
        pages = data.get('pages', [])

        for page in pages:
            self._analyze_page_authentication(page)

        # Check for weak session management
        self._check_session_management(pages)

        # Check for authentication bypass
        self._check_auth_bypass(pages)

        return self.findings

    def _analyze_page_authentication(self, page: Dict):
        """Analyze a single page for authentication issues"""

        url = page['url']
        status_code = page.get('status_code', 0)
        headers = {k.lower(): v for k, v in page.get('headers', {}).items()}
        html_content = page.get('html_snippet', '')

        print(f"  🔐 Analyzing authentication for {url}")

        # Check for authentication endpoints
        self._check_auth_endpoints(url, status_code, headers, html_content)

        # Check for weak authentication mechanisms
        self._check_weak_auth_mechanisms(url, headers)

        # Check for password policy issues
        self._check_password_policy(url, html_content)

        # Check for session security
        self._check_session_security(url, headers, page)

    def _check_auth_endpoints(self, url: str, status_code: int, headers: Dict, html_content: str):
        """Check authentication endpoints for security issues"""

        parsed_url = urlparse(url)
        path = parsed_url.path.lower()

        # Check if this is an authentication endpoint
        is_auth_endpoint = any(endpoint in path for endpoint in self.AUTH_ENDPOINTS)

        if is_auth_endpoint:
            # Check for HTTPS usage
            if not url.startswith('https://'):
                self._add_finding(
                    category='authentication',
                    severity='high',
                    title='Authentication Over HTTP',
                    description=f'Authentication endpoint "{path}" is accessible over HTTP instead of HTTPS.',
                    evidence={
                        'url': url,
                        'endpoint': path,
                        'protocol': 'http',
                        'status_code': status_code
                    },
                    fix_snippet=self._get_https_fix_snippet(),
                    reproduce_command=f"curl -I '{url}'",
                    owasp_category="A07 - Identification and Authentication Failures"
                )

            # Check for missing security headers on auth pages
            if 'x-frame-options' not in headers:
                self._add_finding(
                    category='authentication',
                    severity='medium',
                    title='Missing X-Frame-Options on Auth Page',
                    description=f'Authentication page missing X-Frame-Options header, vulnerable to clickjacking.',
                    evidence={
                        'url': url,
                        'missing_header': 'x-frame-options',
                        'endpoint_type': 'authentication'
                    },
                    fix_snippet=self._get_frame_options_fix_snippet(),
                    reproduce_command=f"curl -I '{url}'",
                    owasp_category="A07 - Identification and Authentication Failures"
                )

            # Check for weak password fields
            if 'password' in html_content.lower():
                self._check_password_field_security(url, html_content)

    def _check_weak_auth_mechanisms(self, url: str, headers: Dict):
        """Check for weak authentication mechanisms"""

        # Check for Basic Auth without HTTPS
        auth_header = headers.get('www-authenticate', '')
        if 'Basic' in auth_header and not url.startswith('https://'):
            self._add_finding(
                category='authentication',
                severity='high',
                title='Basic Authentication Over HTTP',
                description='Basic authentication is used over HTTP, credentials are transmitted in base64.',
                evidence={
                    'url': url,
                    'auth_method': 'Basic',
                    'protocol': 'http',
                    'auth_header': auth_header
                },
                fix_snippet=self._get_basic_auth_fix_snippet(),
                reproduce_command=f"curl -I '{url}'",
                owasp_category="A07 - Identification and Authentication Failures"
            )

        # Check for missing CSRF protection
        if '/login' in url.lower() or '/signup' in url.lower():
            if 'x-csrf-token' not in headers and 'x-xsrf-token' not in headers:
                self._add_finding(
                    category='authentication',
                    severity='medium',
                    title='Missing CSRF Protection on Auth Form',
                    description='Authentication form may be missing CSRF protection.',
                    evidence={
                        'url': url,
                        'form_type': 'authentication',
                        'missing_csrf': True
                    },
                    fix_snippet=self._get_csrf_fix_snippet(),
                    reproduce_command=f"curl '{url}'",
                    owasp_category="A07 - Identification and Authentication Failures"
                )

    def _check_password_field_security(self, url: str, html_content: str):
        """Check password field security"""

        # Check for autocomplete on password fields
        if 'autocomplete="off"' not in html_content and 'password' in html_content:
            self._add_finding(
                category='authentication',
                severity='low',
                title='Password Field Missing Autocomplete Disable',
                description='Password field may not have autocomplete disabled.',
                evidence={
                    'url': url,
                    'field_type': 'password',
                    'autocomplete_disabled': False
                },
                fix_snippet=self._get_password_field_fix_snippet(),
                reproduce_command=f"curl '{url}' | grep -i password",
                owasp_category="A07 - Identification and Authentication Failures"
            )

        # Check for weak password requirements
        if any(pattern in html_content.lower() for pattern in ['minlength="1"', 'minlength="2"', 'minlength="3"']):
            self._add_finding(
                category='authentication',
                severity='medium',
                title='Weak Password Requirements',
                description='Password field has very short minimum length requirement.',
                evidence={
                    'url': url,
                    'field_type': 'password',
                    'min_length': 'very short'
                },
                fix_snippet=self._get_password_policy_fix_snippet(),
                reproduce_command=f"curl '{url}' | grep -i minlength",
                owasp_category="A07 - Identification and Authentication Failures"
            )

    def _check_password_policy(self, url: str, html_content: str):
        """Check password policy implementation"""

        # Look for password policy indicators
        policy_indicators = [
            'password policy', 'password requirements', 'password rules',
            'minimum length', 'uppercase', 'lowercase', 'numbers', 'special characters'
        ]

        has_policy = any(indicator in html_content.lower() for indicator in policy_indicators)

        if '/signup' in url.lower() or '/register' in url.lower():
            if not has_policy:
                self._add_finding(
                    category='authentication',
                    severity='medium',
                    title='Missing Password Policy Display',
                    description='Registration page does not display password policy requirements.',
                    evidence={
                        'url': url,
                        'page_type': 'registration',
                        'password_policy_displayed': False
                    },
                    fix_snippet=self._get_password_policy_fix_snippet(),
                    reproduce_command=f"curl '{url}' | grep -i password",
                    owasp_category="A07 - Identification and Authentication Failures"
                )

    def _check_session_security(self, url: str, headers: Dict, page: Dict):
        """Check session security"""

        cookies = page.get('cookies', [])

        for cookie in cookies:
            cookie_name = cookie.get('name', '').lower()
            cookie_value = cookie.get('value', '')

            # Check for session cookies without secure flag on HTTPS
            if any(session_word in cookie_name for session_word in ['session', 'auth', 'token', 'login']):
                if url.startswith('https://') and not cookie.get('secure', False):
                    self._add_finding(
                        category='authentication',
                        severity='high',
                        title=f'Insecure Session Cookie: {cookie_name}',
                        description=f'Session cookie "{cookie_name}" missing Secure flag on HTTPS site.',
                        evidence={
                            'url': url,
                            'cookie_name': cookie_name,
                            'secure_flag': False,
                            'protocol': 'https'
                        },
                        fix_snippet=self._get_secure_cookie_fix_snippet(),
                        reproduce_command=f"curl -I '{url}'",
                        owasp_category="A07 - Identification and Authentication Failures"
                    )

                # Check for session cookies without HttpOnly flag
                if not cookie.get('httpOnly', False):
                    self._add_finding(
                        category='authentication',
                        severity='medium',
                        title=f'Session Cookie Missing HttpOnly: {cookie_name}',
                        description=f'Session cookie "{cookie_name}" missing HttpOnly flag.',
                        evidence={
                            'url': url,
                            'cookie_name': cookie_name,
                            'httpOnly_flag': False
                        },
                        fix_snippet=self._get_httponly_cookie_fix_snippet(),
                        reproduce_command=f"curl -I '{url}'",
                        owasp_category="A07 - Identification and Authentication Failures"
                    )

                # Check for weak session tokens
                if self._is_weak_session_token(cookie_value):
                    self._add_finding(
                        category='authentication',
                        severity='high',
                        title=f'Weak Session Token: {cookie_name}',
                        description=f'Session cookie "{cookie_name}" contains weak/predictable token.',
                        evidence={
                            'url': url,
                            'cookie_name': cookie_name,
                            'token_pattern': 'weak/predictable',
                            'token_length': len(cookie_value)
                        },
                        fix_snippet=self._get_strong_token_fix_snippet(),
                        reproduce_command=f"curl -I '{url}'",
                        owasp_category="A07 - Identification and Authentication Failures"
                    )

    def _check_session_management(self, pages: List[Dict]):
        """Check session management across pages"""

        session_cookies = {}
        
        for page in pages:
            cookies = page.get('cookies', [])
            for cookie in cookies:
                cookie_name = cookie.get('name', '').lower()
                if any(session_word in cookie_name for session_word in ['session', 'auth', 'token']):
                    if cookie_name not in session_cookies:
                        session_cookies[cookie_name] = []
                    session_cookies[cookie_name].append({
                        'url': page['url'],
                        'value': cookie.get('value', ''),
                        'domain': cookie.get('domain', ''),
                        'path': cookie.get('path', '')
                    })

        # Check for session fixation
        for cookie_name, cookie_data in session_cookies.items():
            if len(cookie_data) > 1:
                # Check if same session token is used across different pages
                values = [data['value'] for data in cookie_data]
                if len(set(values)) == 1 and len(values) > 1:
                    self._add_finding(
                        category='authentication',
                        severity='medium',
                        title=f'Potential Session Fixation: {cookie_name}',
                        description=f'Session cookie "{cookie_name}" uses same token across multiple pages.',
                        evidence={
                            'cookie_name': cookie_name,
                            'token_reuse': True,
                            'pages_count': len(cookie_data),
                            'sample_urls': [data['url'] for data in cookie_data[:3]]
                        },
                        fix_snippet=self._get_session_fixation_fix_snippet(),
                        reproduce_command=f"curl -I '{cookie_data[0]['url']}'",
                        owasp_category="A07 - Identification and Authentication Failures"
                    )

    def _check_auth_bypass(self, pages: List[Dict]):
        """Check for authentication bypass vulnerabilities"""

        for page in pages:
            url = page['url']
            status_code = page.get('status_code', 0)
            html_content = page.get('html_snippet', '')

            # Check for admin pages accessible without authentication
            if any(admin_path in url.lower() for admin_path in ['/admin', '/administrator', '/dashboard']):
                if status_code == 200:
                    # Check if page contains admin content
                    admin_indicators = ['admin panel', 'dashboard', 'user management', 'system settings']
                    if any(indicator in html_content.lower() for indicator in admin_indicators):
                        self._add_finding(
                            category='authentication',
                            severity='critical',
                            title='Admin Panel Accessible Without Authentication',
                            description=f'Admin panel at "{url}" is accessible without proper authentication.',
                            evidence={
                                'url': url,
                                'status_code': status_code,
                                'admin_content_detected': True,
                                'authentication_required': False
                            },
                            fix_snippet=self._get_admin_auth_fix_snippet(),
                            reproduce_command=f"curl '{url}'",
                            owasp_category="A07 - Identification and Authentication Failures"
                        )

    def _is_weak_session_token(self, token: str) -> bool:
        """Check if session token is weak"""

        if not token:
            return True

        # Check for sequential numbers
        if token.isdigit() and len(token) < 10:
            return True

        # Check for short tokens
        if len(token) < 16:
            return True

        # Check for common weak patterns
        weak_patterns = [
            r'^\d+$',  # All digits
            r'^[a-z]+$',  # All lowercase letters
            r'^[A-Z]+$',  # All uppercase letters
            r'^admin$',  # Common words
            r'^test$',
            r'^user$'
        ]

        for pattern in weak_patterns:
            if re.match(pattern, token, re.IGNORECASE):
                return True

        return False

    def _get_https_fix_snippet(self) -> str:
        """Get HTTPS fix code snippet"""
        
        return """// Force HTTPS for authentication
// 1. Express.js middleware
app.use((req, res, next) => {
    if (req.header('x-forwarded-proto') !== 'https' && process.env.NODE_ENV === 'production') {
        res.redirect(`https://${req.header('host')}${req.url}`);
    } else {
        next();
    }
});

// 2. Nginx configuration
server {
    listen 80;
    server_name example.com;
    return 301 https://$server_name$request_uri;
}

// 3. Apache .htaccess
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]"""

    def _get_frame_options_fix_snippet(self) -> str:
        """Get X-Frame-Options fix code snippet"""
        
        return """// Prevent clickjacking on auth pages
// 1. Express.js middleware
app.use('/auth', (req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    next();
});

// 2. Nginx configuration
add_header X-Frame-Options "DENY" always;

// 3. Apache configuration
Header always set X-Frame-Options "DENY"

// 4. Content Security Policy (alternative)
add_header Content-Security-Policy "frame-ancestors 'none';" always;"""

    def _get_basic_auth_fix_snippet(self) -> str:
        """Get Basic Auth fix code snippet"""
        
        return """// Use secure authentication methods
// 1. JWT Authentication
const jwt = require('jsonwebtoken');

function generateToken(user) {
    return jwt.sign(
        { userId: user.id, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
    );
}

// 2. Session-based authentication
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true,  // HTTPS only
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000  // 24 hours
    }
}));

// 3. OAuth 2.0 / OpenID Connect
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
}, (accessToken, refreshToken, profile, done) => {
    // Handle authentication
}));"""

    def _get_csrf_fix_snippet(self) -> str:
        """Get CSRF protection fix code snippet"""
        
        return """// Implement CSRF protection
// 1. Express.js with csurf
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

app.use(csrfProtection);

// 2. Manual CSRF token generation
app.get('/login', (req, res) => {
    const csrfToken = req.csrfToken();
    res.render('login', { csrfToken });
});

// 3. Verify CSRF token in forms
app.post('/login', (req, res) => {
    const { email, password, _csrf } = req.body;
    
    if (!_csrf || _csrf !== req.csrfToken()) {
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    
    // Process login
});

// 4. Include CSRF token in forms
<form method="POST" action="/login">
    <input type="hidden" name="_csrf" value="<%= csrfToken %>">
    <input type="email" name="email" required>
    <input type="password" name="password" required>
    <button type="submit">Login</button>
</form>"""

    def _get_password_field_fix_snippet(self) -> str:
        """Get password field fix code snippet"""
        
        return """// Secure password field implementation
// 1. HTML form with proper attributes
<form method="POST" action="/login">
    <input type="email" name="email" required autocomplete="email">
    <input type="password" name="password" required 
           autocomplete="current-password" 
           minlength="8" 
           maxlength="128">
    <button type="submit">Login</button>
</form>

// 2. Password strength validation
function validatePassword(password) {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    
    return {
        isValid: password.length >= minLength && 
                hasUpperCase && hasLowerCase && 
                hasNumbers && hasSpecialChar,
        errors: [
            password.length < minLength ? 'Password too short' : null,
            !hasUpperCase ? 'Missing uppercase letter' : null,
            !hasLowerCase ? 'Missing lowercase letter' : null,
            !hasNumbers ? 'Missing number' : null,
            !hasSpecialChar ? 'Missing special character' : null
        ].filter(Boolean)
    };
}"""

    def _get_password_policy_fix_snippet(self) -> str:
        """Get password policy fix code snippet"""
        
        return """// Implement strong password policy
// 1. Server-side validation
const passwordPolicy = {
    minLength: 12,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    maxLength: 128,
    preventCommonPasswords: true
};

function validatePasswordPolicy(password) {
    const errors = [];
    
    if (password.length < passwordPolicy.minLength) {
        errors.push(`Password must be at least ${passwordPolicy.minLength} characters long`);
    }
    
    if (passwordPolicy.requireUppercase && !/[A-Z]/.test(password)) {
        errors.push('Password must contain at least one uppercase letter');
    }
    
    if (passwordPolicy.requireLowercase && !/[a-z]/.test(password)) {
        errors.push('Password must contain at least one lowercase letter');
    }
    
    if (passwordPolicy.requireNumbers && !/\d/.test(password)) {
        errors.push('Password must contain at least one number');
    }
    
    if (passwordPolicy.requireSpecialChars && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
        errors.push('Password must contain at least one special character');
    }
    
    return {
        isValid: errors.length === 0,
        errors: errors
    };
}

// 2. Client-side password policy display
<div class="password-policy">
    <h4>Password Requirements:</h4>
    <ul>
        <li>At least 12 characters long</li>
        <li>Contains uppercase and lowercase letters</li>
        <li>Contains numbers and special characters</li>
        <li>Not a common password</li>
    </ul>
</div>"""

    def _get_secure_cookie_fix_snippet(self) -> str:
        """Get secure cookie fix code snippet"""
        
        return """// Set secure session cookies
// 1. Express.js session configuration
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true,        // HTTPS only
        httpOnly: true,      // No JavaScript access
        sameSite: 'strict',  // CSRF protection
        maxAge: 24 * 60 * 60 * 1000  // 24 hours
    }
}));

// 2. Manual cookie setting
res.cookie('sessionId', sessionToken, {
    secure: true,
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000
});

// 3. Nginx secure cookie configuration
proxy_cookie_path / "/; Secure; HttpOnly; SameSite=Strict";"""

    def _get_httponly_cookie_fix_snippet(self) -> str:
        """Get HttpOnly cookie fix code snippet"""
        
        return """// Enable HttpOnly flag for session cookies
// 1. Express.js
app.use(session({
    cookie: {
        httpOnly: true,  // Prevents XSS access to cookies
        secure: true,
        sameSite: 'strict'
    }
}));

// 2. Manual cookie setting
res.cookie('authToken', token, {
    httpOnly: true,  // Cookie not accessible via JavaScript
    secure: true,
    sameSite: 'strict'
});

// 3. Nginx configuration
proxy_cookie_path / "/; HttpOnly; Secure; SameSite=Strict";"""

    def _get_strong_token_fix_snippet(self) -> str:
        """Get strong token generation fix code snippet"""
        
        return """// Generate strong session tokens
// 1. Cryptographically secure random tokens
const crypto = require('crypto');

function generateSecureToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
}

// 2. JWT tokens with proper configuration
const jwt = require('jsonwebtoken');

function generateJWT(payload) {
    return jwt.sign(payload, process.env.JWT_SECRET, {
        expiresIn: '1h',
        issuer: 'your-app',
        audience: 'your-users'
    });
}

// 3. UUID-based session IDs
const { v4: uuidv4 } = require('uuid');

function generateSessionId() {
    return uuidv4();
}

// 4. Session token with additional entropy
function generateSessionToken() {
    const timestamp = Date.now().toString();
    const random = crypto.randomBytes(16).toString('hex');
    return crypto.createHash('sha256')
        .update(timestamp + random)
        .digest('hex');
}"""

    def _get_session_fixation_fix_snippet(self) -> str:
        """Get session fixation fix code snippet"""
        
        return """// Prevent session fixation attacks
// 1. Regenerate session ID after login
app.post('/login', (req, res) => {
    // Authenticate user
    if (authenticateUser(req.body.email, req.body.password)) {
        // Regenerate session ID
        req.session.regenerate((err) => {
            if (err) {
                return res.status(500).json({ error: 'Session error' });
            }
            
            // Set user data in new session
            req.session.userId = user.id;
            req.session.isAuthenticated = true;
            
            res.json({ success: true, redirect: '/dashboard' });
        });
    }
});

// 2. Use different session tokens for different contexts
function generateContextualToken(userId, context) {
    const baseToken = generateSecureToken();
    const contextualData = `${userId}:${context}:${Date.now()}`;
    
    return crypto.createHash('sha256')
        .update(baseToken + contextualData)
        .digest('hex');
}

// 3. Implement session rotation
setInterval(() => {
    // Rotate session tokens periodically
    activeSessions.forEach(session => {
        if (session.lastActivity < Date.now() - 3600000) { // 1 hour
            session.token = generateSecureToken();
            session.lastActivity = Date.now();
        }
    });
}, 300000); // Every 5 minutes"""

    def _get_admin_auth_fix_snippet(self) -> str:
        """Get admin authentication fix code snippet"""
        
        return """// Secure admin panel access
// 1. Middleware for admin authentication
function requireAdmin(req, res, next) {
    if (!req.session.isAuthenticated) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    if (!req.session.user.roles.includes('admin')) {
        return res.status(403).json({ error: 'Admin access required' });
    }
    
    next();
}

// 2. Admin route protection
app.use('/admin', requireAdmin);
app.get('/admin/dashboard', requireAdmin, adminDashboardHandler);

// 3. Role-based access control
function requireRole(role) {
    return (req, res, next) => {
        if (!req.session.user || !req.session.user.roles.includes(role)) {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }
        next();
    };
}

// 4. Multi-factor authentication for admin
function requireMFA(req, res, next) {
    if (req.session.user.roles.includes('admin') && !req.session.mfaVerified) {
        return res.redirect('/mfa-verify');
    }
    next();
}

// Usage
app.use('/admin', requireAuth, requireMFA, requireRole('admin'));"""


def main():
    """Test the authentication scanner"""
    
    scanner = AuthScanner("test_run")
    
    test_pages = Path("test_pages.json")
    if test_pages.exists():
        findings = scanner.scan_pages(test_pages)
        scanner.save_findings(Path("."))
        print(f"✅ Found {len(findings)} authentication vulnerabilities")
    else:
        print("❌ No test_pages.json found. Run crawler first.")


if __name__ == "__main__":
    main()
