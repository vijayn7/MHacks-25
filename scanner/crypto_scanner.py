import json
import uuid
import re
import hashlib
import ssl
import socket
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse
from base_scanner import BaseScanner


class CryptoScanner(BaseScanner):
    """Analyzes cryptographic failures and weak encryption (OWASP A02)"""

    # Weak cipher suites
    WEAK_CIPHERS = [
        'RC4', 'DES', '3DES', 'MD5', 'SHA1', 'NULL', 'EXPORT',
        'ANON', 'ADH', 'AECDH', 'ECDH', 'CAMELLIA', 'SEED'
    ]

    # Weak SSL/TLS versions
    WEAK_TLS_VERSIONS = [
        'SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'
    ]

    # Strong cipher suites
    STRONG_CIPHERS = [
        'AES', 'ChaCha20', 'AES-GCM', 'AES-CCM', 'ChaCha20-Poly1305'
    ]

    # Strong TLS versions
    STRONG_TLS_VERSIONS = [
        'TLSv1.2', 'TLSv1.3'
    ]

    # Common weak hash patterns
    WEAK_HASH_PATTERNS = [
        r'md5\s*[:=]\s*["\']?[a-f0-9]{32}["\']?',
        r'sha1\s*[:=]\s*["\']?[a-f0-9]{40}["\']?',
        r'password\s*[:=]\s*["\']?[a-f0-9]{32}["\']?',  # MD5 password hash
        r'hash\s*[:=]\s*["\']?[a-f0-9]{32}["\']?'  # MD5 hash
    ]

    # Hardcoded secrets patterns
    SECRET_PATTERNS = [
        r'api[_-]?key\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}["\']?',
        r'secret\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}["\']?',
        r'password\s*[:=]\s*["\']?[a-zA-Z0-9]{8,}["\']?',
        r'token\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}["\']?',
        r'private[_-]?key\s*[:=]\s*["\']?-----BEGIN',
        r'jwt[_-]?secret\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}["\']?'
    ]

    def __init__(self, run_id: str):
        super().__init__(run_id)

    def scan_pages(self, pages_file: Path) -> List[Dict]:
        """Scan pages for cryptographic vulnerabilities"""

        print(f"🔍 Scanning for cryptographic vulnerabilities for run {self.run_id}")

        data = self._load_pages_data(pages_file)
        pages = data.get('pages', [])

        for page in pages:
            self._analyze_page_cryptography(page)

        # Check SSL/TLS configuration
        self._check_ssl_configuration(pages)

        # Check for hardcoded secrets
        self._check_hardcoded_secrets(pages)

        return self.findings

    def _analyze_page_cryptography(self, page: Dict):
        """Analyze a single page for cryptographic issues"""

        url = page['url']
        status_code = page.get('status_code', 0)
        headers = {k.lower(): v for k, v in page.get('headers', {}).items()}
        html_content = page.get('html_snippet', '')

        print(f"  🔐 Analyzing cryptography for {url}")

        # Check for weak hash algorithms
        self._check_weak_hashes(url, html_content)

        # Check for missing HTTPS
        self._check_https_usage(url, status_code)

        # Check for weak encryption in forms
        self._check_form_encryption(url, page)

        # Check for cryptographic headers
        self._check_crypto_headers(url, headers)

    def _check_weak_hashes(self, url: str, html_content: str):
        """Check for weak hash algorithms in content"""

        for pattern in self.WEAK_HASH_PATTERNS:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            if matches:
                self._add_finding(
                    category='weak_crypto',
                    severity='high',
                    title='Weak Hash Algorithm Detected',
                    description=f'Page contains weak hash algorithm (MD5/SHA1) which is cryptographically broken.',
                    evidence={
                        'url': url,
                        'weak_pattern': pattern,
                        'matches': matches[:3],  # Limit to first 3 matches
                        'hash_type': 'MD5' if 'md5' in pattern.lower() else 'SHA1'
                    },
                    fix_snippet=self._get_hash_fix_snippet(),
                    reproduce_command=f"curl '{url}' | grep -i md5",
                    owasp_category="A02 - Cryptographic Failures"
                )

    def _check_https_usage(self, url: str, status_code: int):
        """Check for HTTPS usage and configuration"""

        if not url.startswith('https://'):
            self._add_finding(
                category='weak_crypto',
                severity='high',
                title='HTTP Instead of HTTPS',
                description=f'Page is served over HTTP instead of HTTPS, data transmission is not encrypted.',
                evidence={
                    'url': url,
                    'protocol': 'http',
                    'encrypted': False,
                    'status_code': status_code
                },
                fix_snippet=self._get_https_fix_snippet(),
                reproduce_command=f"curl -I '{url}'",
                owasp_category="A02 - Cryptographic Failures"
            )
        else:
            # Check HTTPS configuration
            self._check_https_configuration(url)

    def _check_https_configuration(self, url: str):
        """Check HTTPS configuration for security issues"""

        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or 443

            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Connect and get certificate info
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    # Check TLS version
                    if version in self.WEAK_TLS_VERSIONS:
                        self._add_finding(
                            category='weak_crypto',
                            severity='high',
                            title=f'Weak TLS Version: {version}',
                            description=f'Server uses weak TLS version {version} which has known vulnerabilities.',
                            evidence={
                                'url': url,
                                'tls_version': version,
                                'weak_version': True
                            },
                            fix_snippet=self._get_tls_fix_snippet(),
                            reproduce_command=f"openssl s_client -connect {hostname}:{port} -tls1_2",
                            owasp_category="A02 - Cryptographic Failures"
                        )

                    # Check cipher suite
                    if cipher and cipher[0]:
                        cipher_name = cipher[0]
                        if any(weak_cipher in cipher_name for weak_cipher in self.WEAK_CIPHERS):
                            self._add_finding(
                                category='weak_crypto',
                                severity='medium',
                                title=f'Weak Cipher Suite: {cipher_name}',
                                description=f'Server uses weak cipher suite {cipher_name} which may be vulnerable.',
                                evidence={
                                    'url': url,
                                    'cipher_suite': cipher_name,
                                    'weak_cipher': True
                                },
                                fix_snippet=self._get_cipher_fix_snippet(),
                                reproduce_command=f"openssl s_client -connect {hostname}:{port}",
                                owasp_category="A02 - Cryptographic Failures"
                            )

                    # Check certificate validity
                    if cert:
                        self._check_certificate_security(url, cert)

        except Exception as e:
            # SSL connection failed - this might indicate issues
            self._add_finding(
                category='weak_crypto',
                severity='medium',
                title='SSL Connection Failed',
                description=f'Unable to establish SSL connection to {url}. This may indicate SSL configuration issues.',
                evidence={
                    'url': url,
                    'error': str(e),
                    'connection_failed': True
                },
                fix_snippet=self._get_ssl_config_fix_snippet(),
                reproduce_command=f"openssl s_client -connect {hostname}:443",
                owasp_category="A02 - Cryptographic Failures"
            )

    def _check_certificate_security(self, url: str, cert: Dict):
        """Check SSL certificate for security issues"""

        # Check certificate expiration
        if 'notAfter' in cert:
            from datetime import datetime
            try:
                expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (expire_date - datetime.now()).days
                
                if days_until_expiry < 30:
                    severity = 'high' if days_until_expiry < 7 else 'medium'
                    self._add_finding(
                        category='weak_crypto',
                        severity=severity,
                        title=f'SSL Certificate Expiring Soon',
                        description=f'SSL certificate expires in {days_until_expiry} days.',
                        evidence={
                            'url': url,
                            'expire_date': cert['notAfter'],
                            'days_until_expiry': days_until_expiry
                        },
                        fix_snippet=self._get_cert_renewal_fix_snippet(),
                        reproduce_command=f"openssl s_client -connect {urlparse(url).hostname}:443 -servername {urlparse(url).hostname}",
                        owasp_category="A02 - Cryptographic Failures"
                    )
            except:
                pass

        # Check certificate issuer
        if 'issuer' in cert:
            issuer = cert['issuer']
            if isinstance(issuer, list):
                issuer_str = ', '.join([f"{item[0][0]}={item[0][1]}" for item in issuer])
            else:
                issuer_str = str(issuer)
            
            # Check for self-signed certificates
            if 'self-signed' in issuer_str.lower() or 'self signed' in issuer_str.lower():
                self._add_finding(
                    category='weak_crypto',
                    severity='medium',
                    title='Self-Signed SSL Certificate',
                    description=f'Server uses self-signed SSL certificate which cannot be verified.',
                    evidence={
                        'url': url,
                        'issuer': issuer_str,
                        'self_signed': True
                    },
                    fix_snippet=self._get_cert_authority_fix_snippet(),
                    reproduce_command=f"openssl s_client -connect {urlparse(url).hostname}:443",
                    owasp_category="A02 - Cryptographic Failures"
                )

    def _check_form_encryption(self, url: str, page: Dict):
        """Check forms for encryption-related issues"""

        forms = self._extract_forms_from_page(page)
        
        for form in forms:
            form_action = form.get('action', '')
            form_method = form.get('method', 'GET')
            inputs = form.get('inputs', [])

            # Check if form submits sensitive data
            sensitive_inputs = ['password', 'credit', 'card', 'ssn', 'social', 'bank']
            has_sensitive_data = any(
                any(sensitive in input_field.get('name', '').lower() for sensitive in sensitive_inputs)
                for input_field in inputs
            )

            if has_sensitive_data:
                # Check if form action uses HTTPS
                if form_action and not form_action.startswith('https://'):
                    self._add_finding(
                        category='weak_crypto',
                        severity='high',
                        title='Sensitive Form Data Over HTTP',
                        description=f'Form containing sensitive data submits to non-HTTPS endpoint.',
                        evidence={
                            'url': url,
                            'form_action': form_action,
                            'form_method': form_method,
                            'sensitive_fields': [inp.get('name', '') for inp in inputs if any(sensitive in inp.get('name', '').lower() for sensitive in sensitive_inputs)]
                        },
                        fix_snippet=self._get_form_encryption_fix_snippet(),
                        reproduce_command=f"curl '{url}' | grep -A 10 -B 5 form",
                        owasp_category="A02 - Cryptographic Failures"
                    )

    def _check_crypto_headers(self, url: str, headers: Dict):
        """Check for cryptographic security headers"""

        # Check for HSTS header
        hsts_header = headers.get('strict-transport-security', '')
        if url.startswith('https://') and not hsts_header:
            self._add_finding(
                category='weak_crypto',
                severity='medium',
                title='Missing HSTS Header',
                description=f'HTTPS site missing Strict-Transport-Security header.',
                evidence={
                    'url': url,
                    'protocol': 'https',
                    'missing_header': 'strict-transport-security'
                },
                fix_snippet=self._get_hsts_fix_snippet(),
                reproduce_command=f"curl -I '{url}'",
                owasp_category="A02 - Cryptographic Failures"
            )

        # Check HSTS configuration
        if hsts_header:
            if 'includeSubDomains' not in hsts_header:
                self._add_finding(
                    category='weak_crypto',
                    severity='low',
                    title='HSTS Missing includeSubDomains',
                    description=f'HSTS header missing includeSubDomains directive.',
                    evidence={
                        'url': url,
                        'hsts_header': hsts_header,
                        'missing_directive': 'includeSubDomains'
                    },
                    fix_snippet=self._get_hsts_fix_snippet(),
                    reproduce_command=f"curl -I '{url}'",
                    owasp_category="A02 - Cryptographic Failures"
                )

    def _check_ssl_configuration(self, pages: List[Dict]):
        """Check SSL configuration across all pages"""

        https_urls = [page['url'] for page in pages if page['url'].startswith('https://')]
        
        if https_urls:
            # Check for mixed content
            for page in pages:
                if page['url'].startswith('http://'):
                    html_content = page.get('html_snippet', '')
                    if 'https://' in html_content:
                        self._add_finding(
                            category='weak_crypto',
                            severity='medium',
                            title='Mixed Content on HTTP Page',
                            description=f'HTTP page contains HTTPS resources, which may be blocked by browsers.',
                            evidence={
                                'url': page['url'],
                                'protocol': 'http',
                                'mixed_content': True
                            },
                            fix_snippet=self._get_mixed_content_fix_snippet(),
                            reproduce_command=f"curl '{page['url']}' | grep -i https",
                            owasp_category="A02 - Cryptographic Failures"
                        )

    def _check_hardcoded_secrets(self, pages: List[Dict]):
        """Check for hardcoded secrets in pages"""

        for page in pages:
            url = page['url']
            html_content = page.get('html_snippet', '')
            scripts = self._extract_scripts_from_page(page)

            # Check HTML content for secrets
            for pattern in self.SECRET_PATTERNS:
                matches = re.findall(pattern, html_content, re.IGNORECASE)
                if matches:
                    self._add_finding(
                        category='weak_crypto',
                        severity='critical',
                        title='Hardcoded Secret Detected',
                        description=f'Page contains hardcoded secret which should be stored securely.',
                        evidence={
                            'url': url,
                            'secret_pattern': pattern,
                            'matches': matches[:2],  # Limit to first 2 matches
                            'secret_type': self._get_secret_type(pattern)
                        },
                        fix_snippet=self._get_secret_management_fix_snippet(),
                        reproduce_command=f"curl '{url}' | grep -i secret",
                        owasp_category="A02 - Cryptographic Failures"
                    )

            # Check JavaScript for secrets
            for script in scripts:
                if script.get('type') == 'inline':
                    script_content = script.get('content', '')
                    for pattern in self.SECRET_PATTERNS:
                        matches = re.findall(pattern, script_content, re.IGNORECASE)
                        if matches:
                            self._add_finding(
                                category='weak_crypto',
                                severity='critical',
                                title='Hardcoded Secret in JavaScript',
                                description=f'JavaScript contains hardcoded secret which is visible to clients.',
                                evidence={
                                    'url': url,
                                    'secret_pattern': pattern,
                                    'matches': matches[:2],
                                    'location': 'javascript',
                                    'secret_type': self._get_secret_type(pattern)
                                },
                                fix_snippet=self._get_js_secret_fix_snippet(),
                                reproduce_command=f"curl '{url}' | grep -A 5 -B 5 secret",
                                owasp_category="A02 - Cryptographic Failures"
                            )

    def _get_secret_type(self, pattern: str) -> str:
        """Determine secret type from pattern"""
        if 'api' in pattern.lower():
            return 'API Key'
        elif 'secret' in pattern.lower():
            return 'Secret'
        elif 'password' in pattern.lower():
            return 'Password'
        elif 'token' in pattern.lower():
            return 'Token'
        elif 'private' in pattern.lower():
            return 'Private Key'
        elif 'jwt' in pattern.lower():
            return 'JWT Secret'
        else:
            return 'Unknown'

    def _get_hash_fix_snippet(self) -> str:
        """Get hash algorithm fix code snippet"""
        
        return """// Use strong hash algorithms
// 1. Node.js with crypto
const crypto = require('crypto');

// Strong password hashing with bcrypt
const bcrypt = require('bcrypt');

async function hashPassword(password) {
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
}

async function verifyPassword(password, hash) {
    return await bcrypt.compare(password, hash);
}

// 2. File integrity with SHA-256
function calculateFileHash(filePath) {
    const fs = require('fs');
    const hash = crypto.createHash('sha256');
    const data = fs.readFileSync(filePath);
    hash.update(data);
    return hash.digest('hex');
}

// 3. HMAC for message authentication
function createHMAC(message, secret) {
    return crypto.createHmac('sha256', secret).update(message).digest('hex');
}

// 4. Never use weak algorithms:
// BAD: crypto.createHash('md5')
// BAD: crypto.createHash('sha1')
// GOOD: crypto.createHash('sha256') or bcrypt for passwords"""

    def _get_https_fix_snippet(self) -> str:
        """Get HTTPS fix code snippet"""
        
        return """// Force HTTPS for all connections
// 1. Express.js HTTPS redirect
app.use((req, res, next) => {
    if (req.header('x-forwarded-proto') !== 'https' && process.env.NODE_ENV === 'production') {
        res.redirect(`https://${req.header('host')}${req.url}`);
    } else {
        next();
    }
});

// 2. Nginx HTTPS configuration
server {
    listen 80;
    server_name example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name example.com;
    
    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    
    # Strong SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
}

// 3. Apache HTTPS configuration
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]"""

    def _get_tls_fix_snippet(self) -> str:
        """Get TLS version fix code snippet"""
        
        return """// Configure strong TLS versions
// 1. Nginx SSL configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256;
ssl_prefer_server_ciphers off;

// 2. Apache SSL configuration
SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256
SSLHonorCipherOrder on

// 3. Node.js HTTPS server
const https = require('https');
const fs = require('fs');

const options = {
    key: fs.readFileSync('private-key.pem'),
    cert: fs.readFileSync('certificate.pem'),
    secureProtocol: 'TLSv1_2_method',  // Force TLS 1.2+
    ciphers: 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256'
};

https.createServer(options, app).listen(443);

// 4. Test TLS configuration
// openssl s_client -connect example.com:443 -tls1_2"""

    def _get_cipher_fix_snippet(self) -> str:
        """Get cipher suite fix code snippet"""
        
        return """// Configure strong cipher suites
// 1. Nginx cipher configuration
ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256;
ssl_prefer_server_ciphers off;

// 2. Apache cipher configuration
SSLCipherSuite ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256
SSLHonorCipherOrder on

// 3. Disable weak ciphers
// Remove these weak ciphers:
// - RC4
// - DES
// - 3DES
// - NULL
// - EXPORT
// - ANON
// - ADH

// 4. Test cipher strength
// nmap --script ssl-enum-ciphers -p 443 example.com"""

    def _get_cert_renewal_fix_snippet(self) -> str:
        """Get certificate renewal fix code snippet"""
        
        return """// Set up automatic certificate renewal
// 1. Let's Encrypt with Certbot
// Install certbot
sudo apt-get install certbot python3-certbot-nginx

// Get certificate
sudo certbot --nginx -d example.com

// Auto-renewal (add to crontab)
0 12 * * * /usr/bin/certbot renew --quiet

// 2. Nginx auto-reload on certificate renewal
server {
    listen 443 ssl http2;
    server_name example.com;
    
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    
    # Auto-reload when certificate changes
    ssl_certificate_by_lua_block {
        auto_ssl:ssl_certificate()
    }
}

// 3. Monitor certificate expiration
const https = require('https');
const tls = require('tls');

function checkCertificateExpiry(hostname, port = 443) {
    return new Promise((resolve, reject) => {
        const socket = tls.connect(port, hostname, (err) => {
            if (err) return reject(err);
            
            const cert = socket.getPeerCertificate();
            const expireDate = new Date(cert.valid_to);
            const daysUntilExpiry = Math.ceil((expireDate - new Date()) / (1000 * 60 * 60 * 24));
            
            resolve({ expireDate, daysUntilExpiry });
            socket.destroy();
        });
    });
}"""

    def _get_cert_authority_fix_snippet(self) -> str:
        """Get certificate authority fix code snippet"""
        
        return """// Use trusted certificate authorities
// 1. Let's Encrypt (free, trusted CA)
// Install certbot
sudo apt-get install certbot

// Get certificate
sudo certbot certonly --webroot -w /var/www/html -d example.com

// 2. Commercial CA certificates
// Purchase from trusted CAs like:
// - DigiCert
// - GlobalSign
// - Sectigo
// - Entrust

// 3. Internal CA setup
// Create internal CA for development
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -days 365 -key ca-key.pem -sha256 -out ca.pem

// Generate server certificate
openssl genrsa -out server-key.pem 4096
openssl req -subj "/CN=example.com" -sha256 -new -key server-key.pem -out server.csr
openssl x509 -req -days 365 -sha256 -in server.csr -CA ca.pem -CAkey ca-key.pem -out server-cert.pem

// 4. Certificate validation
const https = require('https');
const tls = require('tls');

const options = {
    hostname: 'example.com',
    port: 443,
    rejectUnauthorized: true  // Reject self-signed certificates
};

const req = https.request(options, (res) => {
    console.log('Certificate is valid');
});

req.on('error', (err) => {
    console.error('Certificate validation failed:', err.message);
});"""

    def _get_form_encryption_fix_snippet(self) -> str:
        """Get form encryption fix code snippet"""
        
        return """// Ensure forms submit sensitive data over HTTPS
// 1. Force HTTPS form actions
app.use((req, res, next) => {
    if (req.secure || req.header('x-forwarded-proto') === 'https') {
        res.locals.protocol = 'https';
    } else {
        res.locals.protocol = 'http';
    }
    next();
});

// 2. Template with secure form action
<form method="POST" action="<%= protocol %>://<%= req.get('host') %>/submit">
    <input type="password" name="password" required>
    <button type="submit">Submit</button>
</form>

// 3. Client-side HTTPS enforcement
if (location.protocol !== 'https:' && location.hostname !== 'localhost') {
    location.replace('https:' + window.location.href.substring(window.location.protocol.length));
}

// 4. Content Security Policy for HTTPS
app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy', "upgrade-insecure-requests");
    next();
});"""

    def _get_hsts_fix_snippet(self) -> str:
        """Get HSTS fix code snippet"""
        
        return """// Implement HTTP Strict Transport Security
// 1. Nginx HSTS configuration
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

// 2. Apache HSTS configuration
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

// 3. Express.js HSTS middleware
const helmet = require('helmet');

app.use(helmet.hsts({
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
}));

// 4. Manual HSTS header
app.use((req, res, next) => {
    if (req.secure) {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    }
    next();
});

// 5. Test HSTS
// curl -I https://example.com | grep -i strict-transport"""

    def _get_mixed_content_fix_snippet(self) -> str:
        """Get mixed content fix code snippet"""
        
        return """// Fix mixed content issues
// 1. Upgrade all HTTP resources to HTTPS
// Replace all http:// URLs with https:// in your code

// 2. Use protocol-relative URLs
// <img src="//example.com/image.jpg" alt="Image">
// This will use the same protocol as the page

// 3. Content Security Policy to block mixed content
app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy', "upgrade-insecure-requests");
    next();
});

// 4. Meta tag for mixed content blocking
<meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests">

// 5. JavaScript to upgrade HTTP URLs
function upgradeToHTTPS() {
    const links = document.querySelectorAll('a[href^="http://"]');
    links.forEach(link => {
        link.href = link.href.replace('http://', 'https://');
    });
    
    const images = document.querySelectorAll('img[src^="http://"]');
    images.forEach(img => {
        img.src = img.src.replace('http://', 'https://');
    });
}

// 6. Server-side URL rewriting
app.use((req, res, next) => {
    if (req.secure) {
        res.locals.baseUrl = `https://${req.get('host')}`;
    } else {
        res.locals.baseUrl = `http://${req.get('host')}`;
    }
    next();
});"""

    def _get_ssl_config_fix_snippet(self) -> str:
        """Get SSL configuration fix code snippet"""
        
        return """// Fix SSL configuration issues
// 1. Check SSL configuration
// Test with: openssl s_client -connect example.com:443

// 2. Nginx SSL configuration
server {
    listen 443 ssl http2;
    server_name example.com;
    
    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    
    # Strong SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
}

// 3. Apache SSL configuration
<VirtualHost *:443>
    ServerName example.com
    DocumentRoot /var/www/html
    
    SSLEngine on
    SSLCertificateFile /path/to/certificate.crt
    SSLCertificateKeyFile /path/to/private.key
    
    SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256
    SSLHonorCipherOrder on
</VirtualHost>

// 4. Test SSL configuration
// nmap --script ssl-enum-ciphers -p 443 example.com"""

    def _get_secret_management_fix_snippet(self) -> str:
        """Get secret management fix code snippet"""
        
        return """// Secure secret management
// 1. Use environment variables
// .env file (never commit to version control)
API_KEY=your-secret-api-key
JWT_SECRET=your-jwt-secret
DB_PASSWORD=your-database-password

// Load environment variables
require('dotenv').config();

const apiKey = process.env.API_KEY;
const jwtSecret = process.env.JWT_SECRET;

// 2. Use secret management services
// AWS Secrets Manager
const AWS = require('aws-sdk');
const secretsManager = new AWS.SecretsManager();

async function getSecret(secretName) {
    const result = await secretsManager.getSecretValue({ SecretId: secretName }).promise();
    return JSON.parse(result.SecretString);
}

// 3. Hashicorp Vault
const vault = require('node-vault');

const client = vault({
    apiVersion: 'v1',
    endpoint: 'https://vault.example.com',
    token: process.env.VAULT_TOKEN
});

// 4. Azure Key Vault
const { SecretClient } = require('@azure/keyvault-secrets');
const { DefaultAzureCredential } = require('@azure/identity');

const credential = new DefaultAzureCredential();
const client = new SecretClient('https://your-vault.vault.azure.net/', credential);

// 5. Never hardcode secrets in code
// BAD: const apiKey = 'sk-1234567890abcdef';
// GOOD: const apiKey = process.env.API_KEY;"""

    def _get_js_secret_fix_snippet(self) -> str:
        """Get JavaScript secret fix code snippet"""
        
        return """// Remove secrets from client-side JavaScript
// 1. Move secrets to server-side
// BAD (client-side):
// const apiKey = 'sk-1234567890abcdef';
// fetch(`https://api.example.com/data?key=${apiKey}`);

// GOOD (server-side):
app.get('/api/data', async (req, res) => {
    const apiKey = process.env.API_KEY;  // Server-side only
    const response = await fetch(`https://api.example.com/data?key=${apiKey}`);
    const data = await response.json();
    res.json(data);
});

// 2. Use proxy endpoints
// Client calls your server
fetch('/api/proxy/data')
    .then(response => response.json())
    .then(data => console.log(data));

// Server makes authenticated request
app.get('/api/proxy/data', async (req, res) => {
    const apiKey = process.env.API_KEY;
    const response = await fetch(`https://external-api.com/data`, {
        headers: { 'Authorization': `Bearer ${apiKey}` }
    });
    const data = await response.json();
    res.json(data);
});

// 3. Use temporary tokens
app.post('/api/temp-token', authenticateUser, (req, res) => {
    const tempToken = jwt.sign(
        { userId: req.user.id, exp: Math.floor(Date.now() / 1000) + 300 }, // 5 minutes
        process.env.JWT_SECRET
    );
    res.json({ tempToken });
});

// 4. OAuth flow for third-party APIs
app.get('/auth/oauth', (req, res) => {
    const authUrl = `https://api.example.com/oauth/authorize?client_id=${process.env.CLIENT_ID}&redirect_uri=${process.env.REDIRECT_URI}`;
    res.redirect(authUrl);
});"""


def main():
    """Test the cryptographic scanner"""
    
    scanner = CryptoScanner("test_run")
    
    test_pages = Path("test_pages.json")
    if test_pages.exists():
        findings = scanner.scan_pages(test_pages)
        scanner.save_findings(Path("."))
        print(f"✅ Found {len(findings)} cryptographic vulnerabilities")
    else:
        print("❌ No test_pages.json found. Run crawler first.")


if __name__ == "__main__":
    main()
