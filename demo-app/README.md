# Vulnerable Demo App

**⚠️ WARNING: This application is INTENTIONALLY VULNERABLE for testing purposes only!**

## Quick Start

```bash
cd demo-app
npm install
npm start
```

App runs on http://localhost:3001

## Intentional Vulnerabilities

This app contains the following security issues for AegisWeb to detect:

### 1. Clickjacking (Missing X-Frame-Options)
- **Test**: All pages can be embedded in iframes
- **Evidence**: No `X-Frame-Options` or `frame-ancestors` CSP directive

### 2. Permissive CORS
- **Test**: `GET /api/sensitive`
- **Evidence**: `Access-Control-Allow-Origin: *` with `credentials: true`

### 3. Reflected XSS
- **Test**: `GET /search?q=<script>alert(1)</script>`
- **Evidence**: User input reflected unescaped in HTML

### 4. Open Redirect
- **Test**: `GET /redirect?url=https://evil.example.com`
- **Evidence**: Redirects to any external URL without validation

### 5. Missing Security Headers
- **Evidence**: No CSP, HSTS, X-Content-Type-Options, etc.

### 6. Insecure Cookies
- **Test**: `GET /login`
- **Evidence**: Cookies without `httpOnly`, `secure`, `sameSite`

### 7. Information Disclosure
- **Test**: `GET /debug`
- **Evidence**: Exposes server version, environment, headers

### 8. Path Traversal
- **Test**: `GET /file?name=../package.json`
- **Evidence**: File access without validation

## Test Commands

```bash
# Test reflected XSS
curl "http://localhost:3001/search?q=INJTEST_12345"

# Test open redirect
curl -I "http://localhost:3001/redirect?url=https://google.com"

# Test CORS
curl -H "Origin: https://evil.com" "http://localhost:3001/api/sensitive"

# Test info disclosure
curl "http://localhost:3001/debug"
```

## Expected Scanner Findings

AegisWeb should detect:
- ✅ Missing `X-Frame-Options` header
- ✅ Permissive CORS configuration
- ✅ Reflected XSS vulnerability in `/search`
- ✅ Open redirect in `/redirect`
- ✅ Missing security headers (CSP, HSTS, etc.)
- ✅ Insecure cookie configuration
- ✅ Information disclosure endpoints