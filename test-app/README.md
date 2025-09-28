# Dynamic Scanner Test Application

This is a comprehensive test application specifically designed to test the Dynamic Scanner functionality. It contains intentional vulnerabilities across all major attack categories that the Dynamic Scanner should detect.

## 🚀 Quick Start

1. **Install dependencies:**
   ```bash
   cd test-app
   npm install
   ```

2. **Start the application:**
   ```bash
   npm start
   ```

3. **Access the app:**
   Open your browser to `http://localhost:3002`

## 🎯 Vulnerabilities Included

### Critical Severity
- **SQL Injection** - Multiple endpoints with direct SQL injection
- **XSS (Cross-Site Scripting)** - Reflected XSS in search functionality
- **Command Injection** - OS command execution via ping endpoint
- **Path Traversal** - File system access without validation

### High Severity
- **IDOR (Insecure Direct Object Reference)** - Access to other users' data
- **Business Logic Flaws** - Price manipulation in purchase endpoint
- **Weak Authentication** - No password strength validation
- **Information Disclosure** - Debug endpoint exposing sensitive data

### Medium Severity
- **Session Management Issues** - Insecure session handling
- **Cryptographic Issues** - Weak encryption algorithms and key management
- **Race Conditions** - Concurrent access issues in withdrawal endpoint

### Low Severity
- **Open Redirect** - Unvalidated redirects
- **Missing Security Headers** - No CORS, CSP, or frame protection
- **Admin Panel Access** - No authentication required

## 🔍 Test Endpoints

| Endpoint | Method | Vulnerability | Description |
|----------|--------|---------------|-------------|
| `/api/users?id=` | GET | SQL Injection | Direct SQL injection in user lookup |
| `/api/login` | POST | SQL Injection + Weak Auth | Login with SQL injection and weak JWT |
| `/api/user/:id` | GET | IDOR | Access any user's data by ID |
| `/search?q=` | GET | XSS | Reflected XSS in search results |
| `/api/ping?host=` | GET | Command Injection | OS command execution |
| `/api/file?name=` | GET | Path Traversal | File system access |
| `/api/purchase` | POST | Business Logic | Price manipulation |
| `/api/debug` | GET | Information Disclosure | System information exposure |
| `/admin` | GET | No Auth | Admin panel without authentication |
| `/redirect?url=` | GET | Open Redirect | Unvalidated redirects |
| `/api/register` | POST | Weak Auth | Registration without validation |
| `/api/session` | GET | Session Issues | Insecure session management |
| `/api/encrypt` | GET | Crypto Issues | Weak encryption implementation |
| `/api/withdraw` | POST | Race Condition | Concurrent access issues |

## 🧪 Testing with Dynamic Scanner

1. **Start the test app:**
   ```bash
   npm start
   ```

2. **Run the Dynamic Scanner:**
   - Use the Swarm Scanner frontend
   - Enter `http://localhost:3002` as the target URL
   - Or use the dynamic scanner directly with the codebase path

3. **Expected Results:**
   The Dynamic Scanner should detect vulnerabilities across all categories:
   - Injection attacks (SQL, Command, XSS)
   - Authentication and Authorization flaws
   - Business logic vulnerabilities
   - Data exposure issues
   - Cryptographic weaknesses
   - Insecure design patterns

## ⚠️ Security Warning

**This application is INTENTIONALLY VULNERABLE and should NEVER be used in production!**

It is designed solely for testing security scanners and educational purposes. All vulnerabilities are deliberately implemented to provide comprehensive test coverage for the Dynamic Scanner.

## 🛠️ Development

- **Port:** 3002 (configurable via PORT environment variable)
- **Database:** SQLite in-memory (resets on restart)
- **Dependencies:** Express, CORS, bcrypt, JWT, SQLite3

## 📊 Test Coverage

This test app covers all attack categories that the Dynamic Scanner tests for:

1. **Injection** - SQL, Command, XSS, LDAP, XPath
2. **Authentication** - Brute force, weak passwords, JWT issues
3. **Authorization** - IDOR, privilege escalation, access control bypass
4. **Business Logic** - Price manipulation, race conditions, workflow bypass
5. **Data Exposure** - Information disclosure, debug info exposure
6. **Cryptography** - Weak encryption, insecure random, key management
7. **Insecure Design** - Missing validation, security misconfiguration
8. **Vulnerable Components** - Outdated dependencies, known CVEs

Perfect for comprehensive testing of the Dynamic Scanner's AI-powered vulnerability detection capabilities!
