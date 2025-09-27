# Swarm - Web Security Scanner

🛡️ **Fast, non-destructive web vulnerability scanner for developers**

Swarm quickly identifies common web security issues like clickjacking, CORS misconfigurations, XSS vulnerabilities, and missing security headers. Get actionable fix snippets that you can copy-paste into your codebase.

## 🚀 Quick Start

### 1. Start the Vulnerable Demo App
```bash
cd demo-app
npm install
npm start
# Runs on http://localhost:3001
```

### 2. Start the Backend API
```bash
cd backend
pip install -r requirements.txt
python main.py
# Runs on http://localhost:8000
```

### 3. Start the Frontend
```bash
cd frontend
npm install
npm start
# Runs on http://localhost:3000
```

### 4. Test the Scanner
1. Open http://localhost:3000
2. Enter target URL: `http://localhost:3001`
3. Accept consent and start scan
4. View real-time results with fix snippets

## 🏗️ Architecture

```
Frontend (React)   <-->  Backend API (FastAPI)
                              |
                         Coordinator
                              |
               +------+-------+-------+
               |      |       |       |
           Crawler  Scanner  Rules  Report
         (Playwright) (Headers) (Priority) (PDF)
```

## 🔍 What We Detect

- **Clickjacking** - Missing X-Frame-Options/CSP frame-ancestors
- **CORS Issues** - Permissive Access-Control-Allow-Origin
- **XSS Indicators** - Reflected user input without escaping
- **Open Redirects** - Unvalidated redirect parameters
- **Missing Security Headers** - CSP, HSTS, X-Content-Type-Options
- **Insecure Cookies** - Missing Secure, HttpOnly, SameSite
- **Information Disclosure** - Verbose error pages, server headers

## 🛠️ Manual Testing

### Crawler Module
```bash
cd crawler
pip install -r requirements.txt
playwright install
python crawler.py
```

### Header Scanner
```bash
cd scanner
python header_scanner.py
```

## 📊 Example Output

```json
{
  "finding": {
    "category": "clickjacking",
    "severity": "high",
    "title": "Missing X-Frame-Options Header",
    "fix_snippet": "add_header X-Frame-Options \"DENY\";",
    "reproduce_command": "curl -I http://localhost:3001"
  }
}
```

## 🔒 Security & Ethics

- ✅ **Non-destructive** - Read-only scans, no data modification
- ✅ **Consent required** - Explicit permission before scanning
- ✅ **Safe probes** - No brute force or credential attacks
- ✅ **Privacy focused** - Temporary data storage, automatic cleanup

## 🎯 Demo Script (3 minutes)

1. **Hook** (20s): "Teams ship fast but miss simple security configs"
2. **Live scan** (60s): Start scan on demo app → show real-time findings
3. **Evidence** (60s): Click finding → show screenshot + headers + fix snippet
4. **Reproduce** (30s): Copy-paste fix snippet → click "Replay" button
5. **Integration** (10s): "Works in CI for every PR"

## 🏆 Key Features for Judges

- **Reproducible** - Exact replay of every finding
- **Actionable** - Copy-paste fix snippets for Nginx/Express/Flask
- **Real-time** - Live SSE streaming of scan progress
- **Evidence-based** - Screenshots, HTTP headers, response analysis
- **Production-ready** - CI integration, email reports, issue creation

## 📈 Success Metrics

- **Speed**: ~2 minutes for 30-page scan
- **Accuracy**: Deterministic findings with reproduction steps
- **Usability**: One-click fixes, clear prioritization
- **Coverage**: OWASP Top 10 surface area

## 🛡️ Legal Notice

Only scan websites you own or have explicit written permission to test. Swarm performs non-destructive security analysis and requires user consent before starting any scan.

---

Built for MHacks 2025 🏆