# Security Scanner - OWASP Top 10 Analysis

A comprehensive security scanner that analyzes web applications for OWASP Top 10 vulnerabilities.

## 🚀 Quick Start

### 1. Run Diagnostics
First, check what data is available:
```bash
python scanner/diagnostic.py
```

### 2. Test the Scanner
Run the scanner with sample data:
```bash
python scanner/test_scanner.py
```

### 3. Run on Real Data
If you have a `pages.json` file from the crawler:
```bash
python scanner/run_scanner.py pages.json
```

## 📊 What the Scanner Analyzes

### OWASP Top 10 Coverage
- **A01** - Broken Access Control
- **A02** - Cryptographic Failures  
- **A03** - Injection (XSS, SQLi, Command Injection)
- **A04** - Insecure Design
- **A05** - Security Misconfiguration
- **A06** - Vulnerable and Outdated Components
- **A07** - Identification and Authentication Failures
- **A08** - Software and Data Integrity Failures
- **A09** - Security Logging and Monitoring Failures
- **A10** - Server-Side Request Forgery

### Data Sources Analyzed
- HTTP headers and security policies
- Forms and input fields
- JavaScript code and libraries
- Cookies and session management
- SSL/TLS configuration
- Server version information
- External resources and CDNs

## 🔧 Usage

### Command Line Interface
```bash
# Basic usage
python scanner/run_scanner.py pages.json

# With custom run ID
python scanner/run_scanner.py pages.json --run-id my_scan

# With custom output directory
python scanner/run_scanner.py pages.json --output-dir ./reports

# Verbose output
python scanner/run_scanner.py pages.json --verbose
```

### Programmatic Usage
```python
from scanner.scanner_orchestrator import ScannerOrchestrator
from pathlib import Path

# Create orchestrator
orchestrator = ScannerOrchestrator("my_run_id")

# Run scan
pages_file = Path("pages.json")
summary = orchestrator.scan_all(pages_file)

# Save reports
orchestrator.save_comprehensive_report(Path("./reports"))
```

## 📋 Output Files

The scanner generates several output files:

### Comprehensive Report
`comprehensive_security_report_{run_id}.json`
- All findings with detailed evidence
- Breakdown by scanner, category, and severity
- Risk scoring and prioritization

### Executive Summary
`executive_summary_{run_id}.json`
- High-level overview for stakeholders
- Risk assessment and recommendations
- Top findings summary

### Individual Scanner Reports
`{scanner_name}_findings.json`
- Findings from each individual scanner
- Detailed analysis per OWASP category

## 🛠️ Troubleshooting

### No Output Issues
If you're not seeing output:

1. **Check if pages.json exists:**
   ```bash
   python scanner/diagnostic.py
   ```

2. **Run the test suite:**
   ```bash
   python scanner/test_scanner.py
   ```

3. **Check file permissions:**
   ```bash
   ls -la pages.json
   ```

### Common Issues

**"Pages file not found"**
- Run the crawler first: `python crawler/crawler.py`
- Or create test data: `python scanner/test_scanner.py`

**"No pages found"**
- Check if pages.json contains valid data
- Verify the JSON format is correct

**"Scanner crashed"**
- Run with `--verbose` flag for detailed error info
- Check Python dependencies are installed

## 📈 Understanding Results

### Risk Score
- **0-20**: Minimal risk
- **21-40**: Low risk  
- **41-60**: Medium risk
- **61-80**: High risk
- **81-100**: Critical risk

### Severity Levels
- **Critical**: Immediate action required
- **High**: Fix within 30 days
- **Medium**: Fix within 90 days
- **Low**: Fix when convenient

### Priority Score
Each finding has a priority score (0-100) based on:
- Severity level
- Fix difficulty
- Impact potential
- OWASP category importance

## 🔍 Scanner Details

### Individual Scanners
- `HeaderScanner`: HTTP headers, CSP, cookies
- `InjectionScanner`: XSS, SQLi, command injection
- `AccessControlScanner`: Authorization, IDOR, admin access
- `AuthScanner`: Authentication, session management
- `CryptoScanner`: SSL/TLS, encryption, secrets
- `VulnerableComponentsScanner`: Library versions, dependencies
- `IntegrityScanner`: SRI, mixed content
- `LoggingScanner`: Security monitoring
- `SSRFScanner`: Server-side request forgery
- `DesignScanner`: Insecure design patterns

### Base Scanner Features
- Common vulnerability detection patterns
- Evidence collection and analysis
- Fix guidance and code snippets
- OWASP categorization
- Risk prioritization

## 🎯 Next Steps

After running the scanner:

1. **Review critical and high findings first**
2. **Implement recommended fixes**
3. **Re-scan to verify improvements**
4. **Set up regular scanning schedule**
5. **Integrate with CI/CD pipeline**

## 📞 Support

For issues or questions:
1. Run diagnostics: `python scanner/diagnostic.py`
2. Check test suite: `python scanner/test_scanner.py`
3. Review error messages with `--verbose` flag
4. Check file permissions and data format
