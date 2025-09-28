# 🧪 Dynamic Scanner Testing Guide

This guide provides comprehensive testing approaches for the dynamic scanner beyond basic test cases.

## 🚀 Quick Start

### Run All Tests
```bash
python run_dynamic_tests.py --all
```

### Run Specific Test Types
```bash
# Quick test (30-60 seconds)
python run_dynamic_tests.py --test quick

# Advanced test suite (2-5 minutes)
python run_dynamic_tests.py --test advanced

# Real-world applications (3-7 minutes)
python run_dynamic_tests.py --test real-world

# Performance testing (5-15 minutes)
python run_dynamic_tests.py --test performance

# Show previous results
python run_dynamic_tests.py --test results
```

## 📊 Test Suites Overview

### 1. **Quick Test** (`--test quick`)
- **Duration**: 30-60 seconds
- **Files**: 1 simple vulnerable app
- **Vulnerabilities**: SQL injection, IDOR, XSS
- **Purpose**: Fast validation of basic functionality

### 2. **Advanced Test Suite** (`--test advanced`)
- **Duration**: 2-5 minutes
- **Files**: 20+ files across multiple scenarios
- **Vulnerabilities**: 6+ categories, 50+ attack types
- **Includes**:
  - Vulnerable Flask application
  - Multi-language codebase
  - Large codebase performance
  - Specific attack categories

### 3. **Real-World Applications** (`--test real-world`)
- **Duration**: 3-7 minutes
- **Files**: 15+ production-like files
- **Vulnerabilities**: Real-world patterns
- **Includes**:
  - E-commerce application
  - API-only application
  - Production-like vulnerabilities

### 4. **Performance Testing** (`--test performance`)
- **Duration**: 5-15 minutes
- **Files**: 100-200+ files
- **Tests**: Memory usage, concurrent scans, edge cases
- **Includes**:
  - Large codebase performance
  - Concurrent scan testing
  - Memory usage analysis
  - Edge case testing

## 🔍 Detailed Test Scenarios

### Vulnerable Flask Application
```python
# Creates a comprehensive Flask app with:
- SQL Injection vulnerabilities
- IDOR (Insecure Direct Object Reference)
- Privilege Escalation
- Path Traversal
- Command Injection
- Weak Password Hashing
- XSS vulnerabilities
- Insecure Deserialization
- Business Logic Flaws
```

### E-commerce Application
```python
# Creates a realistic e-commerce app with:
- User registration/login
- Product search with XSS
- Order creation with business logic flaws
- Payment processing vulnerabilities
- Admin panel access issues
- File upload vulnerabilities
- API endpoints with IDOR
```

### API-Only Application
```python
# Creates a FastAPI application with:
- REST API endpoints
- JWT authentication vulnerabilities
- SQL injection in API calls
- Missing authorization checks
- File upload vulnerabilities
- Search functionality with XSS
```

### Multi-Language Codebase
```python
# Tests multiple programming languages:
- Python (Flask)
- JavaScript (Express)
- Java (Servlets)
- PHP (Native)
```

## 📈 Performance Benchmarks

| Codebase Size | Files | Expected Duration | Expected Memory |
|---------------|-------|-------------------|-----------------|
| Small         | 10    | 30-60 seconds     | 50-100 MB       |
| Medium        | 50    | 1-3 minutes       | 100-200 MB      |
| Large         | 100   | 3-7 minutes       | 200-400 MB      |
| Very Large    | 200   | 5-15 minutes      | 400-800 MB      |

## 🎯 Attack Categories Tested

### 1. **Injection Attacks** (15 test cases)
- SQL Injection
- NoSQL Injection
- Command Injection
- LDAP Injection
- XPath Injection

### 2. **Authentication Vulnerabilities** (12 test cases)
- Weak Password Hashing
- Session Management Issues
- JWT Vulnerabilities
- Brute Force Attacks
- Password Reset Flaws

### 3. **Authorization Issues** (10 test cases)
- IDOR (Insecure Direct Object Reference)
- Privilege Escalation
- Missing Authorization
- Role-Based Access Control Flaws

### 4. **Business Logic Flaws** (8 test cases)
- Price Manipulation
- Race Conditions
- Workflow Bypass
- State Management Issues

### 5. **Data Exposure** (6 test cases)
- Sensitive Data Exposure
- Information Disclosure
- Error Message Leakage

### 6. **Cryptography Issues** (7 test cases)
- Weak Encryption
- Weak Hashing
- Crypto Implementation Flaws

### 7. **Insecure Design** (5 test cases)
- Design Flaws
- Architectural Vulnerabilities

### 8. **Vulnerable Components** (4 test cases)
- Outdated Dependencies
- Vulnerable Libraries

## 📋 Expected Results

### Minimum Thresholds
- **Minimum Vulnerabilities**: 5 per test
- **Minimum AI Findings**: 3 per test
- **Maximum False Positives**: 2 per test
- **Coverage Threshold**: 80%

### Success Criteria
- ✅ All test suites complete successfully
- ✅ AI generates targeted, relevant test cases
- ✅ Vulnerabilities are properly categorized
- ✅ OWASP format output is consistent
- ✅ Performance meets benchmarks
- ✅ Memory usage stays within limits

## 🔧 Custom Testing

### Test Your Own Codebase
```python
import asyncio
from dynamic_scanner import DynamicScanner

async def test_my_codebase():
    scanner = DynamicScanner()
    results = await scanner.run_full_analysis(
        codebase_path="/path/to/your/code",
        target_url="http://localhost:5000"
    )
    
    print(f"Vulnerabilities found: {results.get('vulnerabilities_found', 0)}")
    print(f"AI-generated findings: {len(results.get('owasp_findings', []))}")

asyncio.run(test_my_codebase())
```

### Custom Test Scenarios
```python
# Create your own vulnerable code
vulnerable_code = '''
def vulnerable_function(user_input):
    # Your vulnerable code here
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    return execute_query(query)
'''

# Test with dynamic scanner
results = await scanner.run_full_analysis(test_dir, target_url)
```

## 📊 Test Results

### Output Files
- `dynamic_scanner_test_summary.json` - Advanced test results
- `real_world_app_test_summary.json` - Real-world app results
- `dynamic_scanner_performance_summary.json` - Performance results

### Sample Output
```json
{
  "total_tests": 4,
  "successful_tests": 4,
  "failed_tests": 0,
  "total_vulnerabilities_found": 45,
  "total_ai_generated_findings": 32,
  "performance_metrics": {
    "average_duration": 2.5,
    "max_memory_usage": 250.5
  }
}
```

## 🐛 Troubleshooting

### Common Issues
1. **Rate Limit Errors**: Wait a few minutes and retry
2. **Memory Issues**: Reduce file count in performance tests
3. **Timeout Errors**: Increase timeout in test configuration
4. **Import Errors**: Ensure all dependencies are installed

### Debug Mode
```bash
# Run with debug logging
PYTHONPATH=. python -m logging debug test_dynamic_scanner_advanced.py
```

## 🎉 Success Indicators

### ✅ Test Passes When:
- All vulnerabilities are detected
- AI generates relevant test cases
- Performance meets benchmarks
- Memory usage stays within limits
- No critical errors occur

### ❌ Test Fails When:
- Vulnerabilities are missed
- AI generates irrelevant tests
- Performance is too slow
- Memory usage exceeds limits
- Critical errors occur

## 📚 Next Steps

After running tests:
1. Review test results in JSON files
2. Analyze AI-generated findings
3. Check performance metrics
4. Identify areas for improvement
5. Run tests on your own codebases

## 🤝 Contributing

To add new test scenarios:
1. Create new test file in test directory
2. Add test to `run_dynamic_tests.py`
3. Update `test_config.json`
4. Document in this guide

---

**Happy Testing! 🚀**
