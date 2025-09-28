# 🤖 Agentic Security Testing System

A comprehensive AI-powered security testing platform that generates and executes custom test cases based on your codebase and natural language requests.

## 🚀 Quick Start

### 1. Setup
```bash
# Make setup script executable
chmod +x setup_agentic_tests.sh

# Run setup
./setup_agentic_tests.sh

# Add your Gemini API key to .env file
echo "GEMINI_API_KEY=your_api_key_here" >> .env
```

### 2. Run Demo
```bash
# Quick demo
python3 run_agentic_tests.py --demo

# Interactive mode
python3 run_agentic_tests.py
```

## 🧠 How It Works

### **Two Modes of Operation:**

#### 1. **Code-Aware Mode** (Intelligent)
- **Analyzes your actual codebase** to understand:
  - Function definitions and parameters
  - Database queries and SQL patterns
  - Input validation logic
  - Authentication/authorization flows
  - API endpoints and data structures

- **Generates targeted test cases** that:
  - Use real parameter names from your code
  - Target actual functions and endpoints
  - Exploit specific vulnerabilities found in code
  - Provide realistic payloads based on your app's functionality

#### 2. **Generic Mode** (Fallback)
- Uses **common vulnerability patterns** and **security knowledge**
- Generates test cases based on:
  - Your natural language description
  - General attack templates
  - OWASP Top 10 patterns

## 🔧 Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   User Input    │───▶│  AI Test         │───▶│  Test Execution │
│   (Natural      │    │  Generation      │    │  Engine         │
│    Language)    │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │  Code Analysis   │    │  Results &      │
                       │  (Optional)      │    │  Reporting      │
                       └──────────────────┘    └─────────────────┘
```

## 📁 File Structure

```
scanner/
├── code_aware_test_generator.py    # Analyzes code and generates targeted tests
├── test_runner.py                  # Executes test cases against target
├── enhanced_attack_suite.py        # Comprehensive attack patterns
└── dynamic_scanner.py              # Original dynamic scanner

run_agentic_tests.py                # Main integration script
setup_agentic_tests.sh              # Setup script
requirements.txt                    # Python dependencies
```

## 🎯 Usage Examples

### **Example 1: Code-Aware Testing**
```bash
# Analyze your codebase and generate targeted tests
python3 run_agentic_tests.py \
  --codebase /path/to/your/app \
  --target https://your-app.com \
  --request "Test for SQL injection in user authentication"
```

**What happens:**
1. 🔍 Scans your codebase for SQL queries, user auth functions
2. 🤖 AI generates tests targeting your specific auth endpoints
3. ⚡ Executes tests against your live application
4. 📊 Reports vulnerabilities with specific code locations

### **Example 2: Generic Testing**
```bash
# Generate tests without codebase access
python3 run_agentic_tests.py \
  --target https://your-app.com \
  --request "Test for XSS vulnerabilities in comment system"
```

**What happens:**
1. 🤖 AI generates XSS tests based on common patterns
2. ⚡ Executes tests against your application
3. 📊 Reports findings with mitigation recommendations

## 🔍 Test Types Supported

### **Injection Attacks**
- **SQL Injection**: Tests database queries with malicious payloads
- **XSS**: Tests for cross-site scripting vulnerabilities
- **Command Injection**: Tests for OS command execution
- **Path Traversal**: Tests for file system access

### **Authentication & Authorization**
- **Authentication Bypass**: Tests login mechanisms
- **Authorization Bypass**: Tests access control
- **Session Management**: Tests session handling

### **Business Logic**
- **State Manipulation**: Tests application state changes
- **Race Conditions**: Tests concurrent access
- **Data Validation**: Tests input validation

### **Infrastructure**
- **Security Headers**: Checks for missing security headers
- **Sensitive Data**: Detects exposed secrets
- **Error Messages**: Checks for information disclosure

## 📊 Test Execution Process

### **1. Test Generation**
```python
# Code-aware generation
generator = CodeAwareTestGenerator()
code_files = await generator.analyze_codebase("/path/to/code")
test_cases = await generator.generate_targeted_tests(code_files, user_request)

# Generic generation
suite = EnhancedAttackSuite()
test_cases = await suite.run_llm_assisted_generation(target_url, user_request)
```

### **2. Test Execution**
```python
runner = TestRunner(headless=True)
results = await runner.run_test_cases(test_cases, target_url)
```

### **3. Results Analysis**
```python
report = runner.generate_report(results)
# Generates comprehensive report with:
# - Vulnerability counts by severity
# - Risk score calculation
# - Detailed findings with evidence
# - Screenshots and logs
```

## 🎨 Integration with Frontend

The system integrates with your existing React frontend:

```javascript
// In AgenticChat.js
const handleStartGeneration = async () => {
  const response = await fetch('/api/test-generation/trigger-workflow', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      user_request: inputValue,
      target_url: targetUrl,
      codebase_path: codebasePath
    })
  });
  
  const result = await response.json();
  // Handle test generation and execution
};
```

## 🔧 Configuration

### **Environment Variables**
```bash
# .env file
GEMINI_API_KEY=your_gemini_api_key_here
HEADLESS_MODE=true
TEST_TIMEOUT=30
SCREENSHOTS_DIR=test_screenshots
DEFAULT_TARGET_URL=https://httpbin.org
```

### **Test Configuration**
```python
# In test_runner.py
runner = TestRunner(
    headless=True,        # Run browser in headless mode
    timeout=30           # Test timeout in seconds
)
```

## 📈 Advanced Features

### **1. Custom Test Templates**
```python
# Create custom test templates
custom_template = {
    "name": "Custom Business Logic Test",
    "attack_type": "business_logic",
    "payloads": ["custom_payload_1", "custom_payload_2"],
    "target_function": "process_payment",
    "expected_behavior": "Should reject invalid amounts"
}
```

### **2. CI/CD Integration**
```yaml
# .github/workflows/security-tests.yml
name: Security Tests
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run Agentic Security Tests
        run: python3 run_agentic_tests.py --codebase . --target ${{ env.TARGET_URL }}
```

### **3. Custom Vulnerability Patterns**
```python
# Add custom patterns to code_aware_test_generator.py
custom_patterns = {
    "custom_vuln": [
        r"custom_pattern_1",
        r"custom_pattern_2"
    ]
}
```

## 🚨 Security Considerations

### **Safe Testing Practices**
- ✅ **Non-destructive**: Tests use safe payloads that don't damage data
- ✅ **Controlled environment**: Tests run against designated test targets
- ✅ **Rate limiting**: Built-in delays between test requests
- ✅ **Error handling**: Comprehensive error handling and logging

### **Production Safety**
- ⚠️ **Never test production** without explicit permission
- ⚠️ **Use test environments** for all security testing
- ⚠️ **Review test cases** before execution
- ⚠️ **Monitor test execution** for unexpected behavior

## 🔍 Troubleshooting

### **Common Issues**

#### **1. Gemini API Key Issues**
```bash
# Check if API key is set
echo $GEMINI_API_KEY

# Add to .env file
echo "GEMINI_API_KEY=your_key_here" >> .env
```

#### **2. Playwright Browser Issues**
```bash
# Reinstall browsers
python3 -m playwright install

# Check browser installation
python3 -m playwright --version
```

#### **3. Test Execution Failures**
```bash
# Check logs
tail -f test_execution.log

# Run with verbose output
python3 run_agentic_tests.py --demo --verbose
```

## 📚 API Reference

### **CodeAwareTestGenerator**
```python
class CodeAwareTestGenerator:
    async def analyze_codebase(self, codebase_path: str) -> List[CodeFile]
    async def generate_targeted_tests(self, code_files: List[CodeFile], user_request: str) -> List[TestCase]
```

### **TestRunner**
```python
class TestRunner:
    async def run_test_cases(self, test_cases: List[Dict], target_url: str) -> List[TestResult]
    def generate_report(self, results: List[TestResult]) -> Dict[str, Any]
```

### **EnhancedAttackSuite**
```python
class EnhancedAttackSuite:
    async def run_llm_assisted_generation(self, target_url: str, user_request: str) -> List[Dict]
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add your improvements
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For questions, issues, or contributions:
- Create an issue in the repository
- Check the troubleshooting section
- Review the API documentation

---

**Happy Testing! 🚀🔒**
