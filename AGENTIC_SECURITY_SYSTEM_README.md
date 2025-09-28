# 🚀 Agentic Security Testing System

A revolutionary AI-powered security testing platform that enables users to create custom security test cases through natural language interaction and automatically executes them against target applications.

## 🎯 Overview

This system replaces traditional drag-and-drop block interfaces with an intelligent, conversational AI assistant that understands security testing requirements and generates comprehensive test cases. Users can describe what they want to test in natural language, and the system will create and execute sophisticated security tests.

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Backend API   │    │   GitHub        │
│   (React)       │◄──►│   (FastAPI)     │◄──►│   Workflows     │
│                 │    │                 │    │                 │
│ • Agentic Chat  │    │ • Test Gen      │    │ • Test Exec     │
│ • Dashboard     │    │ • Attack Suite  │    │ • Results       │
│ • Results       │    │ • Swarm DB      │    │ • Notifications │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   AI Assistant  │    │   Test Engine   │    │   AgentMail     │
│   (Gemini)      │    │   (Playwright)  │    │   (Email)       │
│                 │    │                 │    │                 │
│ • Prompt Gen    │    │ • Test Exec     │    │ • Notifications │
│ • Test Cases    │    │ • Evidence      │    │ • Reports       │
│ • Analysis      │    │ • Screenshots   │    │ • Solutions     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🚀 Key Features

### 1. **Agentic Test Case Builder**
- **Natural Language Interface**: Users describe what they want to test in plain English
- **AI-Powered Generation**: Gemini AI creates specific, actionable test cases
- **Interactive Refinement**: Users can refine and customize generated tests
- **Real-time Feedback**: AI provides suggestions and improvements

### 2. **Enhanced Attack Suite (11 Attack Types)**
- **Authenticated Scans**: Test with valid credentials for deeper vulnerability detection
- **Business Logic Fuzzing**: State-aware testing for complex application flows
- **LLM-Assisted Generation**: AI creates creative attack vectors and bypass techniques
- **IAST Instrumentation**: Runtime vulnerability detection during test execution
- **Complex Input Fuzzing**: JSON, GraphQL, JWT, and file upload testing
- **Dependency Scanning**: Supply chain vulnerability detection
- **CI/CD Integration**: Automated testing in development pipelines
- **False-Positive Reduction**: AI-powered verification and confidence scoring
- **Business Logic Templates**: Pre-built scenarios for common business domains
- **Adversary Emulation**: Red team-style attack simulation
- **Runtime Monitoring**: Continuous security monitoring and alerting

### 3. **Test Case Execution Engine**
- **Playwright Integration**: Automated browser testing with screenshots
- **Multiple Attack Types**: SQL injection, XSS, IDOR, authentication bypass, etc.
- **Evidence Collection**: Screenshots, logs, and detailed vulnerability reports
- **Parallel Execution**: Efficient testing of multiple scenarios
- **Result Analysis**: Comprehensive reporting with risk scoring

### 4. **Swarm Database**
- **GitHub PR Monitoring**: Automatic analysis of pull requests for security issues
- **Attack Vector Detection**: Pattern matching for common vulnerability types
- **Real-time Alerts**: Immediate notification of security issues
- **Historical Tracking**: Complete audit trail of security findings

### 5. **AgentMail Component**
- **Intelligent Notifications**: AI-generated, context-aware security alerts
- **Multiple Formats**: HTML emails with rich formatting and attachments
- **User Preferences**: Customizable notification settings and subscriptions
- **Actionable Insights**: Clear mitigation steps and recommendations

### 6. **AI Prompt System**
- **Dynamic Prompt Generation**: Context-aware prompts for different scenarios
- **Strategy-Based Testing**: Beginner, intermediate, expert, and compliance modes
- **Language-Specific**: Tailored prompts for different programming languages
- **Framework-Aware**: Specialized prompts for React, Express, Spring, etc.

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.11+
- Node.js 18+
- MongoDB
- GitHub account with API access

### Backend Setup
```bash
cd backend
pip install -r requirements.txt
python main.py
```

### Frontend Setup
```bash
cd frontend
npm install
npm start
```

### Environment Variables
Create a `.env` file with:
```env
GEMINI_API_KEY=your_gemini_api_key
GITHUB_TOKEN=your_github_token
SMTP_SERVER=smtp.gmail.com
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password
MONGODB_URI=mongodb://localhost:27017/swarm_security
```

## 🎮 Usage

### 1. **Start a Conversation**
Navigate to `/agentic` in the frontend and start chatting with the AI assistant:

```
User: "I want to test our e-commerce site for payment bypass vulnerabilities"
AI: "I'll help you create comprehensive tests for payment bypass vulnerabilities. Let me generate test cases that focus on:
- Cart manipulation attacks
- Payment token replay
- Race conditions in checkout
- Direct API calls to payment endpoints
- Price manipulation techniques"
```

### 2. **Customize Test Cases**
The AI will generate specific test cases that you can refine:

```json
{
  "test_name": "Cart Total Manipulation Test",
  "description": "Test if users can modify cart totals in the frontend",
  "attack_type": "business_logic",
  "payloads": ["-100", "0.01", "999999"],
  "endpoints": ["/api/cart/update"],
  "risk_level": "High",
  "test_steps": [
    "Add item to cart",
    "Intercept cart update request",
    "Modify total amount",
    "Submit modified request",
    "Verify payment processing"
  ]
}
```

### 3. **Execute Tests**
The system automatically executes tests using Playwright and provides detailed results:

```
✅ Test Execution Summary
Total Tests: 15
Completed: 15
Failed: 0
Success Rate: 100%
Total Findings: 3
Risk Score: 75

🔍 Top Findings:
1. Cart Total Manipulation (High) - Payment bypass detected
2. JWT Token Replay (Medium) - Authentication bypass possible
3. Race Condition in Checkout (Medium) - Double payment processing
```

### 4. **Review Results**
Access detailed vulnerability reports with:
- Screenshots of successful exploits
- Step-by-step reproduction instructions
- Mitigation recommendations
- Code examples for fixes

## 🔧 API Endpoints

### Test Generation
```http
POST /api/generate-tests
Content-Type: application/json

{
  "user_request": "Test for SQL injection vulnerabilities",
  "target_url": "https://example.com",
  "conversation_history": []
}
```

### Workflow Trigger
```http
POST /api/trigger-workflow
Content-Type: application/json

{
  "user_request": "Test for SQL injection vulnerabilities",
  "target_url": "https://example.com",
  "test_description": "Comprehensive SQL injection testing",
  "attack_categories": ["injection", "authentication"],
  "workflow_id": "test-123"
}
```

### Workflow Status
```http
GET /api/workflow-status/{workflow_id}
```

## 📊 Security Categories

The system covers all major security categories:

### OWASP Top 10
- **A01**: Broken Access Control
- **A02**: Cryptographic Failures
- **A03**: Injection
- **A04**: Insecure Design
- **A05**: Security Misconfiguration
- **A06**: Vulnerable and Outdated Components
- **A07**: Identification and Authentication Failures
- **A08**: Software and Data Integrity Failures
- **A09**: Security Logging and Monitoring Failures
- **A10**: Server-Side Request Forgery

### Attack Techniques
- **Injection**: SQL, NoSQL, Command, LDAP, XPath, Template
- **Authentication**: Brute Force, Session Fixation, JWT Vulnerabilities
- **Authorization**: IDOR, Privilege Escalation, Access Control Bypass
- **Business Logic**: Price Manipulation, Race Conditions, Workflow Bypass
- **Cryptography**: Weak Encryption, Insecure Random, Key Management

## 🎯 Use Cases

### 1. **Development Teams**
- Automated security testing in CI/CD pipelines
- Real-time vulnerability detection during development
- Educational tool for learning security best practices

### 2. **Security Teams**
- Comprehensive security assessment of applications
- Custom test case development for specific threats
- Integration with existing security tools

### 3. **Compliance Teams**
- Automated compliance testing for regulations
- Audit trail and reporting capabilities
- Risk assessment and mitigation tracking

### 4. **Penetration Testers**
- Rapid test case generation for specific scenarios
- Evidence collection and documentation
- Integration with manual testing workflows

## 🔒 Security Features

### Safe Testing
- **Non-destructive**: All tests are designed to be safe and non-destructive
- **Controlled Environment**: Tests run in isolated environments
- **Rate Limiting**: Built-in rate limiting to prevent overwhelming targets
- **Error Handling**: Comprehensive error handling and recovery

### Privacy & Compliance
- **Data Protection**: Sensitive data is encrypted and protected
- **Audit Logging**: Complete audit trail of all activities
- **User Consent**: Clear consent mechanisms for all testing
- **Data Retention**: Configurable data retention policies

## 🚀 Advanced Features

### 1. **GitHub Integration**
- Automatic PR analysis for security issues
- Webhook-based real-time monitoring
- Integration with GitHub Actions

### 2. **AI-Powered Analysis**
- Context-aware test generation
- Intelligent false-positive reduction
- Dynamic prompt optimization

### 3. **Comprehensive Reporting**
- Executive summaries for stakeholders
- Technical details for developers
- Compliance reports for auditors

### 4. **Multi-Language Support**
- Python, JavaScript, Java, C#, PHP, Go, Rust, C++, Ruby, Swift, Kotlin
- Framework-specific testing (React, Express, Spring, etc.)
- Language-specific vulnerability patterns

## 📈 Performance

### Scalability
- **Horizontal Scaling**: Distributed test execution
- **Caching**: Intelligent caching of test results
- **Queue Management**: Efficient job queuing and processing

### Reliability
- **Fault Tolerance**: Graceful handling of failures
- **Retry Logic**: Automatic retry for failed tests
- **Monitoring**: Comprehensive system monitoring

## 🔮 Future Enhancements

### Planned Features
- **Machine Learning**: ML-based vulnerability prediction
- **Cloud Integration**: AWS, Azure, GCP integration
- **Mobile Testing**: iOS and Android app testing
- **API Testing**: Comprehensive API security testing
- **Performance Testing**: Security-focused performance testing

### Research Areas
- **Zero-Day Detection**: Advanced techniques for unknown vulnerabilities
- **Behavioral Analysis**: User behavior-based attack detection
- **Threat Intelligence**: Integration with threat intelligence feeds

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
git clone https://github.com/your-org/agentic-security-system
cd agentic-security-system
./setup.sh
```

### Running Tests
```bash
# Backend tests
cd backend
python -m pytest

# Frontend tests
cd frontend
npm test

# Integration tests
python demo_agentic_system.py
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Google Gemini**: For providing the AI capabilities
- **Playwright**: For browser automation
- **FastAPI**: For the backend framework
- **React**: For the frontend framework
- **OWASP**: For security standards and guidelines

## 📞 Support

- **Documentation**: [docs.swarm-ai.com](https://docs.swarm-ai.com)
- **Issues**: [GitHub Issues](https://github.com/your-org/agentic-security-system/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/agentic-security-system/discussions)
- **Email**: support@swarm-ai.com

## 🎉 Demo

Try the live demo at [demo.swarm-ai.com](https://demo.swarm-ai.com) or run the local demo:

```bash
python demo_agentic_system.py
```

---

**Built with ❤️ by the Swarm AI Security Team**

*Revolutionizing security testing through AI-powered automation*
