#!/usr/bin/env python3
"""
Demo script for the Dynamic Scanner

This script demonstrates the capabilities of the Gemini-powered dynamic scanner
by analyzing a sample codebase and generating security test cases.
"""

import asyncio
import json
import os
import sys
from pathlib import Path
import logging

# Add the scanner directory to the path
sys.path.append(str(Path(__file__).parent / "scanner"))

from dynamic_scanner import DynamicScanner
from dynamic_config import DynamicScannerConfig

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def create_sample_codebase():
    """Create a sample vulnerable codebase for testing"""
    logger.info("📁 Creating sample vulnerable codebase...")
    
    sample_dir = Path("sample_vulnerable_app")
    sample_dir.mkdir(exist_ok=True)
    
    # Sample Python Flask app with vulnerabilities
    flask_app = '''
from flask import Flask, request, jsonify, session
import sqlite3
import hashlib
import os
import subprocess
import json

app = Flask(__name__)
app.secret_key = 'hardcoded_secret_key'

# Database connection
def get_db_connection():
    return sqlite3.connect('users.db')

# Vulnerable login endpoint
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # SQL Injection vulnerability
    conn = get_db_connection()
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor = conn.execute(query)
    user = cursor.fetchone()
    
    if user:
        session['user_id'] = user[0]
        return jsonify({'status': 'success', 'user_id': user[0]})
    else:
        return jsonify({'status': 'error', 'message': 'Invalid credentials'})

# Vulnerable user data endpoint
@app.route('/user/<int:user_id>')
def get_user(user_id):
    # IDOR vulnerability - no authorization check
    conn = get_db_connection()
    cursor = conn.execute(f"SELECT * FROM users WHERE id={user_id}")
    user = cursor.fetchone()
    
    if user:
        return jsonify({
            'id': user[0],
            'username': user[1],
            'email': user[2],
            'password_hash': user[3]  # Exposing password hash
        })
    else:
        return jsonify({'error': 'User not found'})

# Vulnerable file upload
@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    filename = file.filename
    
    # Path traversal vulnerability
    file.save(f'uploads/{filename}')
    return jsonify({'status': 'success', 'filename': filename})

# Vulnerable command execution
@app.route('/ping', methods=['POST'])
def ping_host():
    host = request.json.get('host')
    
    # Command injection vulnerability
    result = subprocess.run(f'ping -c 1 {host}', shell=True, capture_output=True, text=True)
    return jsonify({'output': result.stdout})

# Vulnerable password hashing
@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')
    
    # Weak password hashing (MD5)
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    conn = get_db_connection()
    conn.execute(f"INSERT INTO users (username, password) VALUES ('{username}', '{password_hash}')")
    conn.commit()
    
    return jsonify({'status': 'success'})

if __name__ == '__main__':
    app.run(debug=True)
'''
    
    # Write the Flask app
    (sample_dir / "app.py").write_text(flask_app)
    
    # Sample JavaScript frontend with vulnerabilities
    js_frontend = '''
// Vulnerable JavaScript frontend
class UserAPI {
    constructor() {
        this.baseUrl = 'http://localhost:5000';
    }
    
    // XSS vulnerability - no input sanitization
    displayUserData(userData) {
        const userDiv = document.getElementById('user-info');
        userDiv.innerHTML = `
            <h2>Welcome ${userData.username}!</h2>
            <p>Email: ${userData.email}</p>
            <p>User ID: ${userData.id}</p>
        `;
    }
    
    // Insecure API call - no CSRF protection
    async login(username, password) {
        const response = await fetch(`${this.baseUrl}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `username=${username}&password=${password}`
        });
        
        return response.json();
    }
    
    // IDOR vulnerability - accessing other users' data
    async getUserData(userId) {
        const response = await fetch(`${this.baseUrl}/user/${userId}`);
        return response.json();
    }
    
    // Insecure file upload
    async uploadFile(file) {
        const formData = new FormData();
        formData.append('file', file);
        
        const response = await fetch(`${this.baseUrl}/upload`, {
            method: 'POST',
            body: formData
        });
        
        return response.json();
    }
}

// Global instance
window.userAPI = new UserAPI();
'''
    
    # Write the JavaScript frontend
    (sample_dir / "frontend.js").write_text(js_frontend)
    
    # Sample HTML with vulnerabilities
    html_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Web App</title>
</head>
<body>
    <h1>Vulnerable Web Application</h1>
    
    <div id="login-form">
        <h2>Login</h2>
        <input type="text" id="username" placeholder="Username">
        <input type="password" id="password" placeholder="Password">
        <button onclick="login()">Login</button>
    </div>
    
    <div id="user-info" style="display: none;">
        <!-- User data will be displayed here -->
    </div>
    
    <div id="file-upload">
        <h2>File Upload</h2>
        <input type="file" id="file-input">
        <button onclick="uploadFile()">Upload</button>
    </div>
    
    <script src="frontend.js"></script>
</body>
</html>
'''
    
    # Write the HTML template
    (sample_dir / "index.html").write_text(html_template)
    
    # Sample package.json with vulnerable dependencies
    package_json = '''
{
    "name": "vulnerable-web-app",
    "version": "1.0.0",
    "dependencies": {
        "express": "4.16.0",
        "lodash": "4.17.4",
        "jquery": "1.9.1",
        "moment": "2.19.0"
    }
}
'''
    
    # Write package.json
    (sample_dir / "package.json").write_text(package_json)
    
    logger.info(f"✅ Sample codebase created at: {sample_dir}")
    return str(sample_dir)

async def demo_dynamic_scanner():
    """Demonstrate the dynamic scanner capabilities"""
    logger.info("🚀 Starting Dynamic Scanner Demo")
    
    # Check for Gemini API key
    if not os.getenv("GEMINI_API_KEY"):
        logger.error("❌ GEMINI_API_KEY environment variable not set!")
        logger.info("Please set your Gemini API key:")
        logger.info("export GEMINI_API_KEY='your-api-key-here'")
        return
    
    try:
        # Create sample codebase
        codebase_path = await create_sample_codebase()
        target_url = "http://localhost:5000"
        
        # Initialize dynamic scanner
        logger.info("🤖 Initializing Dynamic Scanner...")
        scanner = DynamicScanner()
        
        # Run analysis
        logger.info("🔍 Running dynamic code analysis...")
        results = await scanner.run_full_analysis(codebase_path, target_url)
        
        # Display results
        logger.info("📊 Analysis Results:")
        logger.info(f"   Total Files Analyzed: {results.get('total_files', 0)}")
        logger.info(f"   Total Lines of Code: {results.get('total_lines', 0)}")
        logger.info(f"   Languages Detected: {', '.join(results.get('languages', []))}")
        logger.info(f"   Test Cases Generated: {results.get('total_tests', 0)}")
        logger.info(f"   High Priority Tests: {results.get('high_priority_tests', 0)}")
        logger.info(f"   Vulnerabilities Found: {results.get('vulnerabilities_found', 0)}")
        
        # Display security patterns
        if 'code_analysis' in results and 'security_patterns' in results['code_analysis']:
            logger.info("🔍 Security Patterns Detected:")
            for pattern, count in results['code_analysis']['security_patterns'].items():
                if count > 0:
                    logger.info(f"   {pattern.replace('_', ' ').title()}: {count} occurrences")
        
        # Display test cases by category
        if 'test_cases' in results:
            logger.info("🧪 Generated Test Cases:")
            by_category = {}
            for test_case in results['test_cases']:
                category = test_case.get('category', 'unknown')
                if category not in by_category:
                    by_category[category] = []
                by_category[category].append(test_case)
            
            for category, tests in by_category.items():
                logger.info(f"   {category.title()}: {len(tests)} tests")
                for test in tests[:3]:  # Show first 3 tests
                    logger.info(f"     - {test.get('test_name', 'Unknown')} ({test.get('risk_level', 'Unknown')})")
        
        # Display execution results
        if 'execution_results' in results:
            logger.info("⚡ Test Execution Results:")
            for result in results['execution_results'][:5]:  # Show first 5 results
                status = result.get('status', 'unknown')
                test_name = result.get('test_name', 'Unknown')
                vulns = len(result.get('vulnerabilities_found', []))
                logger.info(f"   {test_name}: {status} ({vulns} vulnerabilities)")
        
        # Save detailed results
        output_file = "dynamic_scanner_results.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"💾 Detailed results saved to: {output_file}")
        
        # Display summary
        logger.info("🎯 Demo Summary:")
        logger.info("   ✅ Dynamic code analysis completed")
        logger.info("   ✅ Security test cases generated using Gemini AI")
        logger.info("   ✅ Test execution simulated")
        logger.info("   ✅ Results exported to JSON")
        
        logger.info("🚀 Dynamic Scanner Demo completed successfully!")
        
    except Exception as e:
        logger.error(f"❌ Demo failed: {str(e)}")
        raise

async def demo_specific_attack_categories():
    """Demonstrate specific attack category analysis"""
    logger.info("🎯 Demonstrating specific attack category analysis...")
    
    try:
        scanner = DynamicScanner()
        
        # Test specific categories
        categories_to_test = ["injection", "authentication", "authorization", "business_logic"]
        
        for category in categories_to_test:
            logger.info(f"🔍 Testing {category} category...")
            
            # Create a simple test context
            test_context = f"""
            Sample codebase with {category} vulnerabilities:
            - Python Flask application
            - User authentication system
            - Database operations
            - File upload functionality
            - API endpoints
            """
            
            # Generate test cases for this category
            test_cases = await scanner._generate_category_test_cases(
                category, 
                scanner.attack_categories[category], 
                test_context
            )
            
            logger.info(f"   Generated {len(test_cases)} test cases for {category}")
            for test_case in test_cases[:2]:  # Show first 2
                logger.info(f"     - {test_case.get('test_name', 'Unknown')} ({test_case.get('risk_level', 'Unknown')})")
        
        logger.info("✅ Category-specific analysis completed!")
        
    except Exception as e:
        logger.error(f"❌ Category analysis failed: {str(e)}")

def main():
    """Main demo function"""
    print("🔐 Dynamic Security Scanner Demo")
    print("=" * 50)
    print()
    
    # Check if running in interactive mode
    if len(sys.argv) > 1 and sys.argv[1] == "--interactive":
        print("Interactive mode - you can run specific demos:")
        print("1. Full analysis demo")
        print("2. Category-specific analysis demo")
        print("3. Both")
        
        choice = input("Enter your choice (1-3): ").strip()
        
        if choice == "1":
            asyncio.run(demo_dynamic_scanner())
        elif choice == "2":
            asyncio.run(demo_specific_attack_categories())
        elif choice == "3":
            asyncio.run(demo_dynamic_scanner())
            asyncio.run(demo_specific_attack_categories())
        else:
            print("Invalid choice. Running full demo...")
            asyncio.run(demo_dynamic_scanner())
    else:
        # Run full demo
        asyncio.run(demo_dynamic_scanner())

if __name__ == "__main__":
    main()

