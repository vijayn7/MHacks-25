#!/usr/bin/env python3
"""
Advanced Testing Suite for Dynamic Scanner

This script provides comprehensive testing scenarios for the dynamic scanner
beyond basic test cases, including real-world vulnerable applications.
"""

import asyncio
import json
import os
import sys
import tempfile
import shutil
from pathlib import Path
import logging

# Add scanner directory to path
sys.path.append(str(Path(__file__).parent / "scanner"))

from dynamic_scanner import DynamicScanner

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DynamicScannerTester:
    """Advanced testing class for dynamic scanner"""
    
    def __init__(self):
        self.scanner = DynamicScanner()
        self.test_results = []
    
    async def test_vulnerable_flask_app(self):
        """Test with a comprehensive vulnerable Flask application"""
        logger.info("🧪 Testing with vulnerable Flask application...")
        
        # Create vulnerable Flask app
        flask_app = '''
from flask import Flask, request, jsonify, session, render_template_string
import sqlite3
import hashlib
import os
import subprocess
import pickle
import yaml
import json
from functools import wraps

app = Flask(__name__)
app.secret_key = 'hardcoded_secret_key_12345'

# Database setup
def init_db():
    conn = sqlite3.connect('users.db')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            role TEXT DEFAULT 'user'
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            title TEXT,
            content TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Helper functions
def get_db_connection():
    return sqlite3.connect('users.db')

def is_admin(user_id):
    conn = get_db_connection()
    cursor = conn.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user and user[0] == 'admin'

# Authentication decorator
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

# Admin decorator
def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not is_admin(session['user_id']):
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Vulnerable login endpoint - SQL Injection
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

# Vulnerable user profile - IDOR
@app.route('/user/<int:user_id>')
@require_auth
def get_user_profile(user_id):
    # IDOR vulnerability - no authorization check
    conn = get_db_connection()
    cursor = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if user:
        return jsonify({
            'id': user[0],
            'username': user[1],
            'email': user[2],
            'role': user[3]
        })
    else:
        return jsonify({'error': 'User not found'})

# Vulnerable admin panel - Privilege Escalation
@app.route('/admin/users')
@require_auth
def admin_users():
    # Missing admin check - any authenticated user can access
    conn = get_db_connection()
    cursor = conn.execute("SELECT id, username, email, role FROM users")
    users = cursor.fetchall()
    conn.close()
    
    return jsonify({'users': [{'id': u[0], 'username': u[1], 'email': u[2], 'role': u[3]} for u in users]})

# Vulnerable file upload - Path Traversal
@app.route('/upload', methods=['POST'])
@require_auth
def upload_file():
    file = request.files['file']
    filename = file.filename
    
    # Path traversal vulnerability
    file.save(f'uploads/{filename}')
    return jsonify({'status': 'success', 'filename': filename})

# Vulnerable command execution
@app.route('/ping', methods=['POST'])
@require_auth
def ping_host():
    host = request.json.get('host')
    
    # Command injection vulnerability
    result = subprocess.run(f'ping -c 1 {host}', shell=True, capture_output=True, text=True)
    return jsonify({'output': result.stdout})

# Vulnerable password hashing - Weak crypto
@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')
    email = request.json.get('email')
    
    # Weak password hashing (MD5)
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    conn = get_db_connection()
    try:
        conn.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", 
                    (username, password_hash, email))
        conn.commit()
        return jsonify({'status': 'success'})
    except sqlite3.IntegrityError:
        return jsonify({'status': 'error', 'message': 'Username already exists'})
    finally:
        conn.close()

# Vulnerable search - XSS
@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # XSS vulnerability - no output encoding
    template = f'''
    <html>
    <head><title>Search Results</title></head>
    <body>
        <h1>Search Results for: {query}</h1>
        <p>No results found for your query.</p>
    </body>
    </html>
    '''
    return render_template_string(template)

# Vulnerable API endpoint - Insecure Direct Object Reference
@app.route('/api/posts/<int:post_id>')
@require_auth
def get_post(post_id):
    # IDOR vulnerability - can access any post
    conn = get_db_connection()
    cursor = conn.execute("SELECT * FROM posts WHERE id = ?", (post_id,))
    post = cursor.fetchone()
    conn.close()
    
    if post:
        return jsonify({
            'id': post[0],
            'user_id': post[1],
            'title': post[2],
            'content': post[3]
        })
    else:
        return jsonify({'error': 'Post not found'})

# Vulnerable deserialization
@app.route('/api/import', methods=['POST'])
@require_admin
def import_data():
    data = request.json.get('data')
    
    # Insecure deserialization vulnerability
    try:
        imported_data = pickle.loads(data.encode())
        return jsonify({'status': 'success', 'data': imported_data})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# Vulnerable YAML parsing
@app.route('/api/config', methods=['POST'])
@require_admin
def update_config():
    config = request.json.get('config')
    
    # YAML deserialization vulnerability
    try:
        parsed_config = yaml.load(config, Loader=yaml.Loader)
        return jsonify({'status': 'success', 'config': parsed_config})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# Business logic vulnerability - Price manipulation
@app.route('/api/order', methods=['POST'])
@require_auth
def create_order():
    items = request.json.get('items', [])
    total = 0
    
    for item in items:
        # Business logic vulnerability - client controls price
        price = item.get('price', 0)
        quantity = item.get('quantity', 1)
        total += price * quantity
    
    # No server-side price validation
    return jsonify({
        'status': 'success',
        'total': total,
        'order_id': f'ORD_{os.urandom(4).hex()}'
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
'''
        
        # Create test directory
        test_dir = tempfile.mkdtemp()
        app_file = Path(test_dir) / "vulnerable_app.py"
        app_file.write_text(flask_app)
        
        # Create requirements.txt
        requirements = '''
Flask==2.3.3
PyYAML==6.0.1
'''
        (Path(test_dir) / "requirements.txt").write_text(requirements)
        
        # Create README
        readme = '''
# Vulnerable Flask Application

This is a deliberately vulnerable Flask application for testing security scanners.

## Vulnerabilities Included:
- SQL Injection
- IDOR (Insecure Direct Object Reference)
- Privilege Escalation
- Path Traversal
- Command Injection
- Weak Password Hashing
- XSS (Cross-Site Scripting)
- Insecure Deserialization
- Business Logic Flaws

## Setup:
pip install -r requirements.txt
python vulnerable_app.py
'''
        (Path(test_dir) / "README.md").write_text(readme)
        
        try:
            # Run dynamic analysis
            results = await self.scanner.run_full_analysis(test_dir, 'http://localhost:5000')
            
            test_result = {
                'test_name': 'Vulnerable Flask App',
                'total_files': results.get('total_files', 0),
                'total_tests': results.get('total_tests', 0),
                'vulnerabilities_found': results.get('vulnerabilities_found', 0),
                'ai_generated_findings': len(results.get('owasp_findings', [])),
                'languages': results.get('languages', []),
                'success': True
            }
            
            logger.info(f"✅ Flask app test completed: {test_result['vulnerabilities_found']} vulnerabilities found")
            return test_result
            
        except Exception as e:
            logger.error(f"❌ Flask app test failed: {str(e)}")
            return {'test_name': 'Vulnerable Flask App', 'success': False, 'error': str(e)}
        finally:
            shutil.rmtree(test_dir)
    
    async def test_multi_language_codebase(self):
        """Test with a multi-language codebase"""
        logger.info("🧪 Testing with multi-language codebase...")
        
        test_dir = tempfile.mkdtemp()
        
        # Python file
        python_file = '''
import requests
import json
import sqlite3

def vulnerable_function(user_input):
    # SQL Injection vulnerability
    conn = sqlite3.connect('db.sqlite')
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    return conn.execute(query).fetchall()
'''
        (Path(test_dir) / "app.py").write_text(python_file)
        
        # JavaScript file
        js_file = '''
const express = require('express');
const app = express();

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    // XSS vulnerability
    res.send(`<h1>Welcome ${username}!</h1>`);
});

app.get('/search', (req, res) => {
    const query = req.query.q;
    
    // Command injection vulnerability
    const { exec } = require('child_process');
    exec(`grep -r "${query}" /var/log/`, (error, stdout) => {
        res.send(stdout);
    });
});
'''
        (Path(test_dir) / "server.js").write_text(js_file)
        
        # Java file
        java_file = '''
import java.sql.*;
import javax.servlet.http.*;

public class VulnerableServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        // SQL Injection vulnerability
        String query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/db");
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                response.getWriter().println("Login successful");
            } else {
                response.getWriter().println("Login failed");
            }
        } catch (SQLException e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}
'''
        (Path(test_dir) / "VulnerableServlet.java").write_text(java_file)
        
        # PHP file
        php_file = '''
<?php
$username = $_POST['username'];
$password = $_POST['password'];

// SQL Injection vulnerability
$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysql_query($query);

if (mysql_num_rows($result) > 0) {
    echo "Login successful";
} else {
    echo "Login failed";
}

// XSS vulnerability
echo "<h1>Welcome " . $_GET['name'] . "!</h1>";

// Command injection vulnerability
$file = $_GET['file'];
system("cat " . $file);
?>
'''
        (Path(test_dir) / "login.php").write_text(php_file)
        
        # Package.json
        package_json = '''
{
    "name": "vulnerable-app",
    "version": "1.0.0",
    "dependencies": {
        "express": "4.16.0",
        "lodash": "4.17.4",
        "jquery": "1.9.1"
    }
}
'''
        (Path(test_dir) / "package.json").write_text(package_json)
        
        try:
            results = await self.scanner.run_full_analysis(test_dir, 'http://localhost:3000')
            
            test_result = {
                'test_name': 'Multi-Language Codebase',
                'total_files': results.get('total_files', 0),
                'total_tests': results.get('total_tests', 0),
                'vulnerabilities_found': results.get('vulnerabilities_found', 0),
                'ai_generated_findings': len(results.get('owasp_findings', [])),
                'languages': results.get('languages', []),
                'success': True
            }
            
            logger.info(f"✅ Multi-language test completed: {test_result['vulnerabilities_found']} vulnerabilities found")
            return test_result
            
        except Exception as e:
            logger.error(f"❌ Multi-language test failed: {str(e)}")
            return {'test_name': 'Multi-Language Codebase', 'success': False, 'error': str(e)}
        finally:
            shutil.rmtree(test_dir)
    
    async def test_large_codebase(self):
        """Test with a large codebase to test performance"""
        logger.info("🧪 Testing with large codebase...")
        
        test_dir = tempfile.mkdtemp()
        
        # Create multiple files
        for i in range(20):
            file_content = f'''
# File {i}
import requests
import json
import sqlite3

class VulnerableClass{i}:
    def __init__(self):
        self.conn = sqlite3.connect('db.sqlite')
    
    def vulnerable_method_{i}(self, user_input):
        # SQL Injection vulnerability {i}
        query = f"SELECT * FROM table{i} WHERE id = '{{user_input}}'"
        return self.conn.execute(query).fetchall()
    
    def xss_vulnerability_{i}(self, user_input):
        # XSS vulnerability {i}
        return f"<h1>Welcome {{user_input}}!</h1>"
    
    def command_injection_{i}(self, user_input):
        # Command injection vulnerability {i}
        import subprocess
        return subprocess.run(f"echo {{user_input}}", shell=True, capture_output=True, text=True)
'''
            (Path(test_dir) / f"vulnerable_file_{i}.py").write_text(file_content)
        
        try:
            results = await self.scanner.run_full_analysis(test_dir, 'http://localhost:5000')
            
            test_result = {
                'test_name': 'Large Codebase',
                'total_files': results.get('total_files', 0),
                'total_tests': results.get('total_tests', 0),
                'vulnerabilities_found': results.get('vulnerabilities_found', 0),
                'ai_generated_findings': len(results.get('owasp_findings', [])),
                'languages': results.get('languages', []),
                'success': True
            }
            
            logger.info(f"✅ Large codebase test completed: {test_result['vulnerabilities_found']} vulnerabilities found")
            return test_result
            
        except Exception as e:
            logger.error(f"❌ Large codebase test failed: {str(e)}")
            return {'test_name': 'Large Codebase', 'success': False, 'error': str(e)}
        finally:
            shutil.rmtree(test_dir)
    
    async def test_specific_attack_categories(self):
        """Test specific attack categories individually"""
        logger.info("🧪 Testing specific attack categories...")
        
        test_dir = tempfile.mkdtemp()
        
        # Create files for specific attack categories
        injection_file = '''
# SQL Injection vulnerabilities
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    return db.execute(query).fetchall()

def search(term):
    query = f"SELECT * FROM products WHERE name LIKE '%{term}%'"
    return db.execute(query).fetchall()
'''
        (Path(test_dir) / "injection.py").write_text(injection_file)
        
        auth_file = '''
# Authentication vulnerabilities
def weak_password_hash(password):
    import hashlib
    return hashlib.md5(password.encode()).hexdigest()

def session_fixation():
    session['user_id'] = request.args.get('user_id')
    return "Session set"

def jwt_vulnerability():
    import jwt
    payload = request.json
    token = jwt.encode(payload, 'secret', algorithm='none')
    return token
'''
        (Path(test_dir) / "auth.py").write_text(auth_file)
        
        business_logic_file = '''
# Business logic vulnerabilities
def process_payment(amount, user_id):
    # No validation - client controls amount
    return charge_card(user_id, amount)

def apply_discount(user_id, discount_code):
    # Race condition vulnerability
    discount = get_discount(discount_code)
    user_balance = get_user_balance(user_id)
    new_balance = user_balance - discount
    update_user_balance(user_id, new_balance)
    return new_balance
'''
        (Path(test_dir) / "business_logic.py").write_text(business_logic_file)
        
        try:
            results = await self.scanner.run_full_analysis(test_dir, 'http://localhost:5000')
            
            test_result = {
                'test_name': 'Specific Attack Categories',
                'total_files': results.get('total_files', 0),
                'total_tests': results.get('total_tests', 0),
                'vulnerabilities_found': results.get('vulnerabilities_found', 0),
                'ai_generated_findings': len(results.get('owasp_findings', [])),
                'languages': results.get('languages', []),
                'success': True
            }
            
            logger.info(f"✅ Attack categories test completed: {test_result['vulnerabilities_found']} vulnerabilities found")
            return test_result
            
        except Exception as e:
            logger.error(f"❌ Attack categories test failed: {str(e)}")
            return {'test_name': 'Specific Attack Categories', 'success': False, 'error': str(e)}
        finally:
            shutil.rmtree(test_dir)
    
    async def run_all_tests(self):
        """Run all advanced tests"""
        logger.info("🚀 Starting advanced dynamic scanner tests...")
        
        tests = [
            self.test_vulnerable_flask_app,
            self.test_multi_language_codebase,
            self.test_large_codebase,
            self.test_specific_attack_categories
        ]
        
        results = []
        for test in tests:
            try:
                result = await test()
                results.append(result)
                self.test_results.append(result)
            except Exception as e:
                logger.error(f"❌ Test {test.__name__} failed: {str(e)}")
                results.append({'test_name': test.__name__, 'success': False, 'error': str(e)})
        
        # Generate summary
        self.generate_test_summary()
        return results
    
    def generate_test_summary(self):
        """Generate a comprehensive test summary"""
        logger.info("📊 Generating test summary...")
        
        total_tests = len(self.test_results)
        successful_tests = len([r for r in self.test_results if r.get('success', False)])
        total_vulnerabilities = sum(r.get('vulnerabilities_found', 0) for r in self.test_results)
        total_ai_findings = sum(r.get('ai_generated_findings', 0) for r in self.test_results)
        
        summary = {
            'total_tests': total_tests,
            'successful_tests': successful_tests,
            'failed_tests': total_tests - successful_tests,
            'total_vulnerabilities_found': total_vulnerabilities,
            'total_ai_generated_findings': total_ai_findings,
            'test_results': self.test_results
        }
        
        # Save summary to file
        with open('dynamic_scanner_test_summary.json', 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info("📊 Test Summary:")
        logger.info(f"   Total Tests: {total_tests}")
        logger.info(f"   Successful: {successful_tests}")
        logger.info(f"   Failed: {total_tests - successful_tests}")
        logger.info(f"   Total Vulnerabilities: {total_vulnerabilities}")
        logger.info(f"   AI-Generated Findings: {total_ai_findings}")
        logger.info(f"   Summary saved to: dynamic_scanner_test_summary.json")

async def main():
    """Main test function"""
    print("🧪 Advanced Dynamic Scanner Testing Suite")
    print("=" * 50)
    
    tester = DynamicScannerTester()
    results = await tester.run_all_tests()
    
    print("\n🎉 Testing completed!")
    print("Check 'dynamic_scanner_test_summary.json' for detailed results.")

if __name__ == "__main__":
    asyncio.run(main())
