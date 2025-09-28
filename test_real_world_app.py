#!/usr/bin/env python3
"""
Real-World Application Testing for Dynamic Scanner

This script tests the dynamic scanner against real-world vulnerable applications
and common security patterns found in production codebases.
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

class RealWorldAppTester:
    """Test dynamic scanner against real-world applications"""
    
    def __init__(self):
        self.scanner = DynamicScanner()
    
    async def test_ecommerce_app(self):
        """Test with a realistic e-commerce application"""
        logger.info("🛒 Testing with e-commerce application...")
        
        test_dir = tempfile.mkdtemp()
        
        # Main application file
        app_file = '''
from flask import Flask, request, jsonify, session, render_template
import sqlite3
import hashlib
import jwt
import stripe
import requests
from functools import wraps

app = Flask(__name__)
app.secret_key = 'production_secret_key_12345'

# Database models
class User:
    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = hashlib.md5(password.encode()).hexdigest()  # Weak hashing
    
    def save(self):
        conn = sqlite3.connect('ecommerce.db')
        conn.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                    (self.username, self.email, self.password))
        conn.commit()
        conn.close()

class Product:
    def __init__(self, name, price, description):
        self.name = name
        self.price = price
        self.description = description
    
    def save(self):
        conn = sqlite3.connect('ecommerce.db')
        conn.execute("INSERT INTO products (name, price, description) VALUES (?, ?, ?)",
                    (self.name, self.price, self.description))
        conn.commit()
        conn.close()

class Order:
    def __init__(self, user_id, items, total):
        self.user_id = user_id
        self.items = items
        self.total = total
    
    def save(self):
        conn = sqlite3.connect('ecommerce.db')
        conn.execute("INSERT INTO orders (user_id, items, total) VALUES (?, ?, ?)",
                    (self.user_id, json.dumps(self.items), self.total))
        conn.commit()
        conn.close()

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
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        
        conn = sqlite3.connect('ecommerce.db')
        cursor = conn.execute("SELECT role FROM users WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        conn.close()
        
        if not user or user[0] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Vulnerable user registration
@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    email = request.json.get('email')
    password = request.json.get('password')
    
    # No input validation
    user = User(username, email, password)
    user.save()
    
    return jsonify({'status': 'success', 'message': 'User created'})

# Vulnerable login - SQL Injection
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    # SQL Injection vulnerability
    conn = sqlite3.connect('ecommerce.db')
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor = conn.execute(query)
    user = cursor.fetchone()
    conn.close()
    
    if user:
        session['user_id'] = user[0]
        return jsonify({'status': 'success', 'user_id': user[0]})
    else:
        return jsonify({'status': 'error', 'message': 'Invalid credentials'})

# Vulnerable product search - XSS
@app.route('/search')
def search_products():
    query = request.args.get('q', '')
    
    # XSS vulnerability - no output encoding
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.execute("SELECT * FROM products WHERE name LIKE ?", (f'%{query}%',))
    products = cursor.fetchall()
    conn.close()
    
    # Vulnerable template rendering
    html = f'''
    <html>
    <head><title>Search Results</title></head>
    <body>
        <h1>Search Results for: {query}</h1>
        <div class="products">
    '''
    
    for product in products:
        html += f'''
            <div class="product">
                <h3>{product[1]}</h3>
                <p>Price: ${product[2]}</p>
                <p>{product[3]}</p>
            </div>
        '''
    
    html += '''
        </div>
    </body>
    </html>
    '''
    
    return html

# Vulnerable user profile - IDOR
@app.route('/profile/<int:user_id>')
@require_auth
def get_profile(user_id):
    # IDOR vulnerability - can access any user's profile
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({
            'id': user[0],
            'username': user[1],
            'email': user[2],
            'role': user[3] if len(user) > 3 else 'user'
        })
    else:
        return jsonify({'error': 'User not found'})

# Vulnerable admin panel - Missing authorization
@app.route('/admin/users')
@require_auth
def admin_users():
    # Missing admin check - any authenticated user can access
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.execute("SELECT id, username, email, role FROM users")
    users = cursor.fetchall()
    conn.close()
    
    return jsonify({'users': [{'id': u[0], 'username': u[1], 'email': u[2], 'role': u[3]} for u in users]})

# Vulnerable order creation - Business logic flaw
@app.route('/orders', methods=['POST'])
@require_auth
def create_order():
    items = request.json.get('items', [])
    total = request.json.get('total', 0)
    
    # Business logic vulnerability - client controls total
    order = Order(session['user_id'], items, total)
    order.save()
    
    return jsonify({'status': 'success', 'order_id': f'ORD_{os.urandom(4).hex()}'})

# Vulnerable payment processing
@app.route('/payment', methods=['POST'])
@require_auth
def process_payment():
    amount = request.json.get('amount')
    card_token = request.json.get('card_token')
    
    # No server-side validation
    try:
        # Simulate Stripe API call
        charge = stripe.Charge.create(
            amount=amount * 100,  # Convert to cents
            currency='usd',
            source=card_token
        )
        
        return jsonify({'status': 'success', 'charge_id': charge.id})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# Vulnerable file upload
@app.route('/upload', methods=['POST'])
@require_auth
def upload_file():
    file = request.files['file']
    filename = file.filename
    
    # Path traversal vulnerability
    file.save(f'uploads/{filename}')
    return jsonify({'status': 'success', 'filename': filename})

# Vulnerable API endpoint - Insecure Direct Object Reference
@app.route('/api/orders/<int:order_id>')
@require_auth
def get_order(order_id):
    # IDOR vulnerability - can access any order
    conn = sqlite3.connect('ecommerce.db')
    cursor = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
    order = cursor.fetchone()
    conn.close()
    
    if order:
        return jsonify({
            'id': order[0],
            'user_id': order[1],
            'items': json.loads(order[2]),
            'total': order[3]
        })
    else:
        return jsonify({'error': 'Order not found'})

# Vulnerable JWT implementation
@app.route('/api/token', methods=['POST'])
def get_token():
    username = request.json.get('username')
    password = request.json.get('password')
    
    # Weak JWT secret
    secret = 'weak_secret_key'
    
    # No password verification
    payload = {'username': username, 'admin': False}
    token = jwt.encode(payload, secret, algorithm='HS256')
    
    return jsonify({'token': token})

# Vulnerable admin promotion
@app.route('/admin/promote', methods=['POST'])
@require_auth
def promote_user():
    user_id = request.json.get('user_id')
    
    # Missing admin check - any user can promote others
    conn = sqlite3.connect('ecommerce.db')
    conn.execute("UPDATE users SET role = 'admin' WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'status': 'success', 'message': 'User promoted to admin'})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
'''
        
        (Path(test_dir) / "app.py").write_text(app_file)
        
        # Requirements file
        requirements = '''
Flask==2.3.3
stripe==5.4.0
PyJWT==2.8.0
'''
        (Path(test_dir) / "requirements.txt").write_text(requirements)
        
        # Database schema
        schema_file = '''
-- E-commerce database schema
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    email TEXT,
    password TEXT,
    role TEXT DEFAULT 'user'
);

CREATE TABLE products (
    id INTEGER PRIMARY KEY,
    name TEXT,
    price REAL,
    description TEXT
);

CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    items TEXT,
    total REAL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
'''
        (Path(test_dir) / "schema.sql").write_text(schema_file)
        
        # Configuration file
        config_file = '''
# E-commerce configuration
DATABASE_URL = "sqlite:///ecommerce.db"
SECRET_KEY = "production_secret_key_12345"
STRIPE_SECRET_KEY = "sk_test_1234567890"
JWT_SECRET = "weak_secret_key"
DEBUG = True
'''
        (Path(test_dir) / "config.py").write_text(config_file)
        
        # Frontend JavaScript
        js_file = '''
// E-commerce frontend JavaScript
class EcommerceApp {
    constructor() {
        this.apiBase = '/api';
        this.token = localStorage.getItem('token');
    }
    
    async login(username, password) {
        const response = await fetch('/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, password})
        });
        
        const data = await response.json();
        if (data.status === 'success') {
            this.token = data.token;
            localStorage.setItem('token', this.token);
        }
        return data;
    }
    
    async searchProducts(query) {
        // XSS vulnerability - no input sanitization
        const response = await fetch(`/search?q=${query}`);
        const html = await response.text();
        document.getElementById('results').innerHTML = html;
    }
    
    async createOrder(items, total) {
        // Business logic vulnerability - client controls total
        const response = await fetch('/orders', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.token}`
            },
            body: JSON.stringify({items, total})
        });
        
        return response.json();
    }
    
    async processPayment(amount, cardToken) {
        // No server-side validation
        const response = await fetch('/payment', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.token}`
            },
            body: JSON.stringify({amount, card_token: cardToken})
        });
        
        return response.json();
    }
    
    async uploadFile(file) {
        const formData = new FormData();
        formData.append('file', file);
        
        const response = await fetch('/upload', {
            method: 'POST',
            headers: {'Authorization': `Bearer ${this.token}`},
            body: formData
        });
        
        return response.json();
    }
}

// Initialize app
const app = new EcommerceApp();
'''
        (Path(test_dir) / "static/js/app.js").write_text(js_file)
        
        try:
            results = await self.scanner.run_full_analysis(test_dir, 'http://localhost:5000')
            
            test_result = {
                'test_name': 'E-commerce Application',
                'total_files': results.get('total_files', 0),
                'total_tests': results.get('total_tests', 0),
                'vulnerabilities_found': results.get('vulnerabilities_found', 0),
                'ai_generated_findings': len(results.get('owasp_findings', [])),
                'languages': results.get('languages', []),
                'success': True
            }
            
            logger.info(f"✅ E-commerce app test completed: {test_result['vulnerabilities_found']} vulnerabilities found")
            return test_result
            
        except Exception as e:
            logger.error(f"❌ E-commerce app test failed: {str(e)}")
            return {'test_name': 'E-commerce Application', 'success': False, 'error': str(e)}
        finally:
            shutil.rmtree(test_dir)
    
    async def test_api_only_application(self):
        """Test with an API-only application"""
        logger.info("🔌 Testing with API-only application...")
        
        test_dir = tempfile.mkdtemp()
        
        # FastAPI application
        api_file = '''
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import sqlite3
import jwt
import hashlib
import json
from typing import Optional

app = FastAPI()
security = HTTPBearer()

# Database setup
def init_db():
    conn = sqlite3.connect('api.db')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            email TEXT,
            password TEXT,
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

# Authentication
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, 'secret', algorithms=['HS256'])
        return payload
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Vulnerable user registration
@app.post("/api/users")
async def create_user(username: str, email: str, password: str):
    # No input validation
    password_hash = hashlib.md5(password.encode()).hexdigest()  # Weak hashing
    
    conn = sqlite3.connect('api.db')
    try:
        conn.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                    (username, email, password_hash))
        conn.commit()
        return {"status": "success", "message": "User created"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")
    finally:
        conn.close()

# Vulnerable login
@app.post("/api/auth/login")
async def login(username: str, password: str):
    # SQL Injection vulnerability
    conn = sqlite3.connect('api.db')
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor = conn.execute(query)
    user = cursor.fetchone()
    conn.close()
    
    if user:
        token = jwt.encode({'user_id': user[0], 'username': user[1]}, 'secret', algorithm='HS256')
        return {"status": "success", "token": token}
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")

# Vulnerable user profile - IDOR
@app.get("/api/users/{user_id}")
async def get_user(user_id: int, current_user: dict = Depends(verify_token)):
    # IDOR vulnerability - can access any user's profile
    conn = sqlite3.connect('api.db')
    cursor = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return {
            "id": user[0],
            "username": user[1],
            "email": user[2],
            "role": user[3] if len(user) > 3 else "user"
        }
    else:
        raise HTTPException(status_code=404, detail="User not found")

# Vulnerable posts endpoint
@app.get("/api/posts")
async def get_posts(search: Optional[str] = None):
    conn = sqlite3.connect('api.db')
    
    if search:
        # SQL Injection vulnerability
        query = f"SELECT * FROM posts WHERE title LIKE '%{search}%' OR content LIKE '%{search}%'"
        cursor = conn.execute(query)
    else:
        cursor = conn.execute("SELECT * FROM posts")
    
    posts = cursor.fetchall()
    conn.close()
    
    return [{"id": p[0], "user_id": p[1], "title": p[2], "content": p[3]} for p in posts]

# Vulnerable post creation
@app.post("/api/posts")
async def create_post(title: str, content: str, current_user: dict = Depends(verify_token)):
    # No input validation
    conn = sqlite3.connect('api.db')
    conn.execute("INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)",
                (current_user['user_id'], title, content))
    conn.commit()
    conn.close()
    
    return {"status": "success", "message": "Post created"}

# Vulnerable admin endpoint
@app.get("/api/admin/users")
async def admin_users(current_user: dict = Depends(verify_token)):
    # Missing admin check - any authenticated user can access
    conn = sqlite3.connect('api.db')
    cursor = conn.execute("SELECT id, username, email, role FROM users")
    users = cursor.fetchall()
    conn.close()
    
    return [{"id": u[0], "username": u[1], "email": u[2], "role": u[3]} for u in users]

# Vulnerable file upload
@app.post("/api/upload")
async def upload_file(file: bytes, filename: str, current_user: dict = Depends(verify_token)):
    # Path traversal vulnerability
    with open(f"uploads/{filename}", "wb") as f:
        f.write(file)
    
    return {"status": "success", "filename": filename}

# Vulnerable search endpoint
@app.get("/api/search")
async def search(query: str):
    # XSS vulnerability in response
    conn = sqlite3.connect('api.db')
    cursor = conn.execute("SELECT * FROM posts WHERE title LIKE ? OR content LIKE ?",
                         (f'%{query}%', f'%{query}%'))
    posts = cursor.fetchall()
    conn.close()
    
    # Vulnerable response construction
    results = []
    for post in posts:
        results.append({
            "id": post[0],
            "title": post[2].replace(query, f"<mark>{query}</mark>"),  # XSS vulnerability
            "content": post[3].replace(query, f"<mark>{query}</mark>")  # XSS vulnerability
        })
    
    return {"query": query, "results": results}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
'''
        
        (Path(test_dir) / "main.py").write_text(api_file)
        
        # Requirements
        requirements = '''
fastapi==0.104.1
uvicorn==0.24.0
PyJWT==2.8.0
python-multipart==0.0.6
'''
        (Path(test_dir) / "requirements.txt").write_text(requirements)
        
        # API documentation
        readme = '''
# Vulnerable API Application

This is a deliberately vulnerable FastAPI application for testing security scanners.

## Vulnerabilities Included:
- SQL Injection
- IDOR (Insecure Direct Object Reference)
- Missing Authorization
- Weak Password Hashing
- XSS in API responses
- Path Traversal
- JWT vulnerabilities

## Setup:
pip install -r requirements.txt
python main.py
'''
        (Path(test_dir) / "README.md").write_text(readme)
        
        try:
            results = await self.scanner.run_full_analysis(test_dir, 'http://localhost:8000')
            
            test_result = {
                'test_name': 'API-Only Application',
                'total_files': results.get('total_files', 0),
                'total_tests': results.get('total_tests', 0),
                'vulnerabilities_found': results.get('vulnerabilities_found', 0),
                'ai_generated_findings': len(results.get('owasp_findings', [])),
                'languages': results.get('languages', []),
                'success': True
            }
            
            logger.info(f"✅ API app test completed: {test_result['vulnerabilities_found']} vulnerabilities found")
            return test_result
            
        except Exception as e:
            logger.error(f"❌ API app test failed: {str(e)}")
            return {'test_name': 'API-Only Application', 'success': False, 'error': str(e)}
        finally:
            shutil.rmtree(test_dir)
    
    async def run_all_tests(self):
        """Run all real-world application tests"""
        logger.info("🚀 Starting real-world application tests...")
        
        tests = [
            self.test_ecommerce_app,
            self.test_api_only_application
        ]
        
        results = []
        for test in tests:
            try:
                result = await test()
                results.append(result)
            except Exception as e:
                logger.error(f"❌ Test {test.__name__} failed: {str(e)}")
                results.append({'test_name': test.__name__, 'success': False, 'error': str(e)})
        
        # Generate summary
        total_tests = len(results)
        successful_tests = len([r for r in results if r.get('success', False)])
        total_vulnerabilities = sum(r.get('vulnerabilities_found', 0) for r in results)
        total_ai_findings = sum(r.get('ai_generated_findings', 0) for r in results)
        
        summary = {
            'total_tests': total_tests,
            'successful_tests': successful_tests,
            'failed_tests': total_tests - successful_tests,
            'total_vulnerabilities_found': total_vulnerabilities,
            'total_ai_generated_findings': total_ai_findings,
            'test_results': results
        }
        
        # Save summary
        with open('real_world_app_test_summary.json', 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info("📊 Real-World App Test Summary:")
        logger.info(f"   Total Tests: {total_tests}")
        logger.info(f"   Successful: {successful_tests}")
        logger.info(f"   Failed: {total_tests - successful_tests}")
        logger.info(f"   Total Vulnerabilities: {total_vulnerabilities}")
        logger.info(f"   AI-Generated Findings: {total_ai_findings}")
        logger.info(f"   Summary saved to: real_world_app_test_summary.json")
        
        return results

async def main():
    """Main test function"""
    print("🌍 Real-World Application Testing for Dynamic Scanner")
    print("=" * 60)
    
    tester = RealWorldAppTester()
    results = await tester.run_all_tests()
    
    print("\n🎉 Real-world testing completed!")
    print("Check 'real_world_app_test_summary.json' for detailed results.")

if __name__ == "__main__":
    asyncio.run(main())
