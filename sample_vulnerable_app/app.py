
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
